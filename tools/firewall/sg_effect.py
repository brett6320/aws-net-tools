#!/usr/bin/env python3
"""
Security group effect: what one group really does on every resource that uses it.

Intent: before deleting a security group, taking it off resources, or deleting some
of its rules, see which resources would actually lose access. A group's rules alone
don't say that: every resource also has other groups, and access another group
already allows isn't lost.

Give it a security group (ID or ARN). It finds every network interface that has the
group and the resource behind each one (EC2 instances, load balancers, Lambda
functions, RDS, VPC endpoints, ECS tasks, EFS and more), reads every other group on
those resources, and works out:

  * if the group is removed: what each resource would lose, after counting every
    other group on it, down to exact ports and CIDRs ("tcp 22 from pl-0123
    (corp-networks) except 10.0.0.0/8"). This includes access that other groups
    grant to the target group's members ("db-sg would stop allowing tcp 5432 from
    this resource").
  * if rules are removed (--remove-rule, in the HTML report only): what each
    resource would lose if those rules of the target group were deleted, and which
    rule still allows the access it keeps.
  * which rules of the target group are redundant on every resource: deleting them
    changes no access.
  * with --full: every rule, each resource's effective inbound and outbound access
    across all of its groups, and the groups whose rules reference the target.

Rules are compared by the traffic they allow (lib/sg_algebra.py): prefix lists are
expanded to their entries, so a /8 in another group covers the matching part of a
prefix list. A referenced security group is covered only by a rule that references
the same group. Resources are found through DescribeNetworkInterfaces filtered by
group, and named from the interface (lib/eni_owners.py). An instance whose
interfaces have different groups is shown once per interface set, because access is
per interface.

Not considered: network ACLs, route tables and firewalls on the resources (the
result is what security groups allow, not whether a path exists), and the
addresses behind a referenced group (a CIDR rule never covers a group reference).

Accounts: a group ARN is read with the local profile for its account (profiles
ending in -priv or -cpar are never used; --account-profile forces one). A bare
group ID is read with --profile, AWS_PROFILE or the default credentials.

Configuration (.env, all optional; CLI flags override):

    # AWS profile to use (overridden by --profile)
    AWS_PROFILE=
    # Region for a bare group ID when --region is not given (ARNs carry their own)
    AWS_REGION=us-east-1
    # Base directory for auto-saved reports (<dir>/<tool>/YYYY-MM-DD/...)
    FMM_REPORT_DIR=./reports

Reports: text on screen (the removal effects; --full for everything), plus
auto-saved HTML, CSV (the removal effects) and JSON (the analysis and the collected
data, which --from-json re-analyzes offline) under reports/sg_effect/YYYY-MM-DD/.
The --remove-rule scenario is only in the HTML report.

Usage:

    ./sg_effect.py --profile prod-admin sg-0123456789abcdef0
    ./sg_effect.py arn:aws:ec2:us-east-1:111122223333:security-group/sg-0123456789abcdef0 --full
    ./sg_effect.py sg-0123456789abcdef0 --remove-rule sgr-0abc... --remove-rule in:tcp:22:10.0.0.0/8
    ./sg_effect.py --from-json reports/sg_effect/2026-10-26/101500_sgeffect_sg-0123456789abcdef0.json \
                   --remove-rule sgr-0abc...

Exit codes: 0 ok, 1 the --remove-rule scenario takes access away from at least one
resource, 2 fatal error.

Read-only. No mutating API calls are made.
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import logging
import os
import re
import sys
from typing import Iterable

import truststore

# Must run before boto3/urllib3 import (see fmm_nacl_audit.py).
truststore.inject_into_ssl()

import boto3  # noqa: E402
from botocore.exceptions import BotoCoreError, ClientError  # noqa: E402

from lib import html_report  # noqa: E402
from lib import sg_algebra as acc  # noqa: E402
from lib.accounts import add_profile_args, check_profile_args  # noqa: E402
from lib.aws_common import err_text, get_client  # noqa: E402  (also loads .env, sets up logging)
from lib.eni_owners import eni_owner  # noqa: E402
from lib.output import add_output_args, print_saved, report_paths, setup_logging, write_csv, write_json, write_text  # noqa: E402
from lib.security_groups import fetch_prefix_lists, parse_target, resolve_account_profiles, spec_accounts  # noqa: E402

log = logging.getLogger("sg_effect")

IN, OUT = "inbound", "outbound"
CHUNK = 200          # filter values per call


class ValidationError(ValueError):
    """Bad input: a group ID, rule spec or saved report that can't be used."""

# --------------------------------------------------------------------------- #
# Collection
# --------------------------------------------------------------------------- #
def _code(e: ClientError) -> str:
    return e.response.get("Error", {}).get("Code", "Error")


def _chunks(items: list, n: int = CHUNK) -> Iterable[list]:
    for i in range(0, len(items), n):
        yield items[i:i + n]


def _paginate(ec2, op: str, key: str, **params) -> list[dict]:
    return [x for page in ec2.get_paginator(op).paginate(**params) for x in page.get(key) or []]


def tag(tags: list[dict] | None, key: str = "Name") -> str | None:
    return next((t.get("Value") for t in tags or [] if t.get("Key") == key), None)


def _eni_record(e: dict) -> dict:
    kind, ident = eni_owner(e)
    return {
        "id": e["NetworkInterfaceId"],
        "kind": kind,
        "resource": ident,
        "description": e.get("Description") or None,
        "type": e.get("InterfaceType"),
        "status": e.get("Status"),
        "subnet": e.get("SubnetId"),
        "vpc": e.get("VpcId"),
        "az": e.get("AvailabilityZone"),
        "private_ips": [p.get("PrivateIpAddress") for p in e.get("PrivateIpAddresses") or [] if p.get("PrivateIpAddress")]
        or ([e["PrivateIpAddress"]] if e.get("PrivateIpAddress") else []),
        "public_ip": (e.get("Association") or {}).get("PublicIp"),
        "groups": [g["GroupId"] for g in e.get("Groups") or []],
        "requester_managed": bool(e.get("RequesterManaged")),
        "owner": e.get("OwnerId"),
    }


def _rule_record(r: dict) -> dict:
    ref = r.get("ReferencedGroupInfo") or {}
    if r.get("CidrIpv4") or r.get("CidrIpv6"):
        kind, peer = "cidr", r.get("CidrIpv4") or r.get("CidrIpv6")
    elif r.get("PrefixListId"):
        kind, peer = "pl", r["PrefixListId"]
    else:
        kind, peer = "sg", ref.get("GroupId")
    return {
        "id": r.get("SecurityGroupRuleId"),
        "group": r.get("GroupId"),
        "egress": bool(r.get("IsEgress")),
        "protocol": str(r.get("IpProtocol")),
        "from": r.get("FromPort"),
        "to": r.get("ToPort"),
        "peer_kind": kind,
        "peer": peer,
        "peer_account": ref.get("UserId"),
        "peer_vpc": ref.get("VpcId"),
        "peering": ref.get("VpcPeeringConnectionId"),
        "description": r.get("Description") or None,
    }


def _group_record(g: dict) -> dict:
    return {"id": g["GroupId"], "name": g.get("GroupName"), "description": g.get("Description"),
            "vpc": g.get("VpcId"), "owner": g.get("OwnerId"), "tag_name": tag(g.get("Tags"))}


# ---------- collection ----------

def _groups(ec2, ids: list[str], warnings: list[str]) -> dict[str, dict]:
    out = {}
    for chunk in _chunks(sorted(ids)):
        try:
            for g in _paginate(ec2, "describe_security_groups", "SecurityGroups", GroupIds=chunk):
                out[g["GroupId"]] = _group_record(g)
        except ClientError as e:
            # One unreadable group (another account's, or deleted) fails the whole call: retry singly.
            if len(chunk) == 1:
                warnings.append(f"{chunk[0]}: DescribeSecurityGroups failed: {_code(e)}")
                continue
            for gid in chunk:
                out.update(_groups(ec2, [gid], warnings))
    return out


def _rules(ec2, group_ids: list[str], warnings: list[str]) -> list[dict]:
    out = []
    for chunk in _chunks(sorted(group_ids)):
        try:
            out += [_rule_record(r) for r in _paginate(ec2, "describe_security_group_rules", "SecurityGroupRules",
                                                       Filters=[{"Name": "group-id", "Values": chunk}])]
        except ClientError as e:
            warnings.append(f"DescribeSecurityGroupRules failed for {', '.join(chunk)}: {_code(e)}")
    return out


def _enis(ec2, group_ids: list[str]) -> list[dict]:
    out = []
    for chunk in _chunks(sorted(group_ids)):
        out += [_eni_record(e) for e in _paginate(ec2, "describe_network_interfaces", "NetworkInterfaces",
                                                  Filters=[{"Name": "group-id", "Values": chunk}])]
    return out


def _referencing(ec2, sg: str, warnings: list[str]) -> list[str]:
    ids: set[str] = set()
    for name in ("ip-permission.group-id", "egress.ip-permission.group-id"):
        try:
            ids |= {g["GroupId"] for g in _paginate(ec2, "describe_security_groups", "SecurityGroups",
                                                    Filters=[{"Name": name, "Values": [sg]}])}
        except ClientError as e:
            warnings.append(f"Finding groups that reference {sg} ({name}) failed: {_code(e)}")
    return sorted(ids - {sg})


def _prefix_lists(ec2, ids: list[str], warnings: list[str]) -> dict[str, dict]:
    """Names and entries of the referenced prefix lists; entries None when unreadable."""
    entries, names, errors = fetch_prefix_lists(ec2, set(ids))
    warnings += [f"{err}: prefix list entries unreadable; treated as an opaque peer" for err in errors]
    return {pid: {"id": pid, "name": names.get(pid) or None, "entries": sorted(entries[pid])
                  if entries.get(pid) is not None else None} for pid in sorted(ids)}


def _instance_names(ec2, ids: list[str], warnings: list[str]) -> dict[str, str | None]:
    out = {}
    for chunk in _chunks(sorted(ids), 100):
        try:
            for page in ec2.get_paginator("describe_instances").paginate(InstanceIds=chunk):
                for res in page.get("Reservations") or []:
                    for i in res.get("Instances") or []:
                        out[i["InstanceId"]] = tag(i.get("Tags"))
        except ClientError as e:
            warnings.append(f"DescribeInstances failed: {_code(e)}; instance names not shown")
    return out


def collect(session, region: str, sg: str, account: str | None = None) -> dict:
    """Read the target group, the resources that use it and every group on them (see the
    module docstring). Returns a JSON-serializable bundle; the profile is never in it."""
    if not re.fullmatch(r"sg-[0-9a-f]{8,17}", sg or ""):
        raise ValidationError(f"Not a security group ID: {sg!r}")
    if not region:
        raise ValidationError("No region configured; pass --region or set AWS_REGION")
    ec2 = get_client("ec2", session)
    warnings: list[str] = []
    try:
        target = ec2.describe_security_groups(GroupIds=[sg]).get("SecurityGroups") or []
    except ClientError as e:
        if _code(e) in ("InvalidGroup.NotFound", "InvalidGroupId.Malformed"):
            raise ValidationError(f"Security group {sg} not found in {region}") from None
        raise
    if not target:
        raise ValidationError(f"Security group {sg} not found in {region}")

    enis = _enis(ec2, [sg])
    referencing = _referencing(ec2, sg, warnings)
    ref_enis = [e for e in _enis(ec2, referencing) if sg not in e["groups"]] if referencing else []
    group_ids = {sg} | {g for e in enis for g in e["groups"]} | set(referencing)
    rules = _rules(ec2, sorted(group_ids), warnings)
    peer_groups = {r["peer"] for r in rules if r["peer_kind"] == "sg" and r["peer"]}
    groups = _groups(ec2, sorted(group_ids | peer_groups | {g for e in ref_enis for g in e["groups"]}), warnings)
    pls = _prefix_lists(ec2, sorted({r["peer"] for r in rules if r["peer_kind"] == "pl"}), warnings)
    instances = sorted({e["resource"] for e in enis + ref_enis if e["kind"] == "EC2 instance"})
    names = _instance_names(ec2, instances, warnings) if instances else {}
    return {
        "tool": "sg_effect",
        "generated": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "region": region,
        "account": account or target[0].get("OwnerId"),
        "target": sg,
        "groups": groups,
        "rules": rules,
        "enis": enis,
        "referencing": referencing,
        "referencing_enis": ref_enis,
        "prefix_lists": pls,
        "instance_names": names,
        "warnings": warnings,
    }


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #
def names(bundle: dict) -> dict[str, str]:
    out = {}
    for g in (bundle.get("groups") or {}).values():
        out[g["id"]] = g.get("name") or g.get("tag_name") or ""
    for p in (bundle.get("prefix_lists") or {}).values():
        if p.get("name"):
            out[p["id"]] = p["name"]
    return out


def to_rule(r: dict, bundle: dict) -> acc.Rule:
    nets: tuple = ()
    if r["peer_kind"] == "pl":
        entries = ((bundle.get("prefix_lists") or {}).get(r["peer"]) or {}).get("entries")
        nets = tuple(ipaddress.ip_network(c, strict=False) for c in entries or [])
    return acc.Rule(id=r["id"], group=r["group"], egress=r["egress"], protocol=acc.normalize_protocol(r["protocol"]),
                    lo=r.get("from"), hi=r.get("to"), peer_kind=r["peer_kind"], peer=r["peer"] or "?",
                    description=r.get("description"), peer_nets=nets)


def rules_by_group(bundle: dict) -> dict[str, list[acc.Rule]]:
    out: dict[str, list[acc.Rule]] = {}
    for r in bundle.get("rules") or []:
        out.setdefault(r["group"], []).append(to_rule(r, bundle))
    return out


def rule_text(rule: acc.Rule, nm: dict[str, str]) -> str:
    return f"{'outbound' if rule.egress else 'inbound'} {acc.rule_traffic(rule)} " \
           f"{'to' if rule.egress else 'from'} {acc.peer_label(rule, nm)}"


# ---------- resources ----------

def resources(bundle: dict, enis: list[dict] | None = None) -> list[dict]:
    """ENIs grouped by resource and by group set (an instance's ENIs can differ)."""
    enis = bundle.get("enis") if enis is None else enis
    inames = bundle.get("instance_names") or {}
    target = bundle.get("target")
    out: dict[tuple, dict] = {}
    for e in enis or []:
        groups = sorted(e["groups"], key=lambda g: (g != target, g))
        key = (e["kind"], e["resource"], tuple(groups))
        res = out.setdefault(key, {"kind": e["kind"], "id": e["resource"], "groups": groups, "enis": [],
                                   "name": inames.get(e["resource"]) if e["kind"] == "EC2 instance" else None})
        res["enis"].append({k: e.get(k) for k in ("id", "private_ips", "public_ip", "subnet", "az", "status",
                                                    "description")})
    split = {}
    for (kind, ident, _), r in out.items():
        split[(kind, ident)] = split.get((kind, ident), 0) + 1
    result = sorted(out.values(), key=lambda r: (r["kind"], r["name"] or "", r["id"], r["groups"]))
    for r in result:
        r["split"] = split[(r["kind"], r["id"])] > 1
    return result


# ---------- effective access ----------

def effective(groups: list[str], by_group: dict[str, list[acc.Rule]], target: str, nm: dict[str, str]) -> dict:
    out = {}
    all_rules = [r for g in groups for r in by_group.get(g, [])]
    for direction, egress in ((IN, False), (OUT, True)):
        merged: dict[tuple, dict] = {}
        for r in all_rules:
            if r.egress != egress:
                continue
            m = merged.setdefault(r.signature(), {"rule": r, "grants": []})
            m["grants"].append({"group": r.group, "rule": r.id})
        entries = []
        for sig, m in merged.items():
            r = m["rule"]
            covered = [o["rule"] for s, o in merged.items() if s != sig and acc.covers(o["rule"], r)]
            entries.append({
                "traffic": acc.rule_traffic(r),
                "peer": acc.peer_label(r, nm),
                "peer_kind": r.peer_kind,
                "grants": m["grants"],
                "from_target": any(g["group"] == target for g in m["grants"]),
                "only_target": all(g["group"] == target for g in m["grants"]),
                "covered_by": [{"group": c.group, "rule": c.id, "text": rule_text(c, nm)} for c in covered],
                "open_to_world": r.peer in ("0.0.0.0/0", "::/0"),
                "descriptions": sorted({x.description for x in all_rules if x.signature() == sig and x.description}),
            })
        entries.sort(key=lambda e: (not e["from_target"], e["peer_kind"] != "cidr", e["traffic"], e["peer"]))
        out[direction] = entries
    return out


# ---------- scenarios ----------

def _lost(removed: list[acc.Rule], kept: list[acc.Rule], nm: dict[str, str]) -> dict:
    out: dict[str, list] = {IN: [], OUT: []}
    for r in removed:
        res = acc.residual(r, kept)
        lines = acc.describe(res, r.egress, nm, original=r)
        direction = OUT if r.egress else IN
        if lines:
            out[direction].append({"rule": r.id, "group": r.group, "text": rule_text(r, nm), "lost": lines,
                                   "partly": bool(res) and acc.subtract(r.rects(), res) != []})
        else:
            covering = [o for o in kept if acc.covers(o, r)]
            out[direction].append({"rule": r.id, "group": r.group, "text": rule_text(r, nm), "lost": [],
                                   "kept_by": [{"group": o.group, "rule": o.id, "text": rule_text(o, nm)}
                                               for o in covering]
                                   or [{"group": None, "rule": None, "text": "several rules together"}]})
    return out


def _as_peer(res_groups: list[str], target: str, bundle: dict, by_group: dict[str, list[acc.Rule]],
             nm: dict[str, str]) -> list[dict]:
    """Access other groups grant the target's members, that this resource would lose."""
    others = set(res_groups) - {target}
    out = []
    for gid in bundle.get("referencing") or []:
        rules = by_group.get(gid, [])
        via_target = [r for r in rules if r.peer_kind == "sg" and r.peer == target]
        via_others = [r for r in rules if r.peer_kind == "sg" and r.peer in others]
        for r in via_target:
            mine = acc.Rule(r.id, gid, r.egress, r.protocol, r.lo, r.hi, "sg", "self")
            keep = [acc.Rule(o.id, gid, o.egress, o.protocol, o.lo, o.hi, "sg", "self") for o in via_others]
            res = acc.residual(mine, keep)
            if not res:
                continue
            traffic = "; ".join(sorted({acc._rect_traffic(x) for x in res})) if acc.subtract(mine.rects(), res) \
                else acc.rule_traffic(r)
            gname = f"{gid} ({nm[gid]})" if nm.get(gid) else gid
            text = (f"{gname} would stop allowing outbound {traffic} to this resource" if r.egress
                    else f"{gname} would stop allowing inbound {traffic} from this resource")
            out.append({"group": gid, "rule": r.id, "text": text})
    return out


def parse_rule_spec(spec: str) -> dict:
    """'in:tcp:443:10.0.0.0/8', 'out:-1:all:0.0.0.0/0', 'in:tcp:8000-8080:sg-0123...'."""
    m = re.fullmatch(r"(in|out|inbound|outbound|ingress|egress):([^:]+):([^:]+):(.+)", spec.strip(), re.I)
    if not m:
        raise ValidationError(f"--remove-rule expects sgr-ID or DIRECTION:PROTOCOL:PORTS:PEER, got {spec!r}")
    d, proto, ports, peer = m.groups()
    proto = acc.normalize_protocol({"all": "-1"}.get(proto.lower(), proto.lower()))
    if ports.lower() in ("all", "-1", "*"):
        lo = hi = None
    else:
        a, _, b = ports.partition("-")
        lo, hi = int(a), int(b or a)
    if not peer.startswith(("sg-", "pl-")):
        peer = str(ipaddress.ip_network(peer, strict=False))
    return {"egress": d.lower() in ("out", "outbound", "egress"), "protocol": proto, "lo": lo, "hi": hi, "peer": peer}


def _matches(rule: acc.Rule, spec: dict) -> bool:
    if rule.egress != spec["egress"] or rule.protocol != spec["protocol"] or rule.peer != spec["peer"]:
        return False
    if spec["lo"] is None:
        return rule.lo in (None, -1) or (rule.protocol in ("tcp", "udp") and (rule.lo, rule.hi) == (0, 65535))
    return (rule.lo, rule.hi) == (spec["lo"], spec["hi"])


def select_rules(target_rules: list[acc.Rule], specs: list[str]) -> list[acc.Rule]:
    chosen: list[acc.Rule] = []
    for s in specs:
        if s.startswith("sgr-"):
            hit = [r for r in target_rules if r.id == s]
        else:
            spec = parse_rule_spec(s)
            hit = [r for r in target_rules if _matches(r, spec)]
        if not hit:
            raise ValidationError(f"No rule of the target group matches {s!r}")
        chosen += [r for r in hit if r not in chosen]
    return chosen


# ---------- everything ----------

def analyze(bundle: dict, remove_rules: list[str] | None = None, only: list[str] | None = None) -> dict:
    target = bundle["target"]
    nm = names(bundle)
    by_group = rules_by_group(bundle)
    target_rules = by_group.get(target, [])
    removing = select_rules(target_rules, remove_rules or [])
    res_list = resources(bundle)
    if only:
        res_list = [r for r in res_list if r["id"] in only or any(e["id"] in only for e in r["enis"])]
    summary = {r.id: {"rule": r.id, "text": rule_text(r, nm), "description": r.description,
                      "unique_on": [], "redundant_on": []} for r in target_rules}
    for res in res_list:
        groups = res["groups"]
        others = [r for g in groups if g != target for r in by_group.get(g, [])]
        res["group_names"] = {g: nm.get(g, "") for g in groups}
        res["effective"] = effective(groups, by_group, target, nm)
        res["remove_sg"] = {**_lost(target_rules, others, nm),
                            "as_peer": _as_peer(groups, target, bundle, by_group, nm)}
        if removing:
            kept = others + [r for r in target_rules if r not in removing]
            res["remove_rules"] = _lost(removing, kept, nm)
        label = f"{res['kind']} {res['id']}" + (f" ({res['name']})" if res.get("name") else "")
        if res["split"]:
            label += " via " + ", ".join(e["id"] for e in res["enis"])
        for r in target_rules:
            rest = others + [x for x in target_rules if x is not r]
            (summary[r.id]["unique_on"] if acc.residual(r, rest) else summary[r.id]["redundant_on"]).append(label)
    g = (bundle.get("groups") or {}).get(target) or {"id": target}
    referencing = []
    for gid in bundle.get("referencing") or []:
        refs = [rule_text(r, nm) for r in by_group.get(gid, []) if r.peer_kind == "sg" and r.peer == target]
        members = resources(bundle, [e for e in bundle.get("referencing_enis") or [] if gid in e["groups"]])
        referencing.append({"group": gid, "name": nm.get(gid, ""), "rules": refs,
                            "resources": [{"kind": m["kind"], "id": m["id"], "name": m.get("name")} for m in members]})
    return {
        "target": {**g, "rules": [{"id": r.id, "text": rule_text(r, nm), "description": r.description}
                                  for r in target_rules]},
        "region": bundle.get("region"),
        "account": bundle.get("account"),
        "generated": bundle.get("generated"),
        "removing": [{"id": r.id, "text": rule_text(r, nm)} for r in removing],
        "resources": res_list,
        "rule_summary": list(summary.values()),
        "referencing": referencing,
        "warnings": bundle.get("warnings") or [],
    }


def loses_access(result: dict) -> bool:
    """True when the --remove-rule scenario takes access away from any resource."""
    return any(item["lost"] for res in result["resources"] for d in (IN, OUT)
               for item in (res.get("remove_rules") or {}).get(d, []))


# --------------------------------------------------------------------------- #
# Text report
# --------------------------------------------------------------------------- #
def group_label(gid: str, names: dict[str, str]) -> str:
    return f"{gid} ({names[gid]})" if names.get(gid) else gid


def resource_label(res: dict) -> str:
    return f"{res['kind']} {res['id']}" + (f" ({res['name']})" if res.get("name") else "")


def _grants(entry: dict) -> str:
    return ", ".join(dict.fromkeys(g["group"] for g in entry["grants"]))


def _scenario(lines: list[str], title: str, block: dict, names: dict[str, str]) -> None:
    lines.append(f"   {title}")
    any_line = False
    for d in (IN, OUT):
        for item in block.get(d) or []:
            any_line = True
            if item["lost"]:
                lead = "loses" if not item.get("partly") else "partly loses"
                for i, text in enumerate(item["lost"]):
                    lines.append(f"     {lead if i == 0 else ' ' * len(lead)} {d} {text}"
                                 + (f"   [{item['rule']}]" if i == 0 else ""))
            else:
                by = "; ".join(k["text"] + (f" [{group_label(k['group'], names)}]" if k.get("group") else "")
                               for k in item["kept_by"])
                lines.append(f"     keeps {item['text']}   (still allowed by {by})")
    for item in block.get("as_peer") or []:
        any_line = True
        lines.append(f"     {item['text']}")
    if not any_line:
        lines.append("     no change")


def _names(result: dict) -> dict[str, str]:
    t = result["target"]
    names = {}
    for res in result["resources"]:
        names.update(res.get("group_names") or {})
    names.setdefault(t["id"], t.get("name") or "")
    return names


def loss_lines(res: dict) -> list[str]:
    """What a resource loses if the target group is removed, one line each."""
    out = []
    block = res["remove_sg"]
    for d in (IN, OUT):
        for item in block.get(d) or []:
            mark = "~" if item.get("partly") else "-"
            out += [f"{mark} {d} {text}" for text in item["lost"]]
    out += [f"- {item['text']}" for item in block.get("as_peer") or []]
    return out


def render_text(result: dict, full: bool = False) -> str:
    """The terminal view: by default only what removing the group would cost. full=True adds
    every rule, each resource's effective access, kept access and the referencing groups.
    Rule-removal scenarios (--remove-rule) are left out either way: they're only in the
    HTML report."""
    if full:
        return render_full(result)
    t = result["target"]
    names = _names(result)
    res_list = result["resources"]
    n = len(res_list)
    lines = [f"{group_label(t['id'], names)} · {t.get('vpc') or '?'} · account {result.get('account') or '?'} · "
             f"{result.get('region')} · {len(t['rules'])} rule{'s' if len(t['rules']) != 1 else ''} · "
             + (f"used by {n} resource{'s' if n != 1 else ''}" if n else "not used by any resource")]
    if not n:
        return "\n".join(lines) + "\n"
    groups: dict[tuple, list[dict]] = {}
    for res in res_list:
        groups.setdefault(tuple(loss_lines(res)), []).append(res)
    lines += ["", f"If {group_label(t['id'], names)} is removed:"]
    unchanged = groups.pop((), [])
    for losses, members in groups.items():
        lines.append("")
        for res in members:
            others = [group_label(g, names) for g in res["groups"] if g != t["id"]]
            lines.append(f"  {resource_label(res)}" + (" via " + ", ".join(e["id"] for e in res["enis"])
                                                       if res.get("split") else "")
                         + (f"   [also: {', '.join(others)}]" if others else ""))
        lines += [f"    {x}" for x in losses]
    if unchanged:
        lines += ["", "  No change: " + ", ".join(resource_label(r) for r in unchanged)]
    safe = [s for s in result["rule_summary"] if not s["unique_on"]]
    lines.append("")
    if safe:
        lines.append("Redundant on every resource (deleting them changes no access):")
        lines += [f"  {s['rule']}  {s['text']}" for s in safe]
    elif t["rules"]:
        lines.append(f"No rule of {t['id']} is redundant on every resource.")
    lines += ["", "~ = partly lost (the rest is still allowed by another rule). --full shows each resource's "
                  "effective access."]
    return "\n".join(lines) + "\n"


def render_full(result: dict) -> str:
    t = result["target"]
    names = _names(result)
    lines = [f"Security group {group_label(t['id'], names)}, {t.get('vpc') or '?'}, account "
             f"{result.get('account') or '?'}, {result.get('region')}"]
    if t.get("description"):
        lines.append(f"  {t['description']}")
    lines.append(f"  {len(t['rules'])} rules:")
    lines += [f"    {r['id']}  {r['text']}" + (f"   \"{r['description']}\"" if r.get("description") else "")
              for r in t["rules"]]

    res_list = result["resources"]
    lines += ["", f"Resources using {t['id']}: {len(res_list)}" if res_list
              else f"No resources use {t['id']}."]
    for res in res_list:
        lines += ["", f"== {resource_label(res)}" + ("   (ENIs with different groups are listed separately)"
                                                     if res.get("split") else "")]
        for e in res["enis"]:
            ips = ", ".join(e.get("private_ips") or []) + (f", public {e['public_ip']}" if e.get("public_ip") else "")
            lines.append(f"   ENI {e['id']}  {ips}  {e.get('subnet') or ''}".rstrip())
        lines.append("   Groups: " + ", ".join(group_label(g, names) + (" [target]" if g == t["id"] else "")
                                             for g in res["groups"]))
        for d in (IN, OUT):
            entries = res["effective"][d]
            lines.append(f"   {d.capitalize()} ({len(entries)}):" if entries else f"   {d.capitalize()}: nothing allowed")
            width = max((len(f"{e['traffic']} {'to' if d == OUT else 'from'} {e['peer']}") for e in entries), default=0)
            for e in entries:
                what = f"{e['traffic']} {'to' if d == OUT else 'from'} {e['peer']}"
                note = ""
                if e["covered_by"]:
                    note = f"   (covered by {e['covered_by'][0]['text']})"
                lines.append(f"   {'*' if e['from_target'] else ' '} {what:<{width}}  {_grants(e)}{note}")
        _scenario(lines, f"If {t['id']} is removed from it:", res["remove_sg"], names)
    if res_list:
        lines += ["", "   * = allowed by the target group"]

    if res_list and t["rules"]:
        lines += ["", f"Target rules across {len(res_list)} resource{'s' if len(res_list) != 1 else ''}:"]
        for s in result["rule_summary"]:
            u, r = len(s["unique_on"]), len(s["redundant_on"])
            verdict = (f"redundant on all {r}: removing it changes no access" if not u
                       else f"only rule allowing it on {u}" + (f", redundant on {r}" if r else ""))
            lines.append(f"    {s['rule']}  {s['text']}: {verdict}")

    if result["referencing"]:
        lines += ["", f"Groups whose rules reference {t['id']}:"]
        for g in result["referencing"]:
            n = len(g["resources"])
            lines.append(f"    {group_label(g['group'], {g['group']: g['name']})}, used by {n} other "
                         f"resource{'s' if n != 1 else ''}:")
            lines += [f"      {r}" for r in g["rules"]]
    for w in result["warnings"]:
        lines.append(f"\n% {w}")
    return "\n".join(lines) + "\n"

# --------------------------------------------------------------------------- #
# Reports
# --------------------------------------------------------------------------- #
CSV_COLUMNS = ["resource", "also", "change", "direction", "access", "rule", "note"]
CHANGE_BADGES = {"loses": "error", "partly loses": "warn", "as a peer": "warn", "keeps": "ok", "no change": "ok"}


def _label(res: dict) -> str:
    """Resource label, with the interfaces when the resource's ENIs have different groups."""
    return resource_label(res) + (" via " + ", ".join(e["id"] for e in res["enis"]) if res.get("split") else "")


def change_rows(result: dict, key: str = "remove_sg") -> list[dict]:
    """One row per change to one resource in a scenario: "remove_sg" (the group is removed)
    or "remove_rules" (--remove-rule). Resources with no change get one "no change" row."""
    t = result["target"]["id"]
    names = _names(result)
    rows = []
    for res in result["resources"]:
        base = {"resource": _label(res), "also": [group_label(g, names) for g in res["groups"] if g != t]}
        block = res.get(key) or {}
        mine = []
        for d in (IN, OUT):
            for item in block.get(d) or []:
                if item["lost"]:
                    word = "partly loses" if item.get("partly") else "loses"
                    mine += [{"change": word, "direction": d, "access": x, "rule": item["rule"], "note": ""}
                             for x in item["lost"]]
                else:
                    by = "; ".join(k["text"] + (f" ({group_label(k['group'], names)})" if k.get("group") else "")
                                   for k in item["kept_by"])
                    mine.append({"change": "keeps", "direction": d, "access": item["text"].split(" ", 1)[1],
                                 "rule": item["rule"], "note": f"still allowed by {by}"})
        mine += [{"change": "as a peer", "direction": "inbound" if " inbound " in i["text"] else "outbound",
                  "access": i["text"], "rule": i["rule"], "note": ""} for i in block.get("as_peer") or []]
        if not any(r["change"] != "keeps" for r in mine):
            mine.insert(0, {"change": "no change", "direction": "", "access": "", "rule": "", "note": ""})
        rows += [{**base, **r} for r in mine]
    return rows


def _change_table(tid: str, title: str, note: str, rows: list[dict], collapsed: bool = False) -> dict:
    """html_report table spec for a scenario's change rows."""
    return {
        "collapsed": collapsed,
        "id": tid, "title": title, "note": note, "row_label": "changes",
        "columns": [["resource", "Resource"], ["also", "Other groups"], ["change", "Change"],
                    ["direction", "Direction"], ["access", "Access"], ["rule", "Rule"], ["note", "Note"]],
        "rows": rows, "filters": ["resource", "change", "direction"],
        "uniq": [["resource", "Resources"]], "wrap": ["resource", "access", "note"], "lines": ["also"],
        "badges": {"change": CHANGE_BADGES}, "order": {"change": list(CHANGE_BADGES)},
        "sort": [["resource", 1], ["change", 1]],
        "hide": {"key": "change", "values": ["keeps"], "label": "show kept access"},
    }


def render_html(result: dict) -> str:
    """Interactive HTML report: the removal effects first (both scenarios), then the target's
    rules, every resource's effective access and the groups that reference the target."""
    t = result["target"]
    names = _names(result)
    n = len(result["resources"])
    rows_sg = change_rows(result)
    losing = len({r["resource"] for r in rows_sg if r["change"] not in ("keeps", "no change")})
    safe = [x for x in result["rule_summary"] if not x["unique_on"]] if n else []
    cards = [(n, "resources"), (losing, "lose access if removed"), (len(t["rules"]), "rules"),
             (len(safe), "rules redundant everywhere"), (len(result["referencing"]), "referencing groups")]
    meta = [f"{group_label(t['id'], names)} · {t.get('vpc') or '?'} · account {result.get('account') or '?'} · "
            f"{result.get('region')}" + (f" · {t['description']}" if t.get("description") else ""),
            f"Collected {result.get('generated') or dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')}"
            " · security groups only: network ACLs, route tables and the resources' own firewalls aren't considered"]
    tables = [_change_table("remove_group", f"If {group_label(t['id'], names)} is removed",
                            "What each resource would lose, after counting every other group on it. Partly loses: "
                            "the rest is still allowed by another rule.", rows_sg,
                            collapsed=bool(result["removing"]))]   # a rule scenario leads when given
    if result["removing"]:
        rows_r = change_rows(result, "remove_rules")
        lose = len({r["resource"] for r in rows_r if r["change"] not in ("keeps", "no change")})
        cards.append((lose, "lose access if the selected rules are removed"))
        meta.append("Scenario: remove " + "; ".join(f"{r['id']} {r['text']}" for r in result["removing"]))
        tables.append(_change_table("remove_rules", "If the selected rules are removed",
                                    "Kept access names the rule that still allows it.", rows_r))
    tables.append({
        "id": "rules", "title": f"Rules of {t['id']}", "row_label": "rules", "collapsed": True,
        "columns": [["rule", "Rule"], ["text", "Allows"], ["description", "Description"], ["verdict", "Where it matters"],
                    ["unique_on", "Only rule allowing it on"]],
        "rows": [{"rule": x["rule"], "text": x["text"], "description": x.get("description") or "",
                  "verdict": ("redundant everywhere" if not x["unique_on"] else
                              f"only rule on {len(x['unique_on'])} of {n}") if n else "",
                  "unique_on": x["unique_on"]} for x in result["rule_summary"]],
        "wrap": ["text", "description"], "lines": ["unique_on"],
        "badges": {"verdict": {"redundant everywhere": "ok"}},
    })
    eff = []
    for res in result["resources"]:
        for d in (IN, OUT):
            for e in res["effective"][d]:
                eff.append({"resource": _label(res), "direction": d, "traffic": e["traffic"], "peer": e["peer"],
                            "allowed_by": [f"{group_label(g['group'], names)} {g['rule']}" for g in e["grants"]],
                            "target": "target only" if e["only_target"] else
                            "target + other" if e["from_target"] else "other groups",
                            "note": "; ".join((["anywhere"] if e["open_to_world"] else [])
                                              + [f"covered by {c['text']}" for c in e["covered_by"][:1]])})
    tables.append({
        "id": "access", "title": "Effective access", "row_label": "entries",
        "note": "Each resource's access across all of its groups; identical rules are merged.",
        "columns": [["resource", "Resource"], ["direction", "Direction"], ["traffic", "Traffic"], ["peer", "Peer"],
                    ["allowed_by", "Allowed by"], ["target", "Target group"], ["note", "Note"]],
        "rows": eff, "filters": ["resource", "direction", "target"], "uniq": [["resource", "Resources"]],
        "wrap": ["resource", "peer", "note"], "lines": ["allowed_by"],
        "badges": {"target": {"target only": "warn", "target + other": "info"}},
        "order": {"target": ["target only", "target + other", "other groups"]},
        "hide": {"key": "target", "values": ["other groups"], "label": "show access only other groups allow"},
    })
    tables.append({
        "id": "referencing", "title": f"Groups that reference {t['id']}", "row_label": "groups",
        "note": "Their rules allow traffic to or from members of the target group.",
        "columns": [["group", "Group"], ["rules", "Rules"], ["used_by", "Used by"]],
        "rows": [{"group": group_label(g["group"], {g["group"]: g["name"]}), "rules": g["rules"],
                  "used_by": [resource_label(r) for r in g["resources"]]} for g in result["referencing"]],
        "wrap": ["group"], "lines": ["rules", "used_by"],
    })
    if result["warnings"]:
        tables.append({"id": "warnings", "title": "Warnings", "row_label": "warnings", "columns": [["warning", "Warning"]],
                       "rows": [{"warning": w} for w in result["warnings"]], "wrap": ["warning"]})
    return html_report.render(f"Security group effect: {group_label(t['id'], names)}", meta=meta, cards=cards,
                              tables=tables)


def cli_view(result: dict) -> dict:
    """The analysis without the rule-removal scenario, which only the HTML report shows."""
    view = {k: v for k, v in result.items() if k != "removing"}
    view["resources"] = [{k: v for k, v in r.items() if k != "remove_rules"} for r in result["resources"]]
    return view


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def load_bundle(args) -> dict:
    """The collected data: from a saved JSON report (--from-json), or read from AWS."""
    if args.from_json:
        with open(args.from_json, encoding="utf-8") as fh:
            data = json.load(fh)
        bundle = data.get("bundle", data) if isinstance(data, dict) else {}
        if bundle.get("tool") != "sg_effect":
            raise ValidationError(f"{args.from_json} is not an sg_effect JSON report")
        if args.group and args.group.rsplit("/", 1)[-1] != bundle.get("target"):
            raise ValidationError(f"{args.from_json} is for {bundle.get('target')}, not {args.group}")
        return bundle
    if not args.group:
        raise ValidationError("pass a security group ID or ARN (or --from-json)")
    arn_accounts = spec_accounts([args.group])
    profiles, bare_account = resolve_account_profiles(args, arn_accounts, not arn_accounts)
    account = next(iter(arn_accounts)) if arn_accounts else bare_account
    profile, source = profiles[account]
    log.info("Account %s via %s (%s)", account, profile or "default credentials", source)
    _, region, gid = parse_target(args.group, args.region or boto3.Session(profile_name=profile).region_name)
    return collect(boto3.Session(profile_name=profile, region_name=region), region, gid, account)


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point. Returns 0 ok, 1 the --remove-rule scenario loses access, 2 fatal."""
    p = argparse.ArgumentParser(
        description="Show what a security group really does on every resource that uses it, and what each "
                    "would lose if the group (or some of its rules) were removed.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --profile prod-admin sg-0123456789abcdef0
  %(prog)s sg-0123456789abcdef0 --full
  %(prog)s arn:aws:ec2:us-east-1:111122223333:security-group/sg-0123456789abcdef0
  %(prog)s sg-0123456789abcdef0 --remove-rule sgr-0123456789abcdef0 --remove-rule in:tcp:22:pl-0123456789abcdef0
  %(prog)s --from-json REPORT.json --remove-rule out:-1:all:0.0.0.0/0
""")
    p.add_argument("group", nargs="?", metavar="SG",
                   help="Security group ID or ARN (not needed with --from-json)")
    p.add_argument("--profile", default=None,
                   help="AWS profile for a bare group ID (default AWS_PROFILE); an ARN uses its account's local profile")
    p.add_argument("--region", default=None,
                   help="Region for a bare group ID (default AWS_REGION, then the profile's region)")
    p.add_argument("--remove-rule", action="append", default=[], metavar="RULE",
                   help="Scenario, shown in the HTML report only: delete this rule of the target group "
                        "(repeatable). An sgr- ID, or DIRECTION:PROTOCOL:PORTS:PEER such as in:tcp:443:0.0.0.0/0, "
                        "out:-1:all:0.0.0.0/0, in:tcp:5432:sg-0123... or in:tcp:22:pl-0123...")
    p.add_argument("--full", action="store_true",
                   help="Also list every rule, each resource's effective access, kept access and referencing groups")
    p.add_argument("--resource", action="append", default=[], metavar="ID",
                   help="Only show this resource (instance ID, load balancer or function name, ENI ID; repeatable)")
    p.add_argument("--from-json", metavar="PATH", help="Re-analyze a saved sg_effect JSON report, offline")
    add_output_args(p)
    add_profile_args(p)
    args = p.parse_args(argv)
    setup_logging(args)
    check_profile_args(p, args)
    args.region = args.region or os.getenv("AWS_REGION") or None

    try:
        if args.remove_rule and args.no_save and not args.html_out:
            raise ValidationError("--remove-rule results are only in the HTML report; drop --no-save or pass --html-out")
        bundle = load_bundle(args)
        result = analyze(bundle, args.remove_rule, args.resource)
    except (ValueError, OSError) as e:
        log.error("%s", e)
        return 2
    except (ClientError, BotoCoreError) as e:
        log.error("AWS error: %s", err_text(e))
        return 2
    if args.resource and not result["resources"]:
        log.warning("No resource using %s matches %s", bundle["target"], ", ".join(args.resource))
    for w in result["warnings"]:
        log.warning("%s", w)

    slug = f"sgeffect_{bundle['target']}" + ("_remove-rules" if args.remove_rule else "")
    paths = report_paths(args, "sg_effect", slug)
    view = cli_view(result)
    if paths["json"]:
        write_json(paths["json"], {**view, "bundle": bundle})
    if paths["csv"]:
        write_csv(paths["csv"], change_rows(result), CSV_COLUMNS)
    if paths["html"]:
        write_text(paths["html"], render_html(result))

    if args.json:
        print(json.dumps(view, indent=2, default=str))
    else:
        sys.stdout.write(render_text(result, full=args.full))
        if args.remove_rule:
            print(f"\nRule removal scenario ({', '.join(r['id'] for r in result['removing'])}): "
                  f"see the HTML report")
        print_saved(paths)
    return 1 if loses_access(result) else 0


if __name__ == "__main__":
    sys.exit(main())
