"""Analysis for sg_effect: pure functions over a collected bundle.

For every resource that uses the target group:

  effective    the resource's inbound and outbound access: every rule of every group on
               it, identical rules merged, each with the groups that grant it and any
               broader rule that already covers it.
  remove_sg    what the resource loses if the target group is taken off it: the part of
               each target rule no other group on the resource allows, plus access that
               groups referencing the target grant to its members.
  remove_rules what it loses if the chosen target rules are deleted (--remove-rule), and,
               for access it keeps, which rules still allow it.

The rule summary says, for each target rule, on which resources it grants something no
other rule does. A rule that's redundant everywhere can go without changing any access.
"""
from __future__ import annotations

import ipaddress
import re

import se_access as acc
from se_core import ValidationError

IN, OUT = "inbound", "outbound"


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
