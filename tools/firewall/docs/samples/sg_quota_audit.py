"""Synthetic sg_quota_audit report. scan_region() builds its own boto3 clients, so this builds
the GroupUsage rows and findings it would produce (same codes, thresholds and detail text),
using the tool's _stale_refs() and group_row(), and renders them with render_html()."""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import asdict

import sg_quota_audit as sqa
from lib.output import SEVERITY_ORDER

SHOTS = [("sg-quota-audit", "dark", 1000)]

GENERATED = "2026-03-16 10:05:31"
HEADROOM, ENI_HEADROOM = sqa.DEFAULT_HEADROOM, sqa.DEFAULT_ENI_HEADROOM
PROFILE = {"111122223333": "prod-ro", "444455556666": "shared-svc-ro", "777788889999": "dev-ro"}
PL_NAMES = {"pl-0123456789abcdef0": "corp-onprem-v4", "pl-0c0ffee0123456789": "partner-vpn",
            "pl-01b2c3d4e5f607182": "monitoring-sources", "pl-63a5400a": "com.amazonaws.us-east-1.s3"}
UNKNOWN_PL = {"pl-63a5400a"}     # AWS-managed: no MaxEntries, counted as 1

# (account, region) -> (rules-per-group limit, source, groups-per-ENI limit, source)
QUOTAS = {("111122223333", "us-east-1"): (100, "applied", 5, "applied"),
          ("111122223333", "us-west-2"): (60, "aws-default", 5, "aws-default"),
          ("444455556666", "us-east-1"): (60, "applied", 5, "applied"),
          ("777788889999", "us-east-1"): (60, "default", 5, "default")}
ENIS_SCANNED = {("111122223333", "us-east-1"): 214, ("111122223333", "us-west-2"): 37,
                ("444455556666", "us-east-1"): 96, ("777788889999", "us-east-1"): 58}


def grp(account: str, region: str, vpc: str, gid: str, name: str, in_rules: int, out_rules: int, enis: int,
        in_pls: dict[str, tuple[int, int]] | None = None, out_pls: dict[str, tuple[int, int]] | None = None,
        referenced_by: list[str] | None = None) -> sqa.GroupUsage:
    """A group with `in_rules`/`out_rules` plain rules plus prefix list rules {pl-id: (rules, weight each)}."""
    g = sqa.GroupUsage(account, region, vpc, gid, name, name == "default", limit=QUOTAS[(account, region)][0],
                       enis=enis, referenced_by=referenced_by or [])
    for d, plain, pls in (("inbound", in_rules, in_pls or {}), ("outbound", out_rules, out_pls or {})):
        raw, eff = plain, plain
        for pid, (n, w) in pls.items():
            raw, eff = raw + n, eff + n * w
            g.pl_weights[d][pid] = n * w
        setattr(g, f"{d}_raw", raw)
        setattr(g, f"{d}_effective", eff)
    return g


A, B, C = "111122223333", "444455556666", "777788889999"
VPC_A1, VPC_A2, VPC_B1, VPC_C1 = ("vpc-0a1b2c3d4e5f60718", "vpc-0b2c3d4e5f6071829", "vpc-0c3d4e5f60718293a",
                                  "vpc-0e5f60718293a4b5c")
CORP, PARTNER, MON, S3 = "pl-0123456789abcdef0", "pl-0c0ffee0123456789", "pl-01b2c3d4e5f607182", "pl-63a5400a"

GROUPS = [
    grp(A, "us-east-1", VPC_A1, "sg-0fedcba9876543210", "edge-ingress", 18, 2, 12,
        in_pls={CORP: (2, 20), PARTNER: (4, 10)}),
    grp(A, "us-east-1", VPC_A1, "sg-01a2b3c4d5e6f7081", "app-tier", 41, 3, 46, in_pls={CORP: (2, 20)},
        out_pls={S3: (1, 1)}, referenced_by=["sg-0fedcba9876543210"]),
    grp(A, "us-east-1", VPC_A1, "sg-02b3c4d5e6f708192", "db-tier", 6, 1, 8,
        referenced_by=["sg-01a2b3c4d5e6f7081"]),
    grp(A, "us-east-1", VPC_A1, "sg-0a0b0c0d0e0f01020", "default", 1, 1, 0),
    grp(A, "us-east-1", VPC_A1, "sg-03c4d5e6f7081920a", "old-bastion", 3, 1, 0),
    grp(A, "us-west-2", VPC_A2, "sg-04d5e6f708192a3b4", "dr-app-tier", 22, 1, 9, in_pls={CORP: (2, 20)}),
    grp(A, "us-west-2", VPC_A2, "sg-05e6f708192a3b4c5", "dr-replication", 12, 46, 4),
    grp(A, "us-west-2", VPC_A2, "sg-0b1c2d3e4f5a60718", "default", 0, 1, 2),
    grp(B, "us-east-1", VPC_B1, "sg-06f708192a3b4c5d6", "monitoring-collectors", 6, 1, 6,
        in_pls={MON: (1, 50)}),
    grp(B, "us-east-1", VPC_B1, "sg-0708192a3b4c5d6e7", "shared-dns", 14, 2, 4),
    grp(B, "us-east-1", VPC_B1, "sg-08192a3b4c5d6e7f8", "ldap-replicas", 8, 1, 0,
        referenced_by=["sg-0708192a3b4c5d6e7"]),
    grp(B, "us-east-1", VPC_B1, "sg-0c3d4e5f60718293b", "default", 2, 1, 0),
    grp(C, "us-east-1", VPC_C1, "sg-092a3b4c5d6e7f809", "ci-runners", 31, 1, 18, in_pls={CORP: (1, 20)},
        out_pls={S3: (1, 1)}),
    grp(C, "us-east-1", VPC_C1, "sg-0a3b4c5d6e7f8091a", "sandbox-k8s-nodes", 23, 2, 22),
    grp(C, "us-east-1", VPC_C1, "sg-0b4c5d6e7f8091a2b", "temp-load-test", 5, 1, 0),
]

# Network interfaces carrying many groups: (account, region, vpc, eni, description, groups)
ENIS = [
    (A, "us-east-1", VPC_A1, "eni-0a1b2c3d4e5f60718", "ELB app/edge-alb/0a1b2c3d4e5f6071",
     ["sg-0fedcba9876543210", "sg-01a2b3c4d5e6f7081", "sg-02b3c4d5e6f708192", "sg-0e1f2a3b4c5d6e7f8",
      "sg-0f2a3b4c5d6e7f809"]),
    (A, "us-east-1", VPC_A1, "eni-0b2c3d4e5f6071829", "i-0a1b2c3d4e5f60718",
     ["sg-01a2b3c4d5e6f7081", "sg-02b3c4d5e6f708192", "sg-0e1f2a3b4c5d6e7f8", "sg-0f2a3b4c5d6e7f809"]),
    (C, "us-east-1", VPC_C1, "eni-0c3d4e5f60718293a", "aws-K8S-i-0b2c3d4e5f6071829",
     ["sg-092a3b4c5d6e7f809", "sg-0a3b4c5d6e7f8091a", "sg-0d6e7f8091a2b3c4d", "sg-0e7f8091a2b3c4d5e"]),
]

# describe_stale_security_groups entries: (account, region, vpc, entry)
STALE = [
    (A, "us-west-2", VPC_A2, {"GroupId": "sg-05e6f708192a3b4c5", "GroupName": "dr-replication", "StaleIpPermissions": [
        {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
         "UserIdGroupPairs": [{"GroupId": "sg-0dead0beef0123456", "VpcPeeringConnectionId": "pcx-0a1b2c3d4e5f60718"}]}]}),
    (B, "us-east-1", VPC_B1, {"GroupId": "sg-08192a3b4c5d6e7f8", "GroupName": "ldap-replicas", "StaleIpPermissions": [
        {"IpProtocol": "tcp", "FromPort": 636, "ToPort": 636, "UserIdGroupPairs": [{"GroupId": "sg-0feed0face0123456"}]},
        {"IpProtocol": "tcp", "FromPort": 389, "ToPort": 389, "UserIdGroupPairs": [{"GroupId": "sg-0feed0face0123456"}]}]}),
]


def base(account: str, region: str) -> dict:
    return dict(account=account, profile=PROFILE[account], region=region)


def findings_for() -> list[sqa.Finding]:
    """The findings scan_region() would emit for the synthetic inventory."""
    out = []
    for (acct, region), (rl, rsrc, el, esrc) in QUOTAS.items():
        if "default" in (rsrc, esrc):
            out.append(sqa.Finding("info", "QUOTA_DEFAULTS_USED", **base(acct, region),
                                   detail=f"Service Quotas values not available; using rules-per-group {rl} "
                                          f"({rsrc}), groups-per-interface {el} ({esrc})"))
    for acct, region, vpc, eni, desc, attached in ENIS:
        n, lim = len(attached), QUOTAS[(acct, region)][2]
        if n >= lim - ENI_HEADROOM:
            out.append(sqa.Finding("error" if n >= lim else "warn",
                                   "ENI_AT_SG_LIMIT" if n >= lim else "ENI_NEAR_SG_LIMIT", **base(acct, region),
                                   vpc_id=vpc, resource_id=eni, resource_name=desc, count=n, limit=lim,
                                   detail=f"groups: {', '.join(attached)}"))
    for g in GROUPS:
        gbase = dict(**base(g.account, g.region), vpc_id=g.vpc_id, resource_id=g.group_id, resource_name=g.name)
        for d in sqa.DIRECTIONS:
            eff, raw = getattr(g, f"{d}_effective"), getattr(g, f"{d}_raw")
            if eff >= g.limit - HEADROOM:
                heavy = sorted(g.pl_weights[d].items(), key=lambda kv: -kv[1])[:3]
                parts = [f"{raw} rules count as {eff}"]
                if heavy:
                    parts.append("heaviest prefix lists: " + ", ".join(
                        f"{pid}{f' ({PL_NAMES[pid]})' if PL_NAMES.get(pid) else ''} {w}" for pid, w in heavy))
                if any(pid in UNKNOWN_PL for pid in g.pl_weights[d]):
                    parts.append("AWS-managed prefix list weight not known; counted as 1")
                out.append(sqa.Finding("error" if eff >= g.limit else "warn",
                                       "SG_AT_LIMIT" if eff >= g.limit else "SG_NEAR_LIMIT", **gbase,
                                       direction=d, count=eff, limit=g.limit, detail="; ".join(parts)))
        if g.is_default and (g.inbound_raw or g.outbound_raw):
            out.append(sqa.Finding("warn", "DEFAULT_SG_HAS_RULES", **gbase, count=g.inbound_raw + g.outbound_raw,
                                   detail=f"{g.inbound_raw} inbound, {g.outbound_raw} outbound rule(s); the VPC "
                                          f"default group should allow nothing"))
        if not g.is_default and g.enis == 0:
            refd = (f"referenced by {', '.join(sorted(g.referenced_by))}, so possibly still needed"
                    if g.referenced_by else "not referenced by other groups")
            out.append(sqa.Finding("info", "UNATTACHED_SG", **gbase,
                                   detail=f"attached to no network interface; {refd}. May still be used by "
                                          f"launch templates or other configuration"))
    for acct, region, vpc, sg in STALE:
        refs = sqa._stale_refs(sg)
        out.append(sqa.Finding("warn", "STALE_REFERENCE", **base(acct, region), vpc_id=vpc,
                               resource_id=sg["GroupId"], resource_name=sg["GroupName"], count=len(refs),
                               detail="stale: " + "; ".join(refs)))
    out.append(sqa.Finding("error", "NO_PROFILE", account="555566667777",
                           detail="no local profile found for account 555566667777"))
    return out


def render() -> str:
    """Assemble the payload the way run() does and return the HTML report."""
    findings = findings_for()
    findings.sort(key=lambda f: (f.account, f.region, SEVERITY_ORDER[f.severity], f.code, f.vpc_id,
                                 f.resource_id, f.direction))
    groups = sorted(GROUPS, key=lambda g: (-g.peak_pct, g.account, g.region, g.group_id))
    by_code: dict[str, int] = defaultdict(int)
    for f in findings:
        by_code[f.code] += 1
    stats = {"accounts": len({a for a, _ in QUOTAS}), "accounts_skipped": 1, "regions": len({r for _, r in QUOTAS}),
             "groups": len(GROUPS), "enis": sum(ENIS_SCANNED.values()), "by_code": dict(by_code)}
    quotas = [asdict(sqa.Quotas(a, r, rl, rs, el, es)) for (a, r), (rl, rs, el, es) in QUOTAS.items()]
    payload = {"stats": stats, "quotas": quotas, "groups": [sqa.group_row(g) for g in groups],
               "findings": [asdict(f) for f in findings]}
    html = sqa.render_html(payload)
    # render_html stamps the current time; pin it so the screenshot is reproducible
    return re.sub(r"Generated \d{4}-\d\d-\d\d \d\d:\d\d:\d\d", f"Generated {GENERATED}", html, count=1)
