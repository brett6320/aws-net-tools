"""Synthetic sample for fmm_nacl_audit: two NACL policies across three member accounts.

Made-up FMS policies and describe_network_acls-shaped NACLs are checked with the
tool's own baseline_from_policy(), analyze_nacl() and check_default_nacl(); the
run-level bookkeeping (NO_PROFILE, sort, stats) mirrors run().
"""
from __future__ import annotations

import re

import fmm_nacl_audit as t

SHOTS = [("fmm-nacl-audit", "dark", 1100)]

GENERATED = "2026-10-19 09:14:02"


def _e(num: int, action: str, proto: str, cidr: str, ports: int | tuple[int, int] | None = None,
       egress: bool = False) -> dict:
    """One NACL entry in EC2 / FMS PascalCase shape."""
    e = {"RuleNumber": num, "RuleAction": action, "Protocol": proto, "CidrBlock": cidr, "Egress": egress}
    if ports is not None:
        lo, hi = (ports, ports) if isinstance(ports, int) else ports
        e["PortRange"] = {"From": lo, "To": hi}
    return e


def _policy(pid: str, name: str, first: list[dict], last: list[dict]) -> dict:
    strip = lambda es: [{k: v for k, v in e.items() if k != "RuleNumber"} for e in es]
    return {"PolicyId": pid, "PolicyName": name,
            "SecurityServicePolicyData": {"Type": "NETWORK_ACL_COMMON", "PolicyOption": {"NetworkAclCommonPolicy": {
                "NetworkAclEntrySet": {"FirstEntries": strip(first), "LastEntries": strip(last),
                                       "ForceRemediateForFirstEntries": True,
                                       "ForceRemediateForLastEntries": False}}}}}


# prod: allow internal HTTPS/SSH first, deny a documentation range and RDP last
PROD_FIRST = [_e(0, "allow", "6", "10.0.0.0/8", 443), _e(0, "allow", "6", "10.10.0.0/16", 22),
              _e(0, "allow", "-1", "10.0.0.0/8", egress=True)]
PROD_LAST = [_e(0, "deny", "-1", "203.0.113.0/24"), _e(0, "deny", "6", "0.0.0.0/0", 3389),
             _e(0, "deny", "-1", "198.51.100.0/24", egress=True)]
DEV_FIRST = [_e(0, "allow", "6", "172.16.0.0/12", (1024, 65535)), _e(0, "allow", "-1", "172.16.0.0/12", egress=True)]
DEV_LAST = [_e(0, "deny", "-1", "192.0.2.0/24"), _e(0, "deny", "-1", "192.0.2.0/24", egress=True)]

PROD = _policy("3f2a1b0c-9d8e-4f7a-8b6c-5d4e3f2a1b0c", "prod-baseline-nacl", PROD_FIRST, PROD_LAST)
DEV = _policy("7c6b5a49-3827-4165-9a4b-3c2d1e0f9a8b", "dev-baseline-nacl", DEV_FIRST, DEV_LAST)


def _good_prod(custom: list[dict]) -> list[dict]:
    """Prod policy rules at FMS's initial numbers, plus custom rules, plus the '*' defaults."""
    return ([_e(1, "allow", "6", "10.0.0.0/8", 443), _e(2, "allow", "6", "10.10.0.0/16", 22),
             _e(1, "allow", "-1", "10.0.0.0/8", egress=True)] + custom +
            [_e(32765, "deny", "-1", "203.0.113.0/24"), _e(32766, "deny", "6", "0.0.0.0/0", 3389),
             _e(32766, "deny", "-1", "198.51.100.0/24", egress=True)] + _defaults())


def _defaults() -> list[dict]:
    return [_e(32767, "deny", "-1", "0.0.0.0/0"), _e(32767, "deny", "-1", "0.0.0.0/0", egress=True)]


def _nacl(nid: str, vpc: str, subnets: list[str], entries: list[dict], managed: bool = True,
          default: bool = False) -> dict:
    return {"NetworkAclId": nid, "VpcId": vpc, "IsDefault": default, "Entries": entries,
            "Associations": [{"SubnetId": s} for s in subnets],
            "Tags": [{"Key": "FMManaged", "Value": "true"}] if managed else [{"Key": "Name", "Value": "app-nacl"}]}


def _app_rules(n: int, start: int = 5000) -> list[dict]:
    """n distinct custom ingress rules from the docs ranges and internal subnets."""
    return [_e(start + 10 * i, "allow", "6", f"10.{40 + i // 8}.{(i % 8) * 16}.0/20", 8000 + i) for i in range(n)]


# (region, policy, account, profile, [NACLs]); None profile = no local profile
SCAN = [
    ("us-east-1", PROD, "111122223333", "prod-core", [
        _nacl("acl-0123456789abcdef0", "vpc-0a1b2c3d4e5f60718", ["subnet-0aa11bb22cc33dd44", "subnet-0aa11bb22cc33dd45"],
              _good_prod(_app_rules(4))),
        # first block renumbered, plus an extra custom rule outside 5000-32000
        _nacl("acl-0123456789abcdef1", "vpc-0a1b2c3d4e5f60718", ["subnet-0aa11bb22cc33dd46"],
              [_e(100, "allow", "6", "10.0.0.0/8", 443), _e(110, "allow", "6", "10.10.0.0/16", 22),
               _e(1, "allow", "-1", "10.0.0.0/8", egress=True), _e(200, "allow", "17", "10.30.0.0/16", 53),
               _e(32765, "deny", "-1", "203.0.113.0/24"), _e(32766, "deny", "6", "0.0.0.0/0", 3389),
               _e(32766, "deny", "-1", "198.51.100.0/24", egress=True)] + _defaults()),
        # near the rules-per-direction limit, with a duplicate
        _nacl("acl-0123456789abcdef2", "vpc-0b2c3d4e5f6071829", ["subnet-0bb22cc33dd44ee55", "subnet-0bb22cc33dd44ee56",
                                                                "subnet-0bb22cc33dd44ee57"],
              _good_prod(_app_rules(23) + [_e(5900, "allow", "6", "10.40.0.0/20", 8000)])),
        _nacl("acl-0fedcba9876543210", "vpc-0a1b2c3d4e5f60718", [], [_e(100, "allow", "-1", "0.0.0.0/0"),
              _e(100, "allow", "-1", "0.0.0.0/0", egress=True)] + _defaults(), default=True),
    ]),
    ("us-east-1", PROD, "444455556666", "shared-services", [
        # SSH rule swapped ahead of HTTPS; last block edited by hand
        _nacl("acl-0a9b8c7d6e5f40312", "vpc-0c3d4e5f607182930", ["subnet-0cc33dd44ee55ff66"],
              [_e(1, "allow", "6", "10.10.0.0/16", 22), _e(2, "allow", "6", "10.0.0.0/8", 443),
               _e(1, "allow", "-1", "10.0.0.0/8", egress=True)] + _app_rules(3) +
              [_e(32765, "deny", "-1", "203.0.113.0/24"), _e(32766, "deny", "6", "0.0.0.0/0", 3390),
               _e(32766, "deny", "-1", "198.51.100.0/24", egress=True)] + _defaults()),
        # never taken over by FMS: no policy rules at all
        _nacl("acl-0a9b8c7d6e5f40313", "vpc-0c3d4e5f607182930", ["subnet-0cc33dd44ee55ff67"],
              [_e(100, "allow", "6", "10.0.0.0/8", 443), _e(100, "allow", "-1", "0.0.0.0/0", egress=True)]
              + _defaults(), managed=False),
    ]),
    ("us-east-1", PROD, "777788889999", None, []),
    ("ca-central-1", DEV, "444455556666", "shared-services", [
        _nacl("acl-0d1e2f3a4b5c6d7e8", "vpc-0d4e5f60718293a4b", ["subnet-0dd44ee55ff66aa77"],
              [_e(1, "allow", "6", "172.16.0.0/12", (1024, 65535)), _e(1, "allow", "-1", "172.16.0.0/12", egress=True),
               _e(5000, "allow", "6", "172.20.0.0/16", 5432), _e(32766, "deny", "-1", "192.0.2.0/24"),
               _e(32766, "deny", "-1", "192.0.2.0/24", egress=True)] + _defaults()),
        # egress last block missing entirely
        _nacl("acl-0d1e2f3a4b5c6d7e9", "vpc-0d4e5f60718293a4b", ["subnet-0dd44ee55ff66aa78", "subnet-0dd44ee55ff66aa79"],
              [_e(1, "allow", "6", "172.16.0.0/12", (1024, 65535)), _e(32766, "deny", "-1", "192.0.2.0/24")]
              + _defaults()),
    ]),
    ("ca-central-1", DEV, "777788889999", "dev-sandbox", [
        _nacl("acl-0e2f3a4b5c6d7e8f9", "vpc-0e5f60718293a4b5c", ["subnet-0ee55ff66aa77bb88"],
              [_e(1, "allow", "6", "172.16.0.0/12", (1024, 65535)), _e(1, "allow", "-1", "172.16.0.0/12", egress=True),
               _e(5000, "allow", "6", "172.20.0.0/16", 443), _e(5010, "allow", "6", "172.20.0.0/16", 443),
               _e(32766, "deny", "-1", "192.0.2.0/24"), _e(32766, "deny", "-1", "192.0.2.0/24", egress=True)]
              + _defaults()),
    ]),
]


def render() -> str:
    findings: list[t.Finding] = []
    stats = {"policies": 2, "accounts": 0, "accounts_skipped": 0, "nacls": 0}
    for region, pol, account, profile, nacls in SCAN:
        baselines = [t.baseline_from_policy(pol, "live")]
        ctx = dict(region=region, policy_name=pol["PolicyName"], policy_id=pol["PolicyId"], account=account,
                   profile=profile or "")
        if not profile:
            stats["accounts_skipped"] += 1
            findings.append(t.Finding(severity="error", code="NO_PROFILE", baseline="", **ctx,
                                      detail="no local AWS profile for account (FMS status NON_COMPLIANT)"))
            continue
        stats["accounts"] += 1
        for n in nacls:
            if n["IsDefault"]:
                findings += t.check_default_nacl(n, ctx)
            else:
                stats["nacls"] += 1
                findings += t.analyze_nacl(n, baselines, ctx, t.DEFAULT_LIMIT, t.DEFAULT_HEADROOM)
    findings.sort(key=lambda f: (f.region, f.policy_name, f.account, f.nacl_id,
                                 t.SEVERITY_ORDER[f.severity], f.baseline, f.direction, f.position))
    stats["by_code"] = {}
    for f in findings:
        stats["by_code"][f.code] = stats["by_code"].get(f.code, 0) + 1
    html = t.render_html(findings, stats)
    return re.sub(r"Generated \d{4}-\d\d-\d\d \d\d:\d\d:\d\d", f"Generated {GENERATED}", html)
