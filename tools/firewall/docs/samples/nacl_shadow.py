"""Synthetic nacl_shadow report: made-up NACLs shaped like DescribeNetworkAcls output, run
through the tool's own analyze_entries() and assembled the way scan()/run() do."""
from __future__ import annotations

import nacl_shadow as ns
from lib.accounts import Target

SHOTS = [("nacl-shadow", "dark", 1100)]

ANY4, ANY6 = "0.0.0.0/0", "::/0"


def e(num: int, action: str, proto: str, cidr: str, ports: tuple[int, int] | None = None,
      egress: bool = False) -> dict:
    """One NACL entry in DescribeNetworkAcls shape."""
    out = {"RuleNumber": num, "RuleAction": action, "Protocol": proto, "Egress": egress,
           ("Ipv6CidrBlock" if ":" in cidr else "CidrBlock"): cidr}
    if ports:
        out["PortRange"] = {"From": ports[0], "To": ports[1]}
    return out


def defaults() -> list[dict]:
    """The immutable '*' deny rules (skipped by the analysis, as in AWS)."""
    return [e(32767, "deny", "-1", ANY4), e(32767, "deny", "-1", ANY4, egress=True)]


def nacl(acl: str, vpc: str, subnets: list[str], entries: list[dict], fmm: bool = False,
         default: bool = False) -> dict:
    return {"NetworkAclId": acl, "VpcId": vpc, "IsDefault": default, "Entries": entries + defaults(),
            "Associations": [{"SubnetId": s} for s in subnets],
            "Tags": [{"Key": "FMManaged", "Value": "true"}] if fmm else []}


TCP, UDP, ALL = "6", "17", "-1"

# (account, profile, region) -> NACLs
INVENTORY: dict[tuple[str, str, str], list[dict]] = {
    ("111122223333", "prod-ro", "us-east-1"): [
        nacl("acl-0123456789abcdef0", "vpc-0a1b2c3d4e5f60718", ["subnet-0a11b22c33d44e551", "subnet-0a11b22c33d44e552"], [
            e(100, "allow", TCP, ANY4, (443, 443)),
            e(110, "allow", TCP, ANY4, (80, 80)),
            e(120, "deny", TCP, "203.0.113.0/24", (443, 443)),        # blocklist added below the allow
            e(130, "allow", TCP, ANY4, (1024, 65535)),
            e(140, "allow", TCP, "10.0.0.0/8", (32768, 61000)),
            e(150, "deny", ALL, "198.51.100.0/24"),
            e(200, "allow", TCP, "10.20.0.0/16", (22, 22)),
            e(100, "allow", ALL, ANY4, egress=True),
            e(110, "deny", TCP, ANY4, (25, 25), egress=True),
        ], fmm=True),
        nacl("acl-0fedcba9876543210", "vpc-0a1b2c3d4e5f60718", ["subnet-0a11b22c33d44e553"], [
            e(100, "allow", TCP, "10.20.0.0/16", (5432, 5432)),
            e(110, "allow", TCP, "10.30.0.0/16", (5432, 5432)),
            e(100, "allow", TCP, "10.0.0.0/8", (1024, 65535), egress=True),
        ], fmm=True),
    ],
    ("111122223333", "prod-ro", "us-west-2"): [
        nacl("acl-02468ace13579bdf0", "vpc-0b2c3d4e5f6071829", ["subnet-0b22c33d44e55f661"], [
            e(100, "deny", TCP, ANY4, (22, 22)),
            e(110, "allow", TCP, "10.0.0.0/8", (22, 22)),
            e(120, "allow", TCP, "10.10.0.0/16", (20, 23)),
            e(130, "allow", UDP, "10.0.0.0/8", (53, 53)),
            e(140, "allow", UDP, "10.0.0.0/16", (53, 53)),
            e(160, "allow", TCP, "10.0.0.0/8", (3389, 3389)),
            e(170, "allow", TCP, "10.0.0.0/8", (3300, 3400)),
            e(100, "allow", ALL, ANY4, egress=True),
        ]),
    ],
    ("444455556666", "shared-svc-ro", "us-east-1"): [
        nacl("acl-0a0b0c0d0e0f01020", "vpc-0c3d4e5f60718293a", ["subnet-0c33d44e55f66a771", "subnet-0c33d44e55f66a772",
                                                                "subnet-0c33d44e55f66a773"], [
            e(100, "allow", ALL, ANY4),
            e(101, "allow", ALL, ANY6),
            e(110, "deny", TCP, ANY4, (3389, 3389)),
            e(111, "deny", TCP, ANY6, (22, 22)),
            e(100, "allow", ALL, ANY4, egress=True),
        ], default=True),
    ],
    ("444455556666", "shared-svc-ro", "eu-west-1"): [
        nacl("acl-0135792468ace0bdf", "vpc-0d4e5f60718293a4b", ["subnet-0d44e55f66a77b881"], [
            e(100, "allow", TCP, ANY4, (1024, 65535)),
            e(110, "allow", TCP, "172.16.0.0/12", (443, 443)),
            e(100, "allow", TCP, ANY4, (443, 443), egress=True),
            e(110, "allow", TCP, "10.0.0.0/8", (443, 443), egress=True),
            e(120, "allow", TCP, "10.0.0.0/8", (1024, 65535), egress=True),
            e(130, "allow", TCP, "10.0.0.0/8", (1000, 2000), egress=True),
        ], fmm=True),
    ],
    ("777788889999", "dev-ro", "us-east-1"): [
        nacl("acl-0badc0ffee0123456", "vpc-0e5f60718293a4b5c", ["subnet-0e55f66a77b88c991", "subnet-0e55f66a77b88c992"], [
            e(100, "deny", ALL, "192.0.2.0/24"),
            e(110, "allow", TCP, "192.0.2.0/25", (443, 443)),
            e(120, "allow", TCP, "192.0.2.0/23", (443, 443)),
            e(130, "allow", TCP, "192.0.3.0/24", (443, 443)),
            e(140, "allow", TCP, "10.40.0.0/16", (8080, 8090)),
            e(150, "allow", TCP, "10.40.0.0/16", (8085, 8100)),
            e(100, "allow", ALL, "10.0.0.0/8", egress=True),
            e(110, "allow", TCP, "172.16.0.0/12", (443, 443), egress=True),
        ], fmm=True),
    ],
}

SKIPPED = [Target("555566667777", None, ok=False, note="no local profile found for account 555566667777")]


def render() -> str:
    """Analyse every synthetic NACL as scan()/run() would and return the HTML report."""
    regions = sorted({r for _, _, r in INVENTORY})
    stats = {"accounts": len({a for a, _, _ in INVENTORY}), "accounts_skipped": len(SKIPPED),
             "regions": len(regions), "nacls": 0, "rules": 0}
    findings = [ns.unscannable(t) for t in SKIPPED]
    for (account, profile, region), nacls in INVENTORY.items():
        for n in nacls:
            stats["nacls"] += 1
            stats["rules"] += sum(1 for x in n["Entries"] if x["RuleNumber"] < ns.DEFAULT_RULE_MIN)
            base = dict(account=account, profile=profile, region=region, vpc_id=n["VpcId"], nacl_id=n["NetworkAclId"],
                        subnets=sorted(a["SubnetId"] for a in n["Associations"]),
                        fmmanaged="yes" if ns.is_fmmanaged(n) else "no")
            for code, r, hits, effective in ns.analyze_entries(n["Entries"]):
                findings.append(ns.Finding(
                    severity=ns.SEVERITY[code], code=code, **base, direction=r.direction, rule_number=r.number,
                    action=r.action, rule=r.text, shadowed_by=[o.text for o in hits], effective=effective,
                    detail=ns.DETAIL[code] + (" (default NACL)" if n["IsDefault"] else "")))
    findings.sort(key=lambda f: (f.account, f.region, f.vpc_id, f.nacl_id, f.direction != "ingress",
                                 f.rule_number if isinstance(f.rule_number, int) else -1))
    stats["dead_rules"] = sum(f.code in ns.DEAD_CODES for f in findings)
    stats["by_code"] = {}
    for f in findings:
        stats["by_code"][f.code] = stats["by_code"].get(f.code, 0) + 1
    return ns.render_html(findings, stats)
