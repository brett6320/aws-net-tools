"""Synthetic sg_migration_check report: a legacy group being replaced, with the interfaces that
carry it and the rules in other groups that reference it, all in EC2 API shape (Describe-
NetworkInterfaces / DescribeSecurityGroupRules), run through the tool's own review(),
change_groups() and check_references()."""
from __future__ import annotations

import hashlib
from dataclasses import asdict

import sg_migration_check as mig
from lib.security_groups import SG, SgRule

GENERATED = "2026-10-14 11:18:52"
A1, REGION = "111122223333", "us-east-1"
VPC = "vpc-0a1b2c3d4e5f60718"
OLD, NEW, STD, COMPAT = "sg-0a3f9c2e71b4d5068", "sg-0b7e1d4a9c3f20581", "sg-0c5d8e2f4a1b70936", "sg-0d2a6b9e3f7c14805"
DB, CACHE, ALBSG = "sg-01234abcd5678ef90", "sg-0e8f4c1a7d2b59360", "sg-0fedcba9876543210"
BASTION = "pl-0123456789abcdef0"
PREFIX_LISTS = {BASTION: ("bastion-hosts", ["10.20.255.0/28", "10.21.255.0/28"])}

SHOTS = [("sg-migration-check", "dark", 1100)]

GROUPS = [SG(OLD, "legacy-orders-app", VPC, A1, REGION, "orders app (pre-2024 build)"),
          SG(NEW, "orders-app-v2", VPC, A1, REGION, "orders app"),
          SG(STD, "std-baseline", VPC, A1, REGION, "monitoring and egress baseline"),
          SG(COMPAT, "orders-rds-compat", VPC, A1, REGION, "copy of legacy rules for the RDS proxy")]

# group -> [(egress, proto, from, to, peer, description)]; peer: CIDR, pl-, sg- (the group itself = self)
_LEGACY = [(False, "tcp", 8080, 8080, ALBSG, "from internal ALB"),
           (False, "tcp", 22, 22, BASTION, "SSH from bastions"),
           (False, "tcp", 9100, 9100, "10.50.0.0/24", "node exporter"),
           (True, "tcp", 443, 443, "0.0.0.0/0", "HTTPS out"),
           (True, "tcp", 5432, 5432, DB, "orders database"),
           (True, "udp", 53, 53, "10.20.0.2/32", "VPC resolver"),
           (True, "tcp", 9092, 9094, "10.40.0.0/16", "Kafka brokers")]
RULES: dict[str, list[tuple]] = {
    OLD: _LEGACY,
    NEW: [(False, "tcp", 8080, 8080, ALBSG, "from internal ALB"),
          (False, "tcp", 22, 22, "10.20.255.0/28", "SSH from bastion A"),
          (False, "tcp", 22, 22, "10.21.255.0/28", "SSH from bastion B"),
          (False, "tcp", 8443, 8443, "10.20.0.0/16", "mTLS health checks"),
          (False, "-1", None, None, NEW, "cluster peers"),
          (True, "tcp", 443, 443, "0.0.0.0/0", "HTTPS out"),
          (True, "tcp", 5432, 5432, DB, "orders database"),
          (True, "udp", 53, 53, "10.20.0.2/32", "VPC resolver")],
    STD: [(False, "tcp", 9100, 9100, "10.50.0.0/24", "node exporter"),
          (False, "icmp", 8, -1, "10.0.0.0/8", "ping"),
          (True, "-1", None, None, "0.0.0.0/0", "")],
    COMPAT: _LEGACY,
}

# groups referencing the old group (find_references): {group: [(egress, proto, from, to, peer, description)]}
REFERENCING: dict[str, list[tuple]] = {
    DB: [(False, "tcp", 5432, 5432, OLD, "orders app (legacy)"), (False, "tcp", 5432, 5432, NEW, "orders app")],
    CACHE: [(False, "tcp", 6379, 6379, OLD, "orders app session cache"),
            (False, "tcp", 6379, 6379, "10.30.0.0/16", "admin subnet")],
    ALBSG: [(True, "tcp", 8080, 8080, OLD, "targets (legacy)"), (True, "tcp", 8080, 8080, NEW, "targets"),
            (True, "tcp", 8081, 8081, OLD, "admin port")],
}

UUID = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
# (eni, attachment / type / description fields, groups)
INTERFACES = [
    ("eni-0123456789abcdef0", {"Attachment": {"InstanceId": "i-0abc123def4567890"}}, [OLD, NEW, STD]),
    ("eni-0fedcba9876543210", {"Attachment": {"InstanceId": "i-0def456abc7890123"}}, [OLD, NEW, STD]),
    ("eni-0a1b2c3d4e5f60789", {"InterfaceType": "interface", "Description": "ELB app/orders-internal/0123456789abcdef",
                               "RequesterManaged": True, "RequesterId": "amazon-elb"}, [OLD, NEW, STD]),
    ("eni-0b2c3d4e5f6071890", {"Attachment": {"InstanceId": "i-0123456789abcdef0"}}, [OLD, NEW]),
    ("eni-0c3d4e5f607182901", {"InterfaceType": "lambda", "Description": f"AWS Lambda VPC ENI-orders-sync-{UUID}",
                               "RequesterManaged": True, "RequesterId": "AROAEXAMPLEROLEID:orders-sync"}, [OLD]),
    ("eni-0d4e5f60718293012", {"InterfaceType": "interface", "Description": "EFS mount target for fs-0123456789abcdef0 "
                               "(fsmt-0123456789abcdef0)", "RequesterManaged": True, "RequesterId": "amazon-efs"}, [OLD]),
    ("eni-0e5f6071829301234", {"InterfaceType": "interface", "Description": "RDSNetworkInterface",
                               "RequesterManaged": True, "RequesterId": "amazon-rds"}, [OLD, COMPAT]),
]


def rule_id(gid: str, i: int) -> str:
    """Stable made-up rule id."""
    return "sgr-0" + hashlib.sha1(f"{gid}/{i}".encode()).hexdigest()[:16]


def api_rule(gid: str, i: int, egress: bool, proto: str, fp, tp, peer: str, desc: str) -> dict:
    """One rule in DescribeSecurityGroupRules shape."""
    r = {"GroupId": gid, "SecurityGroupRuleId": rule_id(gid, i), "IsEgress": egress, "IpProtocol": proto,
         "FromPort": -1 if fp is None else fp, "ToPort": -1 if tp is None else tp, "Description": desc}
    if peer.startswith("pl-"):
        r["PrefixListId"] = peer
    elif peer.startswith("sg-"):
        r["ReferencedGroupInfo"] = {"GroupId": peer}
    else:
        r["CidrIpv6" if ":" in peer else "CidrIpv4"] = peer
    return r


def load() -> dict[str, list[SgRule]]:
    """Expanded rules by group as load_groups() returns them, self-references renamed as main() does."""
    entries = {pid: cidrs for pid, (_, cidrs) in PREFIX_LISTS.items()}
    rules = {}
    for g in GROUPS:
        rs = [SgRule.from_api(api_rule(g.group_id, i, *spec)) for i, spec in enumerate(RULES[g.group_id])]
        for r in rs:
            if r.peer_kind == "pl":
                r.peer_label = f"{PREFIX_LISTS[r.peer][0]}, {len(entries[r.peer])} entries"
            r.expand(entries)
            if r.peer == "self":
                r.boxes = [(f"sg:{g.group_id}", b) for _, b in r.boxes]
        rules[g.group_id] = sorted(rs, key=lambda r: (r.egress, r.key()[1], r.peer))
    return rules


def render() -> str:
    rules = load()
    groups = {g.group_id: g for g in GROUPS}
    rename = {f"sg:{OLD}": f"sg:{NEW}"}
    enis = [{"NetworkInterfaceId": eni, "VpcId": VPC, "Groups": [{"GroupId": g} for g in gids], **extra}
            for eni, extra, gids in INTERFACES]
    rows = [mig.review(n, A1, REGION, [OLD], [NEW], groups, rules, rename) for n in enis]
    cgroups = mig.change_groups(rows)
    refs = mig.check_references({gid: [api_rule(gid, 100 + i, *spec) for i, spec in enumerate(rs)]
                                 for gid, rs in REFERENCING.items()}, [OLD], A1, REGION, rename)
    payload = {"generated": GENERATED,
               "accounts": [{"account": A1, "profile": "orders-prod-ro", "profile_source": "--profile"}],
               "old": [OLD], "new": [NEW], "rename": {OLD: NEW}, "groups": [asdict(g) for g in GROUPS],
               "warnings": [], "resources": [asdict(r) for r in rows], "change_groups": cgroups, "references": refs}
    return mig.render_html(payload, rows, cgroups, refs)
