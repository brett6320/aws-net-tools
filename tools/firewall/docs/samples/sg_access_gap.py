"""Synthetic sg_access_gap report: a legacy group checked against two standard groups (one
owned by another account in a shared VPC). Rules are built in DescribeSecurityGroupRules shape,
parsed and expanded as load_groups() does, and run through the tool's own diff_groups()."""
from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import asdict

import sg_access_gap as gap
from lib.security_groups import SG, SgRule

GENERATED = "2026-10-14 10:05:33"
A1, A2 = "111122223333", "444455556666"
VPC = "vpc-0a1b2c3d4e5f60718"
LEGACY, STD, SHARED = "sg-0a3f9c2e71b4d5068", "sg-0b7e1d4a9c3f20581", "sg-0c5d8e2f4a1b70936"
ALB, BASTION = "sg-0fedcba9876543210", "pl-0123456789abcdef0"
PREFIX_LISTS = {BASTION: ("bastion-hosts", ["10.20.255.0/28", "10.21.255.0/28"])}

SHOTS = [("sg-access-gap", "dark", 1100)]

GROUPS = [SG(LEGACY, "legacy-orders-app", VPC, A1, "us-east-1", "orders app (pre-2024 build)"),
          SG(STD, "std-app-ingress", VPC, A1, "us-east-1", "standard application ingress"),
          SG(SHARED, "net-shared-baseline", VPC, A2, "us-east-1", "network team baseline (shared VPC)")]

# group -> [(egress, proto, from, to, peer, description)]; peer: CIDR, pl-, sg- (the group itself = self)
RULES: dict[str, list[tuple]] = {
    LEGACY: [(False, "tcp", 443, 443, "10.0.0.0/8", "HTTPS internal"),
             (False, "tcp", 8080, 8090, "10.20.0.0/16", "app ports"),
             (False, "tcp", 22, 22, BASTION, "SSH from bastions"),
             (False, "tcp", 5432, 5432, ALB, "reporting replica"),
             (False, "icmp", 8, -1, "10.0.0.0/8", "ping"),
             (False, "udp", 161, 161, "192.168.10.0/24", "SNMP polling"),
             (False, "tcp", 80, 80, "198.51.100.0/24", "partner callback (HTTP)"),
             (False, "-1", None, None, LEGACY, "cluster peers"),
             (True, "tcp", 443, 443, "0.0.0.0/0", "HTTPS out"),
             (True, "udp", 53, 53, "10.20.0.2/32", "VPC resolver"),
             (True, "tcp", 9092, 9094, "10.40.0.0/16", "Kafka brokers")],
    STD: [(False, "tcp", 443, 443, "10.0.0.0/9", "HTTPS internal (low)"),
          (False, "tcp", 8080, 8085, "10.20.0.0/16", "app ports"),
          (False, "tcp", 22, 22, "10.20.255.0/28", "SSH from bastion A"),
          (False, "tcp", 22, 22, "10.21.255.0/28", "SSH from bastion B"),
          (False, "-1", None, None, STD, "cluster peers"),
          (True, "tcp", 443, 443, "0.0.0.0/0", "HTTPS out")],
    SHARED: [(False, "tcp", 443, 443, "10.128.0.0/9", "HTTPS internal (high)"),
             (False, "icmp", 8, -1, "10.0.0.0/8", "ping"),
             (False, "udp", 161, 161, "192.168.10.0/25", "SNMP polling"),
             (True, "udp", 53, 53, "10.20.0.0/24", "DNS"),
             (True, "tcp", 5432, 5432, "10.40.8.0/22", "warehouse")],
}


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
    """Expanded rules by group, as lib.security_groups.load_groups would return them."""
    entries = {pid: cidrs for pid, (_, cidrs) in PREFIX_LISTS.items()}
    rules = {}
    for g in GROUPS:
        rs = [SgRule.from_api(api_rule(g.group_id, i, *spec)) for i, spec in enumerate(RULES[g.group_id])]
        for r in rs:
            if r.peer_kind == "pl":
                r.peer_label = f"{PREFIX_LISTS[r.peer][0]}, {len(entries[r.peer])} entries"
            r.expand(entries)
        rules[g.group_id] = sorted(rs, key=lambda r: (r.egress, r.key()[1], r.peer))
    return rules


def render() -> str:
    groups, rules = GROUPS, load()
    findings, summary = gap.diff_groups(groups, rules)
    findings.insert(0, gap.Finding("info", "DIFFERENT_ACCOUNTS",          # as main() adds it
                                   detail="groups are in 2 accounts; group references are matched by group id"))
    by_code = defaultdict(int)
    for f in findings:
        by_code[f.code] += 1
    payload = {"account": f"{A1}, {A2}",
               "accounts": [{"account": A1, "profile": "orders-prod-ro", "profile_source": "--profile"},
                            {"account": A2, "profile": "network-ro", "profile_source": f"local profile for account {A2}"}],
               "groups": [asdict(g) for g in groups], "summary": summary, "stats": dict(by_code),
               "rules": {g.group_id: [{**{k: v for k, v in asdict(r).items() if k != "boxes"}, "rule": str(r)}
                                      for r in rules[g.group_id]] for g in groups},
               "findings": [asdict(f) for f in findings]}
    return gap.render_html(payload, GENERATED)
