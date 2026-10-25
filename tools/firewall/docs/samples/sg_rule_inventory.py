"""Synthetic sg_rule_inventory report: made-up groups and rules in DescribeSecurityGroupRules
shape, parsed and expanded as load_groups() does, then run through the tool's own analysis
(rule_rows, combined_access, interface_deltas, tester_data) and render_html()."""
from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import asdict

import sg_rule_inventory as inv
from lib.security_groups import SG, SgRule

GENERATED = "2026-10-14 09:42:17"
A1, A2 = "111122223333", "444455556666"
VPC1, VPC2 = "vpc-0a1b2c3d4e5f60718", "vpc-0f9e8d7c6b5a40312"
WEB, APP, DBC = "sg-0a3f9c2e71b4d5068", "sg-0b7e1d4a9c3f20581", "sg-0c5d8e2f4a1b70936"
PIPE, MON = "sg-0d2a6b9e3f7c14805", "sg-0e8f4c1a7d2b59360"
ALB, DB = "sg-0fedcba9876543210", "sg-01234abcd5678ef90"
VPN, BASTION, S3 = "pl-0123456789abcdef0", "pl-0a1b2c3d4e5f60789", "pl-0fedcba9876543210"

PREFIX_LISTS = {VPN: ("corp-vpn", ["10.100.0.0/16", "10.101.0.0/16", "192.168.50.0/24"]),
                BASTION: ("bastion-hosts", ["10.20.255.0/28", "10.21.255.0/28"]),
                S3: ("s3-gateway", ["198.51.100.0/24", "203.0.113.0/24"])}

GROUPS = [SG(WEB, "web-tier", VPC1, A1, "us-east-1", "HTTPS from the ALB and corporate VPN"),
          SG(APP, "app-baseline", VPC1, A1, "us-east-1", "Baseline for application hosts"),
          SG(DBC, "db-clients", VPC1, A1, "us-east-1", "Members may reach the orders database"),
          SG(PIPE, "data-pipeline", VPC2, A2, "us-east-1", "Batch workers"),
          SG(MON, "shared-monitoring", VPC2, A2, "us-east-1", "Prometheus / SNMP scraping")]

# group -> [(egress, proto, from, to, peer, description)]; peer: CIDR, pl-, sg- (or the group itself)
RULES: dict[str, list[tuple]] = {
    WEB: [(False, "tcp", 443, 443, ALB, "HTTPS from public ALB"),
          (False, "tcp", 443, 443, VPN, "HTTPS from corporate VPN"),
          (False, "tcp", 8080, 8080, "10.20.0.0/16", "health checks"),
          (True, "tcp", 443, 443, "0.0.0.0/0", "HTTPS out"),
          (True, "tcp", 8080, 8080, "10.20.0.0/16", "service mesh")],
    APP: [(False, "tcp", 22, 22, BASTION, "SSH from bastions"),
          (False, "icmp", 8, -1, "10.0.0.0/8", "ping"),
          (False, "tcp", 8080, 8080, "10.20.0.0/17", "legacy health checks"),
          (False, "tcp", 9100, 9100, "10.50.0.0/24", "node exporter"),
          (True, "tcp", 443, 443, "0.0.0.0/0", "HTTPS out"),
          (True, "udp", 53, 53, "10.20.0.2/32", "VPC resolver")],
    DBC: [(False, "-1", None, None, DBC, "cluster peers"),
          (True, "tcp", 5432, 5432, DB, "orders database")],
    PIPE: [(False, "tcp", 8443, 8443, "10.40.0.0/20", "job API"),
           (True, "tcp", 443, 443, S3, "S3 via gateway endpoint"),
           (True, "tcp", 5432, 5432, "10.40.8.0/22", "warehouse"),
           (True, "tcp", 443, 443, "0.0.0.0/0", "HTTPS out")],
    MON: [(False, "tcp", 9100, 9100, "10.50.0.0/24", "node exporter"),
          (False, "udp", 161, 161, "10.50.0.0/24", "SNMP"),
          (False, "icmpv6", -1, -1, "2001:db8:50::/48", "ICMPv6 from monitoring"),
          (True, "udp", 514, 514, "10.50.0.10/32", "syslog")],
}

INTERFACES = [
    {"id": "eni-0123456789abcdef0", "kind": "eni", "region": "us-east-1", "attachment": "i-0abc123def4567890",
     "vpc_id": VPC1, "description": "orders-api-1", "groups": [WEB, APP, DBC], "account": A1},
    {"id": "eni-0fedcba9876543210", "kind": "instance", "region": "us-east-1", "attachment": "i-0def456abc7890123 eth0",
     "vpc_id": VPC1, "description": "orders-api-2", "groups": [WEB, APP], "account": A1},
]
TARGET_WARNINGS = ["Lambda nightly-report: not attached to a VPC, so no security groups apply; skipped"]

# tester shot: run a few tests with app-baseline switched off ("what if it were removed?")
_TESTS = "\\n".join(["ingress 10.100.4.20 tcp 443", "ingress 10.20.255.5 tcp 22", "ingress 10.50.0.0/24 tcp",
                     "egress 203.0.113.10 tcp 443", "egress sg-01234abcd5678ef90 tcp 5432"])
_TESTER_JS = ("const s=document.getElementById('tester'),l=s.querySelector('[data-t=lines]');"
              f"s.querySelector('input[data-g={APP}]').checked=false;"
              "s.querySelector('[data-t=sname]').value='orders-api without app-baseline';"
              "s.querySelector('[data-t=snotes]').value='CHG-2041: confirm what removing app-baseline breaks';"
              f"l.value='{_TESTS}';l.dispatchEvent(new Event('input'))")
# overview shots: the tester sits above the tables; move it below them so the tables show
_OVERVIEW_JS = "document.getElementById('app').appendChild(document.getElementById('tester'))"
SHOTS = [("sg-rule-inventory", "dark", 1100, _OVERVIEW_JS),
         ("sg-rule-inventory-tester", "dark", 1100, _TESTER_JS),
         ("sg-rule-inventory-light", "light", 1100, _OVERVIEW_JS)]


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


def load() -> tuple[list[SG], dict[str, list[SgRule]]]:
    """Groups and expanded rules, as lib.security_groups.load_groups would return them."""
    entries = {pid: cidrs for pid, (_, cidrs) in PREFIX_LISTS.items()}
    rules = {}
    for g in GROUPS:
        rs = [SgRule.from_api(api_rule(g.group_id, i, *spec)) for i, spec in enumerate(RULES[g.group_id])]
        for r in rs:
            if r.peer_kind == "pl":
                r.peer_label = f"{PREFIX_LISTS[r.peer][0]}, {len(entries[r.peer])} entries"
            r.expand(entries)
        rules[g.group_id] = sorted(rs, key=lambda r: (r.egress, r.key()[1], r.peer))
    return GROUPS, rules


def render() -> str:
    groups, rules = load()
    inv.fix_self_refs(rules)
    pls = inv.known_prefix_lists(rules)
    rows = inv.rule_rows(groups, rules)
    combined = inv.combined_access(groups, rules)
    via = defaultdict(list)
    for n in INTERFACES:
        for gid in n["groups"]:
            via[gid].append(n["id"])
    payload = {"account": f"{A1}, {A2}",
               "accounts": [{"account": A1, "profile": "orders-prod-ro", "profile_source": "--profile"},
                            {"account": A2, "profile": "data-prod-ro", "profile_source": f"local profile for account {A2}"}],
               "profile": None, "profile_source": "", "generated": GENERATED,
               "interfaces": INTERFACES, "warnings": [], "target_warnings": TARGET_WARNINGS,
               "groups": [{**asdict(g), "via": via.get(g.group_id, [])} for g in groups],
               "rules": [asdict(r) for r in rows], "combined_access": combined,
               "interface_deltas": inv.interface_deltas(INTERFACES, rules)}
    tester_text, payload["rule_data_sha256"] = inv.tester_data(payload, groups, rules, pls)
    return inv.render_html(payload, rows, combined, tester_text)
