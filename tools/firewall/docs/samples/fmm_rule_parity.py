"""Synthetic sample for fmm_rule_parity: moving access from an old load balancer IP
(10.50.0.10) to a new subnet or prefix list, across SG, Network Firewall and NACL policies.

Made-up policies, security groups, rule groups and prefix lists go through the tool's
own Extractor (its lookup caches are pre-filled, so it never calls AWS), analyze()
and build_container_report().
"""
from __future__ import annotations

import ipaddress
import json
import re

import fmm_rule_parity as t

SHOTS = [("fmm-rule-parity", "dark", 1100)]

GENERATED = "2026-10-19 10:02:37"
REGIONS = ["us-east-1", "ca-central-1"]
PL = "pl-0a1b2c3d4e5f6a7b8"           # new-app-lb prefix list
PL_CIDRS = ["10.60.0.0/24", "10.60.1.0/24"]
ACCT = "111122223333"


def _perm(proto: str, port: int | tuple[int, int] | None, cidrs=(), pls=(), groups=()) -> dict:
    """One IpPermission in describe_security_groups shape."""
    p = {"IpProtocol": proto, "IpRanges": [{"CidrIp": c} for c in cidrs],
         "PrefixListIds": [{"PrefixListId": x} for x in pls], "UserIdGroupPairs": [{"GroupId": g} for g in groups]}
    if port is not None:
        lo, hi = (port, port) if isinstance(port, int) else port
        p.update(FromPort=lo, ToPort=hi)
    return p


def _sg(sg_id: str, name: str, ingress: list[dict], egress: list[dict] | None = None) -> dict:
    return {"GroupId": sg_id, "GroupName": name, "IpPermissions": ingress,
            "IpPermissionsEgress": egress or [_perm("-1", None, ["0.0.0.0/0"])]}


SGS = {
    # us-east-1
    "sg-0a1b2c3d4e5f60718": _sg("sg-0a1b2c3d4e5f60718", "prod-web-baseline",
                                [_perm("tcp", 8443, ["10.50.0.10/32"]), _perm("tcp", 8443, pls=[PL]),
                                 _perm("tcp", 443, ["10.0.0.0/8"])]),
    "sg-0b2c3d4e5f6071829": _sg("sg-0b2c3d4e5f6071829", "prod-api-baseline",
                                [_perm("tcp", 8443, ["10.50.0.10/32"]), _perm("tcp", 22, ["10.10.0.0/16"])]),
    "sg-0c3d4e5f607182930": _sg("sg-0c3d4e5f607182930", "prod-batch-baseline",
                                [_perm("tcp", (8000, 8999), ["10.50.0.0/16"]), _perm("tcp", (8000, 8999), ["10.60.0.0/16"])]),
    "sg-0d4e5f60718293a4b": _sg("sg-0d4e5f60718293a4b", "prod-admin-baseline",
                                [_perm("tcp", 22, ["10.10.0.0/16"]), _perm("tcp", 3389, ["10.10.0.0/16"])]),
    "sg-0e5f60718293a4b5c": _sg("sg-0e5f60718293a4b5c", "shared-services-ingress",
                                [_perm("tcp", 8443, ["10.50.0.10/32", "10.50.0.11/32"]),
                                 _perm("tcp", 8443, groups=["sg-0123456789abcdef0"])],
                                [_perm("tcp", 8443, ["10.50.0.10/32"]), _perm("tcp", 8443, ["10.60.0.0/24"])]),
    # ca-central-1
    "sg-0f60718293a4b5c6d": _sg("sg-0f60718293a4b5c6d", "prod-web-baseline",
                                [_perm("tcp", 8443, ["10.50.0.10/32"]), _perm("tcp", 443, ["10.0.0.0/8"])]),
    "sg-0718293a4b5c6d7e8": _sg("sg-0718293a4b5c6d7e8", "prod-api-baseline",
                                [_perm("tcp", 8443, ["10.50.0.10/32"]), _perm("tcp", 8443, ["10.60.0.0/24"])]),
    "sg-08293a4b5c6d7e8f9": _sg("sg-08293a4b5c6d7e8f9", "dev-open-baseline",
                                [_perm("-1", None, ["10.0.0.0/8"]), _perm("udp", 53, ["10.0.0.0/8"])]),
}


def _arn(region: str, kind: str, name: str) -> str:
    return f"arn:aws:network-firewall:{region}:{ACCT}:{kind}-rulegroup/{name}"


def _rule_groups(region: str) -> dict:
    """describe_rule_group responses for one region's egress-inspection policy."""
    stateful = {
        "RuleGroup": {
            "RuleVariables": {"IPSets": {"OLD_APP_LB": {"Definition": ["10.50.0.10/32"]},
                                         "APP_SUBNETS": {"Definition": ["10.20.0.0/16", "10.21.0.0/16"]}},
                              "PortSets": {"APP_PORTS": {"Definition": ["8443", "9443"]}}},
            "ReferenceSets": {"IPSetReferences": {"NEW_APP_LB": {
                "ReferenceArn": f"arn:aws:ec2:{region}:{ACCT}:prefix-list/{PL}"}}},
            "RulesSource": {"RulesString": "\n".join([
                "# app tier to load balancers",
                'pass tcp $APP_SUBNETS any -> $OLD_APP_LB $APP_PORTS (msg:"app to old lb"; sid:1001; rev:3;)',
                *(['pass tcp $APP_SUBNETS any -> $NEW_APP_LB $APP_PORTS (msg:"app to new lb"; sid:1002; rev:1;)']
                  if region == "us-east-1" else []),
                'pass tcp $APP_SUBNETS any -> 10.50.0.10 443 (msg:"health checks"; sid:1003; rev:1;)',
                'drop tcp any any -> any 23 (msg:"no telnet"; sid:1900; rev:1;)',
            ])},
        },
        "RuleGroupResponse": {"RuleGroupName": "egress-allow-apps", "Type": "STATEFUL"},
    }
    five_tuple = {
        "RuleGroup": {"RulesSource": {"StatefulRules": [
            {"Action": "PASS", "Header": {"Protocol": "TCP", "Source": "10.30.0.0/16", "SourcePort": "ANY",
                                          "Direction": "FORWARD", "Destination": "10.50.0.10/32",
                                          "DestinationPort": "8443"}, "RuleOptions": [{"Keyword": "sid", "Settings": ["2001"]}]},
            {"Action": "PASS", "Header": {"Protocol": "TCP", "Source": "10.30.0.0/16", "SourcePort": "ANY",
                                          "Direction": "FORWARD", "Destination": "10.60.0.0/24",
                                          "DestinationPort": "8443"}, "RuleOptions": [{"Keyword": "sid", "Settings": ["2002"]}]},
        ]}},
        "RuleGroupResponse": {"RuleGroupName": "egress-allow-batch", "Type": "STATEFUL"},
    }
    stateless = {
        "RuleGroup": {"RulesSource": {"StatelessRulesAndCustomActions": {"StatelessRules": [
            {"Priority": 10, "RuleDefinition": {"Actions": ["aws:pass"], "MatchAttributes": {
                "Sources": [{"AddressDefinition": "10.40.0.0/16"}],
                "Destinations": [{"AddressDefinition": "10.50.0.10/32"}],
                "DestinationPorts": [{"FromPort": 8443, "ToPort": 8443}], "Protocols": [6]}}},
            {"Priority": 100, "RuleDefinition": {"Actions": ["aws:forward_to_sfe"], "MatchAttributes": {}}},
        ]}}},
        "RuleGroupResponse": {"RuleGroupName": "fast-path", "Type": "STATELESS"},
    }
    return {_arn(region, "stateful", "egress-allow-apps"): stateful,
            _arn(region, "stateful", "egress-allow-batch"): five_tuple,
            _arn(region, "stateless", "fast-path"): stateless}


def _policy(pid: str, name: str, ptype: str, msd: dict) -> dict:
    return {"PolicyId": pid, "PolicyName": name,
            "SecurityServicePolicyData": {"Type": ptype, "ManagedServiceData": json.dumps({"type": ptype, **msd})}}


def _nacl(cidr: str, port: int, egress: bool = False, action: str = "allow") -> dict:
    return {"egress": egress, "protocol": "6", "portRange": {"from": port, "to": port}, "cidrBlock": cidr,
            "ruleAction": action}


def _policies(region: str) -> list[dict]:
    if region == "us-east-1":
        sgs = ["sg-0a1b2c3d4e5f60718", "sg-0b2c3d4e5f6071829", "sg-0c3d4e5f607182930", "sg-0d4e5f60718293a4b"]
        nacl_first = [_nacl("10.50.0.10/32", 8443), _nacl("10.60.0.0/24", 8443), _nacl("10.0.0.0/8", 443)]
        out = [_policy("1a2b3c4d-1111-4e5f-8a9b-0c1d2e3f4a5b", "prod-baseline-sg", "SECURITY_GROUPS_COMMON",
                       {"securityGroups": [{"id": s} for s in sgs]}),
               _policy("2b3c4d5e-2222-4f60-9bac-1d2e3f4a5b6c", "shared-services-sg", "SECURITY_GROUPS_COMMON",
                       {"securityGroups": [{"id": "sg-0e5f60718293a4b5c"}]})]
    else:
        sgs = ["sg-0f60718293a4b5c6d", "sg-0718293a4b5c6d7e8", "sg-08293a4b5c6d7e8f9"]
        nacl_first = [_nacl("10.50.0.10/32", 8443), _nacl("10.0.0.0/8", 443)]
        out = [_policy("6f708192-6666-43a4-9f01-5b6c7d8e9fa0", "prod-baseline-sg", "SECURITY_GROUPS_COMMON",
                       {"securityGroups": [{"id": s} for s in sgs]})]
    rgs = list(_rule_groups(region))
    pfx = "3c4d5e6f-3333-4071" if region == "us-east-1" else "708192a3-7777-44b5"
    out += [
        _policy(f"{pfx}-8cbd-2e3f4a5b6c7d", "prod-baseline-nacl", "NETWORK_ACL_COMMON",
                {"networkAclEntrySet": {"firstEntries": nacl_first,
                                        "lastEntries": [_nacl("203.0.113.0/24", 8443, action="deny")],
                                        "forceRemediateForFirstEntries": True,
                                        "forceRemediateForLastEntries": False}}),
        _policy(f"{pfx}-9dce-3f4a5b6c7d8e", "egress-inspection", "NETWORK_FIREWALL",
                {"networkFirewallStatelessRuleGroupReferences": [{"resourceARN": rgs[2], "priority": 1}],
                 "networkFirewallStatefulRuleGroupReferences": [{"resourceARN": a} for a in rgs[:2]],
                 "networkFirewallStatelessDefaultActions": ["aws:forward_to_sfe"]}),
    ]
    return out


def _extractor(region: str) -> t.Extractor:
    """An Extractor whose SG / rule group / prefix list caches already hold the sample data."""
    ex = object.__new__(t.Extractor)
    ex.session, ex.region, ex.fms, ex._ec2, ex._nfw = None, region, None, None, None
    ex._sg_cache = dict(SGS)
    ex._rg_cache = _rule_groups(region)
    ex._pl_cache = {PL: [ipaddress.ip_network(c) for c in PL_CIDRS]}
    return ex


def render() -> str:
    rules: list[t.Rule] = []
    for region in REGIONS:
        ex = _extractor(region)
        for pol in _policies(region):
            rules.extend(ex.rules_for_policy(pol))
    A = t.parse_targets("A", [["10.50.0.10", "tcp", "8443"]], "any", None, "ref")
    B = t.parse_targets("B", [["10.60.0.0/24", "tcp", "8443"], [PL, "tcp", "8443"]], "any", None, "ref")
    findings, stats = t.analyze(rules, A, B, "container")
    report = t.build_container_report(rules, findings, A, B)
    html = t.render_html(rules, findings, stats, A, B, "container", REGIONS, report)
    return re.sub(r"generated \d{4}-\d\d-\d\d \d\d:\d\d:\d\d", f"generated {GENERATED}", html)
