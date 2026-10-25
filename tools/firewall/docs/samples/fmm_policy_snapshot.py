"""Synthetic sample for fmm_policy_snapshot: a diff between two weekly snapshots.

Builds two made-up policy sets (get-policy shaped), applies a handful of edits
to the newer one, and runs them through the tool's own diff_snapshots().
"""
from __future__ import annotations

import copy
import json

import fmm_policy_snapshot as t

SHOTS = [("fmm-policy-snapshot", "dark", 1100)]

OLD, NEW = "2026-10-12_090000", "2026-10-19_090000"
REGIONS = ["us-east-1", "ca-central-1"]
OU = "ou-ab12-cdef3456"


def _policy(pid: str, name: str, ptype: str, msd: dict, **kw) -> dict:
    """An FMS Policy object with the usual defaults."""
    p = {"PolicyId": pid, "PolicyName": name, "PolicyUpdateToken": f"1:{pid[:8]}",
         "SecurityServicePolicyData": {"Type": ptype, "ManagedServiceData": json.dumps({"type": ptype, **msd})},
         "ResourceType": kw.pop("ResourceType", "AWS::EC2::SecurityGroup"),
         "ResourceTags": [], "ExcludeResourceTags": False, "RemediationEnabled": True,
         "DeleteUnusedFMManagedResources": False, "IncludeMap": {"ORGUNIT": [OU]},
         "ExcludeMap": {"ACCOUNT": ["777788889999"]}, "PolicyDescription": "", "PolicyStatus": "ACTIVE"}
    p.update(kw)
    return p


def _nacl(cidr: str) -> dict:
    """networkAclEntrySet with an internal allow first and a deny-all-from-docs-range last."""
    return {"networkAclEntrySet": {
        "firstEntries": [{"egress": False, "protocol": "6", "portRange": {"from": 443, "to": 443},
                          "cidrBlock": cidr, "ruleAction": "allow"},
                         {"egress": True, "protocol": "-1", "cidrBlock": "10.0.0.0/8", "ruleAction": "allow"}],
        "lastEntries": [{"egress": False, "protocol": "-1", "cidrBlock": "203.0.113.0/24", "ruleAction": "deny"}],
        "forceRemediateForFirstEntries": True, "forceRemediateForLastEntries": False}}


def _old(region: str) -> list[dict]:
    """The older snapshot's policies for one region (ids differ per region)."""
    s = "1" if region == "us-east-1" else "2"
    return [
        _policy(f"{s}a2b3c4d-1111-4e5f-8a9b-0c1d2e3f4a5b", "prod-baseline-sg", "SECURITY_GROUPS_COMMON",
                {"revertManualSecurityGroupChanges": True, "exclusiveResourceSecurityGroupManagement": False,
                 "applyToAllEC2InstanceENIs": False,
                 "securityGroups": [{"id": "sg-0a1b2c3d4e5f60718"}]},
                ResourceTypeList=["AWS::EC2::Instance", "AWS::EC2::NetworkInterface"],
                ResourceType="ResourceTypeList", PolicyDescription="Baseline SG for prod workloads"),
        _policy(f"{s}b3c4d5e-2222-4f60-9bac-1d2e3f4a5b6c", "prod-baseline-nacl", "NETWORK_ACL_COMMON",
                _nacl("10.20.0.0/16"), ResourceType="AWS::EC2::Subnet",
                ResourceTags=[{"Key": "tier", "Value": "private"}]),
        _policy(f"{s}c4d5e6f-3333-4071-8cbd-2e3f4a5b6c7d", "sg-content-audit", "SECURITY_GROUPS_CONTENT_AUDIT",
                {"securityGroupAction": {"type": "ALLOW"},
                 "securityGroups": [{"id": "sg-0b2c3d4e5f6071829"}]},
                RemediationEnabled=False),
        _policy(f"{s}d5e6f70-4444-4182-9dce-3f4a5b6c7d8e", "egress-inspection", "NETWORK_FIREWALL",
                {"networkFirewallStatelessDefaultActions": ["aws:forward_to_sfe"],
                 "networkFirewallStatefulRuleGroupReferences": [
                     {"resourceARN": f"arn:aws:network-firewall:{region}:111122223333:stateful-rulegroup/egress-allow"}],
                 "networkFirewallOrchestrationConfig": {"singleFirewallEndpointPerVPC": False}},
                ResourceType="AWS::EC2::VPC"),
        _policy(f"{s}e6f7081-5555-4293-8edf-4a5b6c7d8e9f", "legacy-dmz-sg", "SECURITY_GROUPS_COMMON",
                {"securityGroups": [{"id": "sg-0c3d4e5f607182930"}]}, RemediationEnabled=False),
    ]


def _edit(policies: list[dict], region: str) -> list[dict]:
    """The newer snapshot: the old one plus a week of edits."""
    p = {x["PolicyName"]: x for x in copy.deepcopy(policies)}
    s = "1" if region == "us-east-1" else "2"

    def msd(name: str) -> dict:
        return json.loads(p[name]["SecurityServicePolicyData"]["ManagedServiceData"])

    def set_msd(name: str, d: dict) -> None:
        p[name]["SecurityServicePolicyData"]["ManagedServiceData"] = json.dumps(d)

    for x in p.values():
        x["PolicyUpdateToken"] = x["PolicyUpdateToken"].replace("1:", "2:")   # dropped before diffing
    if region == "us-east-1":
        d = msd("prod-baseline-sg")
        d["securityGroups"][0]["id"] = "sg-0d4e5f60718293a4b"
        d["exclusiveResourceSecurityGroupManagement"] = True
        set_msd("prod-baseline-sg", d)
        p["prod-baseline-sg"]["ExcludeMap"]["ACCOUNT"].append("444455556666")
        p["prod-baseline-sg"]["PolicyDescription"] = "Baseline SG for prod workloads (v2)"
        d = msd("prod-baseline-nacl")
        d["networkAclEntrySet"]["firstEntries"][0]["cidrBlock"] = "10.20.0.0/15"
        d["networkAclEntrySet"]["forceRemediateForLastEntries"] = True
        set_msd("prod-baseline-nacl", d)
        p["prod-baseline-nacl"]["ResourceTags"].append({"Key": "env", "Value": "prod"})
        p["sg-content-audit"]["RemediationEnabled"] = True
        p["sg-content-audit"]["PolicyName"] = "sg-content-audit-v2"
        d = msd("egress-inspection")
        d["networkFirewallOrchestrationConfig"]["singleFirewallEndpointPerVPC"] = True
        d["networkFirewallStatefulRuleGroupReferences"].append(
            {"resourceARN": "arn:aws:network-firewall:us-east-1:111122223333:stateful-rulegroup/egress-deny-tor"})
        set_msd("egress-inspection", d)
        del p["legacy-dmz-sg"]
        p["shared-services-sg"] = _policy(f"{s}f708192-6666-43a4-9f01-5b6c7d8e9fa0", "shared-services-sg",
                                          "SECURITY_GROUPS_COMMON",
                                          {"securityGroups": [{"id": "sg-0e5f60718293a4b5c"}]})
    else:
        p["prod-baseline-nacl"]["IncludeMap"] = {"ORGUNIT": [OU, "ou-ab12-9876fedc"]}
        p["prod-baseline-nacl"]["DeleteUnusedFMManagedResources"] = True
        d = msd("prod-baseline-sg")
        d["revertManualSecurityGroupChanges"] = False
        set_msd("prod-baseline-sg", d)
    return list(p.values())


def _records(label: str) -> list[t.Record]:
    out = []
    for region in REGIONS:
        pols = _old(region) if label == OLD else _edit(_old(region), region)
        out += [t.Record(region=region, policy=pol,
                         arn=f"arn:aws:fms:{region}:111122223333:policy/{pol['PolicyId']}") for pol in pols]
    return out


def render() -> str:
    old, new = _records(OLD), _records(NEW)
    findings = t.sort_findings(t.diff_snapshots(old, new, OLD, NEW))
    compared = len({(r.region, r.policy_id) for r in old} | {(r.region, r.policy_id) for r in new})
    title = f"FMS policy diff: {OLD} -> {NEW}"
    meta = [f"Old: {OLD}", f"New: {NEW}", f"Regions: {', '.join(sorted(REGIONS))}"]
    return t.render_html(findings, title, meta, compared)
