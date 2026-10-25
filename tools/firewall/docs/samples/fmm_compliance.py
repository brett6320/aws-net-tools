"""Synthetic sample for fmm_compliance: seven FMS policies over five member accounts.

A small in-memory stand-in for the FMS client (get_policy, list_compliance_status,
get_compliance_detail) serves made-up responses to the tool's own policy_info()
and scan_policy(); the stats mirror run().
"""
from __future__ import annotations

import datetime as dt
import re
from collections import defaultdict

from botocore.exceptions import ClientError

import fmm_compliance as t
from lib.output import SEVERITY_ORDER

SHOTS = [("fmm-compliance", "dark", 1100)]

GENERATED = "2026-10-19 09:20:41"
UPDATED = dt.datetime(2026, 10, 19, 8, 47, 13)
REGIONS = ["us-east-1", "ca-central-1"]
NAMES = {"111122223333": "prod-core", "222233334444": "data-platform", "444455556666": "shared-services",
         "555566667777": "log-archive", "777788889999": "dev-sandbox"}


def _pol(pid: str, name: str, ptype: str, rtype: str, *, remediation: bool = True, exclude: bool = False) -> dict:
    """(ListPolicies summary, get_policy Policy) for one policy."""
    summary = {"PolicyId": pid, "PolicyName": name, "SecurityServiceType": ptype, "ResourceType": rtype,
               "RemediationEnabled": remediation, "DeleteUnusedFMManagedResources": False}
    policy = {"PolicyId": pid, "PolicyName": name, "ResourceType": rtype, "RemediationEnabled": remediation,
              "SecurityServicePolicyData": {"Type": ptype}, "IncludeMap": {"ORGUNIT": ["ou-ab12-cdef3456"]},
              "ExcludeMap": {"ACCOUNT": ["555566667777"]} if exclude else {}}
    return {"summary": summary, "policy": policy}


def _v(rtype: str, rid: str, reason: str, **md) -> dict:
    return {"ResourceType": rtype, "ResourceId": rid, "ViolationReason": reason, "Metadata": md}


SG, ENI, EC2, SUBNET, VPC = ("AWS::EC2::SecurityGroup", "AWS::EC2::NetworkInterface", "AWS::EC2::Instance",
                             "AWS::EC2::Subnet", "AWS::EC2::VPC")
ALB = "AWS::ElasticLoadBalancingV2::LoadBalancer"
DENIED = ClientError({"Error": {"Code": "AccessDeniedException",
                                "Message": "member account 222233334444 is not accessible"}}, "GetComplianceDetail")

# region -> [(policy, {account: (evaluations, detail | ClientError | None, IssueInfoMap)})]
DATA = {
    "us-east-1": [
        (_pol("1a2b3c4d-1111-4e5f-8a9b-0c1d2e3f4a5b", "prod-baseline-sg", "SECURITY_GROUPS_COMMON", "ResourceTypeList"), {
            "111122223333": ([("NON_COMPLIANT", 3)], [
                _v(EC2, "i-0a1b2c3d4e5f60718", "RESOURCE_MISSING_SECURITY_GROUP", SecurityGroupId="sg-0a1b2c3d4e5f60718"),
                _v(EC2, "i-0a1b2c3d4e5f60719", "RESOURCE_MISSING_SECURITY_GROUP", SecurityGroupId="sg-0a1b2c3d4e5f60718"),
                _v(ENI, "eni-0f1e2d3c4b5a69788", "RESOURCE_MISSING_SECURITY_GROUP", SecurityGroupId="sg-0a1b2c3d4e5f60718")],
                {}),
            "222233334444": ([("NON_COMPLIANT", 1)], DENIED, {}),
            "444455556666": ([("COMPLIANT", 0)], None, {}),
            "777788889999": ([("NON_COMPLIANT", 2)], [
                _v(SG, "sg-0c3d4e5f607182930", "SECURITY_GROUP_REDUNDANT", RedundantTo="sg-0a1b2c3d4e5f60718"),
                _v(EC2, "i-0c3d4e5f607182931", "RESOURCE_MISSING_SECURITY_GROUP", SecurityGroupId="sg-0a1b2c3d4e5f60718")],
                {}),
        }),
        (_pol("2b3c4d5e-2222-4f60-9bac-1d2e3f4a5b6c", "sg-content-audit", "SECURITY_GROUPS_CONTENT_AUDIT", SG,
              remediation=False), {
            "111122223333": ([("NON_COMPLIANT", 2)], [
                _v(SG, "sg-0d4e5f60718293a4b", "RESOURCE_VIOLATES_AUDIT_SECURITY_GROUP",
                   Rule="ingress tcp 22 0.0.0.0/0"),
                _v(SG, "sg-0d4e5f60718293a4c", "RESOURCE_VIOLATES_AUDIT_SECURITY_GROUP",
                   Rule="ingress tcp 3389 203.0.113.0/24")], {}),
            "444455556666": ([("NON_COMPLIANT", 1)], [
                _v(SG, "sg-0e5f60718293a4b5c", "RESOURCE_VIOLATES_AUDIT_SECURITY_GROUP", Rule="ingress -1 0.0.0.0/0")],
                {}),
            "777788889999": ([("COMPLIANT", 0)], None, {}),
        }),
        (_pol("3c4d5e6f-3333-4071-8cbd-2e3f4a5b6c7d", "prod-baseline-nacl", "NETWORK_ACL_COMMON", SUBNET), {
            "111122223333": ([("NON_COMPLIANT", 2)], [
                _v(SUBNET, "subnet-0aa11bb22cc33dd44", "INVALID_NETWORK_ACL_ENTRY", NetworkAclId="acl-0123456789abcdef1"),
                _v(SUBNET, "subnet-0aa11bb22cc33dd46", "INVALID_NETWORK_ACL_ENTRY", NetworkAclId="acl-0123456789abcdef2")],
                {}),
            "444455556666": ([("NON_COMPLIANT", 4)], {"Violators": [],
                                                      "ExpiredAt": dt.datetime(2026, 10, 18, 22, 0, 0)}, {}),
            "777788889999": ([("COMPLIANT", 0)], None, {}),
        }),
        (_pol("4d5e6f70-4444-4182-9dce-3f4a5b6c7d8e", "egress-inspection", "NETWORK_FIREWALL", VPC, exclude=True), {
            "111122223333": ([("NON_COMPLIANT", 2)], [
                _v(VPC, "vpc-0a1b2c3d4e5f60718", "MISSING_EXPECTED_ROUTE_TABLE", RouteTableId="rtb-0a1b2c3d4e5f60718"),
                _v(VPC, "vpc-0b2c3d4e5f6071829", "MISSING_FIREWALL_SUBNET_IN_AZ", AvailabilityZone="us-east-1c")], {}),
            "222233334444": ([("COMPLIANT", 0)], None, {}),
            "444455556666": ([("UNKNOWN", 0)], None,
                             {"AWSCONFIG": "AWS Config is not enabled in this account and region"}),
        }),
        (_pol("5e6f7081-5555-4293-8edf-4a5b6c7d8e9f", "waf-edge", "WAFV2", ALB), {
            "111122223333": ([("NON_COMPLIANT", 1)], [
                _v(ALB, "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/web-prod/0a1b2c3d4e5f6071",
                   "RESOURCE_MISSING_WEB_ACL")], {}),
            "444455556666": ([("COMPLIANT", 0)], None, {}),
            "777788889999": ([("COMPLIANT", 0)], None, {}),
        }),
    ],
    "ca-central-1": [
        (_pol("6f708192-6666-43a4-9f01-5b6c7d8e9fa0", "prod-baseline-sg", "SECURITY_GROUPS_COMMON", "ResourceTypeList"), {
            "111122223333": ([("NON_COMPLIANT", 1)], [
                _v(ENI, "eni-0a9b8c7d6e5f40312", "RESOURCE_MISSING_SECURITY_GROUP",
                   SecurityGroupId="sg-0f60718293a4b5c6d")], {}),
            "444455556666": ([("COMPLIANT", 0)], None, {}),
        }),
        (_pol("708192a3-7777-44b5-8012-6c7d8e9fa0b1", "dev-baseline-nacl", "NETWORK_ACL_COMMON", SUBNET), {
            "444455556666": ([("COMPLIANT", 0)], None, {}),
            "777788889999": ([("NON_COMPLIANT", 2, True)], [
                _v(SUBNET, "subnet-0ee55ff66aa77bb88", "INVALID_NETWORK_ACL_ENTRY", NetworkAclId="acl-0e2f3a4b5c6d7e8f9"),
                _v(SUBNET, "subnet-0ee55ff66aa77bb89", "INVALID_NETWORK_ACL_ENTRY", NetworkAclId="acl-0e2f3a4b5c6d7e8fa")],
                {"AWSVPC": "Subnet limit reached evaluating vpc-0e5f60718293a4b5c"}),
        }),
    ],
}


class _Pages:
    def __init__(self, pages: list[dict]):
        self.pages = pages

    def paginate(self, **_):
        return iter(self.pages)


class _Fms:
    """Just enough of the FMS client for policy_info() and scan_policy()."""
    def __init__(self, region: str):
        self.policies = {p["summary"]["PolicyId"]: (p, accts) for p, accts in DATA[region]}

    def get_policy(self, PolicyId: str) -> dict:
        return {"Policy": self.policies[PolicyId][0]["policy"]}

    def get_paginator(self, op: str) -> _Pages:
        assert op == "list_compliance_status"
        return _ComplianceStatus(self)

    def get_compliance_detail(self, PolicyId: str, MemberAccount: str) -> dict:
        evals, detail, issues = self.policies[PolicyId][1][MemberAccount]
        if isinstance(detail, ClientError):
            raise detail
        if isinstance(detail, list):
            detail = {"Violators": detail}
        detail = dict(detail or {"Violators": []})
        detail.update(PolicyId=PolicyId, MemberAccount=MemberAccount, IssueInfoMap=issues,
                      EvaluationLimitExceeded=any(len(e) > 2 and e[2] for e in evals))
        return {"PolicyComplianceDetail": detail}


class _ComplianceStatus(_Pages):
    def __init__(self, fms: _Fms):
        self.fms = fms

    def paginate(self, PolicyId: str, **_):
        entries = []
        for account, (evals, _detail, issues) in self.fms.policies[PolicyId][1].items():
            entries.append({"PolicyId": PolicyId, "MemberAccount": account, "LastUpdated": UPDATED,
                            "IssueInfoMap": issues,
                            "EvaluationResults": [{"ComplianceStatus": e[0], "ViolatorCount": e[1],
                                                   "EvaluationLimitExceeded": len(e) > 2 and e[2]} for e in evals]})
        return iter([{"PolicyComplianceStatusList": entries}])


def render() -> str:
    policies, rows, findings = [], [], []
    for region in REGIONS:
        fms = _Fms(region)
        for s in sorted((p["summary"] for p, _ in DATA[region]), key=lambda x: x["PolicyName"]):
            info = t.policy_info(fms, region, s, findings)
            t.scan_policy(fms, info, set(), NAMES, False, rows, findings)
            policies.append(info)
    findings.sort(key=lambda f: (f.region, f.policy_name, f.account, SEVERITY_ORDER[f.severity], f.code,
                                 f.reason, f.resource_type, f.resource_id))
    by_code: dict[str, int] = defaultdict(int)
    for f in findings:
        by_code[f.code] += 1
    stats = {"regions": len(REGIONS), "policies": len(policies), "account_rows": len(rows),
             "accounts": len({r.account for r in rows}),
             "non_compliant_accounts": len({r.account for r in rows if r.status == "NON_COMPLIANT"}),
             "violations": by_code.get("VIOLATION", 0), "by_code": dict(by_code)}
    html = t.render_html(policies, rows, findings, stats, REGIONS)
    return re.sub(r"generated \d{4}-\d\d-\d\d \d\d:\d\d:\d\d", f"generated {GENERATED}", html)
