import datetime as dt
import json
from types import SimpleNamespace

import pytest
from botocore.exceptions import ClientError

from conftest import load_tool, run_main

fc = load_tool("fmm_compliance")


def err(code="AccessDeniedException"):
    return ClientError({"Error": {"Code": code, "Message": "denied"}}, "op")


class FakeFms:
    """Firewall Manager double: policies, compliance status per policy, details per (policy, account)."""
    def __init__(self, summaries, policies=None, status=None, details=None, fail=()):
        self.summaries, self.policies = summaries, policies or {}
        self.status, self.details, self.fail = status or {}, details or {}, set(fail)

    def get_paginator(self, op):
        if op == "list_policies":
            def pages():
                if "list_policies" in self.fail:
                    raise err()
                return [{"PolicyList": self.summaries}]
        else:
            def pages(PolicyId):
                if ("list_compliance_status", PolicyId) in self.fail:
                    raise err()
                return [{"PolicyComplianceStatusList": self.status.get(PolicyId, [])}]
        return SimpleNamespace(paginate=pages)

    def get_policy(self, PolicyId):
        if ("get_policy", PolicyId) in self.fail:
            raise err("ResourceNotFoundException")
        return {"Policy": self.policies[PolicyId]}

    def get_compliance_detail(self, PolicyId, MemberAccount):
        if ("detail", MemberAccount) in self.fail:
            raise err()
        return {"PolicyComplianceDetail": self.details[(PolicyId, MemberAccount)]}


def test_helpers():
    assert fc._ts(None) == "" and fc._ts(dt.datetime(2026, 1, 2, 3, 4, 5)) == "2026-01-02 03:04:05"
    assert fc._ts("2026") == "2026"
    assert fc._metadata({"b": 2, "a": 1}) == "a=1; b=2" and fc._metadata(None) == ""


@pytest.mark.parametrize("results,expected", [
    ([{"ComplianceStatus": "COMPLIANT", "ViolatorCount": 0}], ("COMPLIANT", 0, False)),
    ([{"ComplianceStatus": "COMPLIANT"}, {"ComplianceStatus": "NON_COMPLIANT", "ViolatorCount": 3,
                                          "EvaluationLimitExceeded": True}], ("NON_COMPLIANT", 3, True)),
    ([], ("UNKNOWN", 0, False)),
    ([{"ComplianceStatus": "COMPLIANT"}, {"ComplianceStatus": None}], ("UNKNOWN", 0, False)),
])
def test_account_status(results, expected):
    assert fc.account_status({"EvaluationResults": results}) == expected


def test_policy_info():
    summary = {"PolicyId": "p1", "PolicyName": "sg", "SecurityServiceType": "SECURITY_GROUPS_COMMON",
               "ResourceType": "AWS::EC2::SecurityGroup", "RemediationEnabled": False}
    fms = FakeFms([], {"p1": {"ResourceType": "AWS::EC2::Instance", "ResourceTypeList": ["AWS::EC2::NetworkInterface"],
                              "RemediationEnabled": True, "IncludeMap": {"ACCOUNT": ["1"]}, "ExcludeMap": None}})
    findings = []
    info = fc.policy_info(fms, "us-east-1", summary, findings)
    assert info.resource_types == ["AWS::EC2::Instance", "AWS::EC2::NetworkInterface"]
    assert (info.remediation_enabled, info.include_map, info.exclude_map) == (True, True, False)
    fms.fail.add(("get_policy", "p1"))
    info = fc.policy_info(fms, "us-east-1", summary, findings)
    assert info.resource_types == ["AWS::EC2::SecurityGroup"] and info.remediation_enabled is False
    assert [f.code for f in findings] == ["FMS_ERROR"] and "settings from policy summary only" in findings[0].detail


def make_fms():
    summaries = [{"PolicyId": "p1", "PolicyName": "sg-baseline", "SecurityServiceType": "SECURITY_GROUPS_COMMON"},
                 {"PolicyId": "p2", "PolicyName": "nacl", "SecurityServiceType": "NETWORK_ACL_COMMON"}]
    status = {"p1": [
        {"MemberAccount": "222", "EvaluationResults": [{"ComplianceStatus": "NON_COMPLIANT", "ViolatorCount": 2}],
         "LastUpdated": dt.datetime(2026, 1, 1)},
        {"MemberAccount": "111", "EvaluationResults": [{"ComplianceStatus": "COMPLIANT"}],
         "IssueInfoMap": {"AWSCONFIG": "Config not enabled"}},
        {"MemberAccount": "333", "EvaluationResults": [{"ComplianceStatus": "NON_COMPLIANT", "ViolatorCount": 1}]}],
        "p2": [{"MemberAccount": "111", "EvaluationResults": [{"ComplianceStatus": "COMPLIANT"}]}]}
    details = {("p1", "222"): {"Violators": [
        {"ResourceType": "AWS::EC2::SecurityGroup", "ResourceId": "sg-1", "ViolationReason": "RESOURCE_VIOLATES_AUDIT_SECURITY_GROUP",
         "Metadata": {"rule": "0.0.0.0/0"}},
        {"ResourceType": "AWS::EC2::SecurityGroup", "ResourceId": "sg-2", "ViolationReason": "RESOURCE_MISSING_SECURITY_GROUP"}],
        "EvaluationLimitExceeded": True},
        ("p1", "333"): {"Violators": [], "ExpiredAt": dt.datetime(2026, 1, 3)}}
    policies = {"p1": {"RemediationEnabled": False}, "p2": {"RemediationEnabled": True}}
    return FakeFms(summaries, policies, status, details)


def cargs(**kw):
    return SimpleNamespace(**{"account": None, "type": None, "org_names": False, "profile": None, "policy": None,
                              "details_all": False, **kw})


def test_run(monkeypatch):
    fms = make_fms()
    monkeypatch.setattr(fc, "get_client", lambda svc, s: fms)
    policies, rows, findings, stats = fc.run(cargs(), ["us-east-1"])
    assert [(p.policy_name, p.accounts, p.compliant, p.non_compliant, p.violators) for p in policies] == \
        [("nacl", 1, 1, 0, 0), ("sg-baseline", 3, 1, 2, 3)]
    assert [(r.policy_id, r.account, r.status) for r in rows] == \
        [("p2", "111", "COMPLIANT"), ("p1", "111", "COMPLIANT"), ("p1", "222", "NON_COMPLIANT"), ("p1", "333", "NON_COMPLIANT")]
    row222 = rows[2]
    assert row222.evaluation_limit_exceeded is True and row222.last_updated == "2026-01-01 00:00:00"
    assert rows[1].issues == ["AWSCONFIG: Config not enabled"]
    got = [(f.code, f.account, f.resource_id) for f in findings]
    assert got == [("ISSUE", "111", ""), ("VIOLATION", "222", "sg-2"), ("VIOLATION", "222", "sg-1"),
                   ("EVALUATION_LIMIT_EXCEEDED", "222", ""), ("NON_COMPLIANT_NO_DETAIL", "333", "")]
    v = next(f for f in findings if f.resource_id == "sg-1")
    assert v.metadata == "rule=0.0.0.0/0" and v.reason == "RESOURCE_VIOLATES_AUDIT_SECURITY_GROUP"
    assert "detail expired at 2026-01-03 00:00:00" in findings[-1].detail
    assert stats["violations"] == 2 and stats["non_compliant_accounts"] == 2 and stats["accounts"] == 3


def test_run_filters_and_errors(monkeypatch):
    fms = make_fms()
    monkeypatch.setattr(fc, "get_client", lambda svc, s: fms)
    policies, rows, findings, _ = fc.run(cargs(type=["network_acl_common"]), ["us-east-1"])
    assert [p.policy_id for p in policies] == ["p2"]
    _, rows, _, _ = fc.run(cargs(account=["222,333"], policy="p1"), ["us-east-1"])
    assert [r.account for r in rows] == ["222", "333"]
    with pytest.raises(ValueError, match="not found"):
        fc.run(cargs(policy="nope"), ["us-east-1"])
    fms.fail |= {("detail", "222"), ("list_compliance_status", "p2")}
    _, _, findings, _ = fc.run(cargs(), ["us-east-1"])
    assert sorted(f.detail.split(":")[0] for f in findings if f.code == "FMS_ERROR") == \
        ["get_compliance_detail", "list_compliance_status"]
    fms.fail.add("list_policies")
    with pytest.raises(ValueError, match="could not list"):
        fc.run(cargs(), ["us-east-1", "eu-west-1"])


def test_main(monkeypatch, capsys, tmp_path):
    fms = make_fms()
    monkeypatch.setattr(fc, "get_client", lambda svc, s: fms)
    html = tmp_path / "c.html"
    assert run_main(fc, monkeypatch, ["--region", "us-east-1", "--json", "--no-save", "--html-out", str(html), "-q"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert len(out["violations"]) == 2 and out["regions"] == ["us-east-1"]
    assert html.exists()
    assert run_main(fc, monkeypatch, ["--policy", "nacl", "--no-save"]) == 0
    assert "nacl" in capsys.readouterr().out
    fms.fail.add("list_policies")
    assert run_main(fc, monkeypatch, ["--no-save", "-q"]) == 2
