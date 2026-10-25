import json
from types import SimpleNamespace

import boto3
import pytest
from moto import mock_aws

from conftest import load_tool, run_main

fna = load_tool("fmm_nacl_audit")
Entry = fna.Entry

SSH_DENY = {"Egress": False, "Protocol": "6", "PortRange": {"From": 22, "To": 22}, "CidrBlock": "10.0.0.0/8",
            "RuleAction": "deny"}
ALLOW_ALL = {"Egress": False, "Protocol": "-1", "CidrBlock": "0.0.0.0/0", "RuleAction": "allow"}


def policy(first=(SSH_DENY,), last=(ALLOW_ALL,), pid="p1", name="nacl-base", **extra):
    es = {"FirstEntries": list(first), "LastEntries": list(last), "ForceRemediateForFirstEntries": True,
          "ForceRemediateForLastEntries": False}
    return {"PolicyId": pid, "PolicyName": name, **extra, "SecurityServicePolicyData": {
        "Type": "NETWORK_ACL_COMMON", "PolicyOption": {"NetworkAclCommonPolicy": {"NetworkAclEntrySet": es}}}}


def live(number, base, **kw):
    return {**base, "RuleNumber": number, **kw}


# --------------------------------------------------------------------------- #
# Entry
# --------------------------------------------------------------------------- #
def test_entry_parsing_and_text():
    e = Entry.from_live(live(100, SSH_DENY, CidrBlock="10.1.2.3/8", RuleAction="DENY"))
    assert (e.egress, e.action, e.proto, e.cidr, e.ports, e.icmp, e.number) == \
        (False, "deny", "tcp", "10.0.0.0/8", (22, 22), None, 100)
    assert str(e) == "#100 ingress deny tcp 22 10.0.0.0/8"
    p = Entry.from_policy(SSH_DENY)
    assert p.number is None and p.key() == e.key() and str(p) == "ingress deny tcp 22 10.0.0.0/8"
    icmp = Entry.from_live({"RuleNumber": 5, "Egress": True, "Protocol": "1", "IcmpTypeCode": {"Type": 8, "Code": -1},
                            "PortRange": {"From": 1, "To": 2}, "Ipv6CidrBlock": "::/0", "RuleAction": "allow"})
    assert (icmp.ports, icmp.icmp, icmp.cidr) == (None, (8, -1), "::/0")
    assert str(icmp) == "#5 egress allow icmp type=8,code=-1 ::/0"
    assert str(Entry.from_policy({"Protocol": "-1", "RuleAction": "allow"})) == "ingress allow any any"


def test_entry_diff_and_formatting():
    a = Entry.from_policy(SSH_DENY)
    b = Entry.from_live(live(1, SSH_DENY, CidrBlock="10.1.0.0/16", PortRange={"From": 20, "To": 23}))
    assert a.diff(b) == ["cidr: expected 10.0.0.0/8, got 10.1.0.0/16", "ports: expected 22, got 20-23"]
    assert fna._fmt_val("ports", None) == "-" and fna._fmt_val("cidr", "") == "-"
    assert fna._norm_cidr("") == "" and fna._norm_cidr(" junk ") == "junk"


# --------------------------------------------------------------------------- #
# policy loading
# --------------------------------------------------------------------------- #
def test_baseline_from_policy_shapes():
    bl = fna.baseline_from_policy(policy(), "live")
    assert (bl.policy_id, bl.policy_name, bl.force_first, bl.force_last) == ("p1", "nacl-base", True, False)
    assert [str(e) for e in bl.block("first", False)] == ["ingress deny tcp 22 10.0.0.0/8"]
    assert bl.block("first", True) == []
    bare = fna.baseline_from_policy({"FirstEntries": [SSH_DENY]}, "file")
    assert len(bare.first) == 1 and bare.last == [] and bare.policy_id == ""


def test_baseline_fails_closed():
    with pytest.raises(ValueError, match="no first or last entries"):
        fna.baseline_from_policy(policy(first=(), last=()), "file")
    with pytest.raises(ValueError, match="no SecurityServicePolicyData"):
        fna.baseline_from_policy({"PolicyId": "x"}, "file")
    with pytest.raises(ValueError, match="not NETWORK_ACL_COMMON"):
        fna.baseline_from_policy({"SecurityServicePolicyData": {"Type": "WAFV2"}}, "file")


def test_load_policy_file(tmp_path):
    p = tmp_path / "pol.json"
    p.write_text(json.dumps({"Policy": policy(), "PolicyArn": "arn:aws:fms:eu-west-1:111122223333:policy/p1"}))
    doc, region = fna.load_policy_file(str(p))
    assert region == "eu-west-1" and doc["PolicyId"] == "p1"
    p.write_text(json.dumps(policy()))
    assert fna.load_policy_file(str(p)) == (policy(), None)


@pytest.mark.parametrize("pol,tags,expected", [
    ({}, {}, True),
    ({"ResourceTags": [{"Key": "env", "Value": "prod"}]}, {"env": "prod"}, True),
    ({"ResourceTags": [{"Key": "env", "Value": "prod"}]}, {"env": "dev"}, False),
    ({"ResourceTags": [{"Key": "env"}]}, {"env": "anything"}, True),
    ({"ResourceTags": [{"Key": "a", "Value": "1"}, {"Key": "b", "Value": "2"}]}, {"a": "1"}, False),
    ({"ResourceTags": [{"Key": "a", "Value": "1"}, {"Key": "b", "Value": "2"}], "ResourceTagLogicalOperator": "OR"},
     {"a": "1"}, True),
    ({"ResourceTags": [{"Key": "env", "Value": "prod"}], "ExcludeResourceTags": True}, {"env": "prod"}, False),
    ({"ResourceTags": [{"Key": "env", "Value": "prod"}], "ExcludeResourceTags": True}, {}, True),
])
def test_subnet_in_scope(pol, tags, expected):
    assert fna.subnet_in_scope(tags, pol) is expected


class Pager:
    def __init__(self, fn):
        self.paginate = fn


class FakeFms:
    def __init__(self, policies, compliance):
        self.policies, self.compliance = policies, compliance

    def get_paginator(self, op):
        if op == "list_policies":
            return Pager(lambda: [{"PolicyList": [{"PolicyId": p["PolicyId"], "PolicyName": p["PolicyName"],
                                                   "SecurityServiceType": p["SecurityServicePolicyData"]["Type"]}
                                                  for p in self.policies]}])
        assert op == "list_compliance_status"
        return Pager(lambda PolicyId: [{"PolicyComplianceStatusList": self.compliance}])

    def get_policy(self, PolicyId):
        return {"Policy": next(p for p in self.policies if p["PolicyId"] == PolicyId)}


def test_policy_accounts():
    fms = FakeFms([], [
        {"MemberAccount": "1", "EvaluationResults": [{"ComplianceStatus": "COMPLIANT"}, {"ComplianceStatus": "NON_COMPLIANT"}]},
        {"MemberAccount": "2", "EvaluationResults": [{"ComplianceStatus": "COMPLIANT"}]},
        {"MemberAccount": "3", "EvaluationResults": []}])
    assert fna.policy_accounts(fms, "p1") == {"1": "NON_COMPLIANT", "2": "COMPLIANT", "3": "UNKNOWN"}


# --------------------------------------------------------------------------- #
# NACL checks
# --------------------------------------------------------------------------- #
def mk(sev, code, pos, exp, got, detail):
    return (sev, code, pos, str(got) if got else "", detail)


EXP = [Entry.from_policy(SSH_DENY)]


def test_check_block_first():
    ok = [Entry.from_live(live(1, SSH_DENY))]
    assert fna.check_block("first", EXP, ok, mk) == []
    assert fna.check_block("first", [], ok, mk) == []
    [r] = fna.check_block("first", EXP, [Entry.from_live(live(100, SSH_DENY))], mk)
    assert r[:3] == ("info", "FIRST_RENUMBERED", "first[1]")
    assert r[4] == "matches, but rule #100 (FMS initial numbering #1)"
    [r] = fna.check_block("first", EXP, [], mk)
    assert r[:2] == ("error", "FIRST_MISSING")
    other = Entry.from_live(live(1, ALLOW_ALL))
    [r] = fna.check_block("first", EXP, [other, Entry.from_live(live(2, SSH_DENY))], mk)
    assert r[:2] == ("error", "FIRST_OUT_OF_ORDER") and r[4] == "expected rule not in position; same rule found at #2"
    [r] = fna.check_block("first", EXP, [Entry.from_live(live(1, SSH_DENY, CidrBlock="10.1.0.0/16"))], mk)
    assert r[:2] == ("error", "FIRST_MISMATCH") and r[4] == "cidr: expected 10.0.0.0/8, got 10.1.0.0/16"


def test_check_block_last():
    exp = [Entry.from_policy(SSH_DENY), Entry.from_policy(ALLOW_ALL)]
    good = [Entry.from_live(live(100, ALLOW_ALL, RuleAction="deny")), Entry.from_live(live(32765, SSH_DENY)),
            Entry.from_live(live(32766, ALLOW_ALL))]
    assert fna.check_block("last", exp, good, mk) == []
    [r] = fna.check_block("last", exp, [Entry.from_live(live(32766, ALLOW_ALL))], mk)
    assert r[:3] == ("error", "LAST_MISSING", "last[1]")
    [r] = fna.check_block("last", exp[1:], [Entry.from_live(live(32000, ALLOW_ALL))], mk)
    assert r[1] == "LAST_RENUMBERED" and "(FMS initial numbering #32766)" in r[4]


CTX = dict(region="us-east-1", policy_name="nacl-base", policy_id="p1", account="1", profile="p")


def nacl(entries, tags=(("FMManaged", "true"),), default=False):
    return {"NetworkAclId": "acl-1", "VpcId": "vpc-1", "IsDefault": default,
            "Associations": [{"SubnetId": "subnet-b"}, {"SubnetId": "subnet-a"}],
            "Tags": [{"Key": k, "Value": v} for k, v in tags],
            "Entries": entries + [live(32767, ALLOW_ALL, RuleAction="deny")]}


def test_analyze_nacl_clean():
    bl = fna.baseline_from_policy(policy(), "live")
    out = fna.analyze_nacl(nacl([live(1, SSH_DENY), live(5000, ALLOW_ALL, CidrBlock="10.0.0.0/8"),
                                 live(32766, ALLOW_ALL)]), [bl], CTX, 30, 3)
    assert out == []


def test_analyze_nacl_findings():
    bl = fna.baseline_from_policy(policy(), "live")
    entries = [live(1, SSH_DENY), live(100, ALLOW_ALL, CidrBlock="10.0.0.0/8"),
               live(200, ALLOW_ALL, CidrBlock="10.0.0.0/8"), live(32766, ALLOW_ALL)]
    out = fna.analyze_nacl(nacl(entries, tags=()), [bl], CTX, 5, 1)
    got = sorted((f.code, f.severity, f.actual) for f in out)
    assert got == [
        ("CUSTOM_OUTSIDE_RANGE", "info", "#100 ingress allow any 10.0.0.0/8"),
        ("CUSTOM_OUTSIDE_RANGE", "info", "#200 ingress allow any 10.0.0.0/8"),
        ("DUPLICATE_RULE", "warn", "ingress allow any 10.0.0.0/8 at #100, #200"),
        ("NEAR_LIMIT", "warn", "4"),
        ("NOT_FMMANAGED", "warn", ""),
    ]
    assert out[0].subnets == ["subnet-a", "subnet-b"]
    at = fna.analyze_nacl(nacl(entries), [bl], CTX, 4, 0)
    assert [f.detail for f in at if f.code == "AT_LIMIT"] == ["4 ingress rules, limit 4"]


def test_check_default_nacl():
    assert fna.check_default_nacl(nacl([], default=True), CTX) == []
    [f] = fna.check_default_nacl(nacl([live(100, ALLOW_ALL)], default=True), CTX)
    assert (f.code, f.direction, f.actual) == ("DEFAULT_NACL_NOT_DENY_ALL", "ingress", "#100 ingress allow any 0.0.0.0/0")


def test_diff_baselines():
    file_bl = fna.baseline_from_policy(policy(first=(SSH_DENY, ALLOW_ALL)), "file")
    live_p = policy(first=({**SSH_DENY, "CidrBlock": "10.1.0.0/16"},))
    live_p["SecurityServicePolicyData"]["PolicyOption"]["NetworkAclCommonPolicy"]["NetworkAclEntrySet"][
        "ForceRemediateForLastEntries"] = True
    out = fna.diff_baselines(file_bl, fna.baseline_from_policy(live_p, "live"), CTX)
    assert [(f.severity, f.position, f.detail) for f in out] == [
        ("warn", "first[1]", "cidr: expected 10.0.0.0/8, got 10.1.0.0/16"),
        ("warn", "first[2]", "only in policy file"),
        ("info", "force_last", "forceRemediateForLastEntries differs"),
    ]


# --------------------------------------------------------------------------- #
# end to end: fake FMS, moto EC2/STS
# --------------------------------------------------------------------------- #
def test_main_fake_fms_moto_ec2(monkeypatch, capsys, aws_profiles, tmp_path):
    aws_profiles({"member": {"aws_account_id": "123456789012"}, "member-priv": {"aws_account_id": "555555555555"}})
    fms = FakeFms([policy(), {**policy(pid="p2", name="sg"), "SecurityServicePolicyData": {"Type": "SECURITY_GROUPS_COMMON"}}],
                  [{"MemberAccount": "123456789012", "EvaluationResults": [{"ComplianceStatus": "NON_COMPLIANT"}]},
                   {"MemberAccount": "555555555555", "EvaluationResults": []}])
    real = fna.get_client
    monkeypatch.setattr(fna, "get_client", lambda svc, session: fms if svc == "fms" else real(svc, session))
    with mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        acl = ec2.create_network_acl(VpcId=vpc, TagSpecifications=[{"ResourceType": "network-acl", "Tags": [
            {"Key": "FMManaged", "Value": "true"}]}])["NetworkAcl"]["NetworkAclId"]
        ec2.create_network_acl_entry(NetworkAclId=acl, RuleNumber=1, Protocol="6", RuleAction="deny", Egress=False,
                                     CidrBlock="10.0.0.0/8", PortRange={"From": 22, "To": 22})
        ec2.create_network_acl_entry(NetworkAclId=acl, RuleNumber=32000, Protocol="-1", RuleAction="allow",
                                     Egress=False, CidrBlock="0.0.0.0/0")
        rc = run_main(fna, monkeypatch, ["--region", "us-east-1", "--nacl-scope", "fmmanaged", "--json", "--no-save",
                                         "--html-out", str(tmp_path / "n.html"), "-q"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert out["stats"]["policies"] == 1 and out["stats"]["accounts"] == 1 and out["stats"]["accounts_skipped"] == 1
    got = {(f["code"], f["account"], f["nacl_id"]) for f in out["findings"]}
    assert ("LAST_RENUMBERED", "123456789012", acl) in got
    assert ("NO_PROFILE", "555555555555", "") in got                 # only a -priv profile exists for it
    assert not any(f["nacl_id"] == acl and f["severity"] == "error" for f in out["findings"])
    assert (tmp_path / "n.html").exists()


def test_main_rejects_compare_live_without_file(monkeypatch):
    with pytest.raises(SystemExit):
        run_main(fna, monkeypatch, ["--compare-live"])


def test_build_jobs_policy_file(monkeypatch, tmp_path):
    p = tmp_path / "pol.json"
    p.write_text(json.dumps({"Policy": policy(first=({**SSH_DENY, "CidrBlock": "10.9.0.0/16"},)),
                             "PolicyArn": "arn:aws:fms:us-east-1:1:policy/p1"}))
    fms = FakeFms([policy()], [])
    monkeypatch.setattr(fna, "get_client", lambda svc, session: fms)
    findings = []
    args = SimpleNamespace(policy_file=str(p), policy=None, region=None, profile=None, compare_live=True)
    [job] = fna.build_jobs(args, ["eu-west-1"], findings)
    assert job.region == "us-east-1" and [b.source for b in job.baselines] == ["file", "live"]
    assert [f.code for f in findings] == ["POLICY_DRIFT"]
    args.policy = "missing"
    with pytest.raises(ValueError, match="not found"):
        fna.build_jobs(args, ["eu-west-1"], [])
