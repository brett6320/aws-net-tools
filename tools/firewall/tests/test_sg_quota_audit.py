import argparse
import json

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from conftest import load_tool, run_main
from lib.accounts import Target

sq = load_tool("sg_quota_audit")


def client_error(code):
    return ClientError({"Error": {"Code": code, "Message": code}}, "op")


class FakeQuotas:
    def __init__(self, applied=None, default=None):
        self.applied, self.default = applied, default

    def _answer(self, v):
        if isinstance(v, Exception):
            raise v
        return {"Quota": {"Value": v}}

    def get_service_quota(self, ServiceCode, QuotaCode):
        return self._answer(self.applied)

    def get_aws_default_service_quota(self, ServiceCode, QuotaCode):
        return self._answer(self.default)


def test_lookup_quota_sources():
    q = sq.RULE_QUOTA
    assert sq.lookup_quota(None, q, 7) == (7, "override", False)
    assert sq.lookup_quota(FakeQuotas(applied=200.0), q, None) == (200, "applied", False)
    assert sq.lookup_quota(FakeQuotas(applied=client_error("NoSuchResourceException"), default=60.0), q, None) == \
        (60, "aws-default", False)
    denied = client_error("AccessDeniedException")
    assert sq.lookup_quota(FakeQuotas(applied=denied, default=denied), q, None) == (60, "default", True)
    assert sq.lookup_quota(FakeQuotas(applied=client_error("Throttling"), default=KeyError("x")), sq.ENI_QUOTA, None) == \
        (5, "default", False)


class FakePlEc2:
    """describe_managed_prefix_lists; any batch containing a missing id fails like EC2 does."""
    def __init__(self, lists):
        self.lists = lists
        self.calls = []

    def get_paginator(self, op):
        assert op == "describe_managed_prefix_lists"
        ec2 = self

        class P:
            def paginate(self, PrefixListIds):
                ec2.calls.append(list(PrefixListIds))
                if any(i not in ec2.lists for i in PrefixListIds):
                    raise client_error("InvalidPrefixListID.NotFound")
                return [{"PrefixLists": [ec2.lists[i] for i in PrefixListIds]}]
        return P()


def test_prefix_list_weights():
    ec2 = FakePlEc2({"pl-a": {"PrefixListId": "pl-a", "PrefixListName": "corp", "MaxEntries": 20},
                     "pl-aws": {"PrefixListId": "pl-aws", "PrefixListName": "com.amazonaws.s3"}})
    weights, names, unknown = sq.prefix_list_weights(ec2, {"pl-a", "pl-aws", "pl-gone"})
    assert weights == {"pl-a": 20, "pl-aws": 1, "pl-gone": 1}
    assert names == {"pl-a": "corp", "pl-aws": "com.amazonaws.s3"}
    assert unknown == {"pl-aws", "pl-gone"}
    assert ec2.calls[0] == ["pl-a", "pl-aws", "pl-gone"]     # one batch, then one id at a time
    assert sorted(map(tuple, ec2.calls[1:])) == [("pl-a",), ("pl-aws",), ("pl-gone",)]


def test_stale_refs():
    sg = {"StaleIpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                                  "UserIdGroupPairs": [{"GroupId": "sg-1", "VpcPeeringConnectionId": "pcx-1"}]}],
          "StaleIpPermissionsEgress": [{"IpProtocol": "-1", "FromPort": -1,
                                        "UserIdGroupPairs": [{"GroupName": "old"}, {}]}]}
    assert sq._stale_refs(sg) == ["inbound tcp 22-22 sg-1 via pcx-1", "outbound -1 old", "outbound -1 ?"]


class FakeStaleEc2:
    def __init__(self, pages):
        self.pages = pages
        self.tokens = []

    def describe_stale_security_groups(self, VpcId, NextToken=None):
        self.tokens.append(NextToken)
        return self.pages[NextToken]


def test_stale_groups_follows_next_token():
    ec2 = FakeStaleEc2({None: {"StaleSecurityGroupSet": [{"GroupId": "sg-1"}], "NextToken": "t"},
                        "t": {"StaleSecurityGroupSet": [{"GroupId": "sg-2"}]}})
    assert [g["GroupId"] for g in sq.stale_groups(ec2, "vpc-1")] == ["sg-1", "sg-2"]
    assert ec2.tokens == [None, "t"]


def test_env_int_and_peak(monkeypatch):
    monkeypatch.setenv("X_LIMIT", " 42 ")
    assert sq._env_int("X_LIMIT", None) == 42
    monkeypatch.setenv("X_LIMIT", "")
    assert sq._env_int("X_LIMIT", 5) == 5
    g = sq.GroupUsage("1", "r", "vpc", "sg-1", "n", False, inbound_effective=30, outbound_effective=45, limit=60)
    assert g.peak_pct == 75
    assert sq.GroupUsage("1", "r", "vpc", "sg-1", "n", False).peak_pct == 0
    assert sq._name_tag([{"Key": "a", "Value": "b"}, {"Key": "Name", "Value": "web"}]) == "web"
    assert sq._name_tag(None) == ""


# --------------------------------------------------------------------------- #
# moto-backed scan
# --------------------------------------------------------------------------- #
def qargs(**kw):
    return argparse.Namespace(**{"rule_limit": 10, "sg_per_eni_limit": 3, "headroom": 2, "eni_headroom": 1,
                                 "vpc": None, **kw})


@pytest.fixture
def env(monkeypatch):
    stale = []
    monkeypatch.setattr(sq, "stale_groups", lambda ec2, vpc: stale)   # not implemented by moto
    with mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
        mk = lambda n: ec2.create_security_group(GroupName=n, Description=n, VpcId=vpc)["GroupId"]  # noqa: E731
        busy, heavy, idle, ref, extra = mk("busy"), mk("heavy"), mk("idle"), mk("ref"), mk("extra")
        ec2.authorize_security_group_ingress(GroupId=busy, IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": p, "ToPort": p, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}
            for p in range(1000, 1008)])                                   # 8 inbound: near a limit of 10
        pl = ec2.create_managed_prefix_list(PrefixListName="big", AddressFamily="IPv4", MaxEntries=12,
                                            Entries=[{"Cidr": "192.168.0.0/24"}])["PrefixList"]["PrefixListId"]
        ec2.authorize_security_group_ingress(GroupId=heavy, IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "PrefixListIds": [{"PrefixListId": pl}]}])
        ec2.authorize_security_group_ingress(GroupId=ref, IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "UserIdGroupPairs": [{"GroupId": idle}]}])
        ec2.create_network_interface(SubnetId=subnet, Groups=[busy, heavy, ref])
        ec2.create_network_interface(SubnetId=subnet, Groups=[busy, extra])
        default = ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc]},
                                                        {"Name": "group-name", "Values": ["default"]}]
                                               )["SecurityGroups"][0]["GroupId"]
        yield dict(ec2=ec2, vpc=vpc, busy=busy, heavy=heavy, idle=idle, ref=ref, extra=extra, pl=pl,
                   default=default, stale=stale)


def test_scan_region(env):
    findings, groups, quotas, n_enis = sq.scan_region(Target("123456789012", None), "us-east-1", qargs(vpc=[env["vpc"]]))
    assert n_enis == 2
    assert (quotas.rule_limit, quotas.rule_source, quotas.eni_limit, quotas.eni_source) == (10, "override", 3, "override")
    got = {(f.code, f.resource_id, f.direction): f for f in findings}
    near = got[("SG_NEAR_LIMIT", env["busy"], "inbound")]
    assert (near.severity, near.count, near.limit, near.detail) == ("warn", 8, 10, "8 rules count as 8")
    at = got[("SG_AT_LIMIT", env["heavy"], "inbound")]
    assert (at.severity, at.count) == ("error", 12)                    # one rule counts as MaxEntries 12
    assert f"heaviest prefix lists: {env['pl']} (big) 12" in at.detail
    eni = [f for f in findings if f.code == "ENI_AT_SG_LIMIT"]
    assert len(eni) == 1 and eni[0].count == 3
    unattached = {f.resource_id: f.detail for f in findings if f.code == "UNATTACHED_SG"}
    assert set(unattached) == {env["idle"]}
    assert f"referenced by {env['ref']}" in unattached[env["idle"]]
    by_id = {g.group_id: g for g in groups}
    assert (by_id[env["busy"]].enis, by_id[env["busy"]].inbound_raw) == (2, 8)
    assert by_id[env["heavy"]].pl_weights["inbound"] == {env["pl"]: 12}
    assert by_id[env["default"]].is_default
    # moto's default group holds a self-reference ingress rule and an allow-all egress rule
    assert ("DEFAULT_SG_HAS_RULES", env["default"], "") in got


def test_scan_region_service_quotas_and_stale(env):
    env["stale"].append({"GroupId": env["idle"], "GroupName": "idle", "StaleIpPermissions": []})
    findings, _, quotas, _ = sq.scan_region(Target("123456789012", None), "us-east-1",
                                            qargs(rule_limit=None, sg_per_eni_limit=None, vpc=[env["vpc"]]))
    # moto implements GetServiceQuota for the rules quota (60); the ENI quota lookup falls back further
    assert (quotas.rule_limit, quotas.rule_source) == (60, "applied")
    stale = [f for f in findings if f.code == "STALE_REFERENCE"]
    assert [(f.resource_id, f.detail) for f in stale] == [(env["idle"], "stale: see console")]


def test_run_unusable_targets(env):
    payload = sq.run(qargs(vpc=[env["vpc"]]), [Target("123456789012", None), Target("1", None, False, "no local profile"),
                                               Target("2", "p", False, "profile p resolves to 3")], ["us-east-1"])
    assert payload["stats"]["accounts"] == 1 and payload["stats"]["accounts_skipped"] == 2
    codes = {f["code"] for f in payload["findings"]}
    assert {"NO_PROFILE", "PROFILE_ACCOUNT_MISMATCH", "SG_AT_LIMIT"} <= codes
    assert payload["groups"][0]["peak_pct"] == max(g["peak_pct"] for g in payload["groups"])   # sorted by usage


def test_main_moto(env, monkeypatch, capsys, tmp_path):
    rc = run_main(sq, monkeypatch, ["--region", "us-east-1", "--vpc", env["vpc"], "--rule-limit", "10",
                                    "--sg-per-eni-limit", "3", "--headroom", "2", "--out-dir", str(tmp_path / "rep"),
                                    "--json", "-q"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert payload["quotas"] == [{"account": "123456789012", "region": "us-east-1", "rule_limit": 10,
                                  "rule_source": "override", "eni_limit": 3, "eni_source": "override"}]
    [html] = list((tmp_path / "rep" / "sg_quota_audit").glob("*/*.html"))
    assert "Security group" in html.read_text()
    saved = json.loads(next(html.parent.glob("*.json")).read_text())
    assert saved["stats"] == payload["stats"]


def test_main_text_report(env, monkeypatch, capsys):
    assert run_main(sq, monkeypatch, ["--vpc", env["vpc"], "--rule-limit", "100", "--sg-per-eni-limit", "16",
                                      "--no-save", "--show-info"]) == 1      # default group with rules: warn
    out = capsys.readouterr().out
    assert "DEFAULT_SG_HAS_RULES" in out and "UNATTACHED_SG" in out
