import argparse
import ipaddress

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from lib import security_groups as sgm
from lib.boxes import ALL_PORTS, ALL_PROTOS, addr_interval
from lib.security_groups import (SgRule, parse_account_targets, parse_target, spec_accounts, split_specs)

SG = "sg-0123456789abcdef0"
SG2 = "sg-0fedcba9876543210"
ACCT = "111122223333"


def api(**kw):
    return {"GroupId": SG, "SecurityGroupRuleId": "sgr-1", "IsEgress": False, "IpProtocol": "tcp",
            "FromPort": 443, "ToPort": 443, **kw}


def iv(c):
    return addr_interval(ipaddress.ip_network(c))


# --------------------------------------------------------------------------- #
# SgRule
# --------------------------------------------------------------------------- #
def test_from_api_ipv4_normalised():
    r = SgRule.from_api(api(CidrIpv4="10.1.2.3/8", Description="web"))
    assert (r.peer, r.peer_kind, r.description, r.direction) == ("10.0.0.0/8", "ipv4", "web", "ingress")
    assert (r.proto, r.from_port, r.to_port, r.rule_id) == ("tcp", 443, 443, "sgr-1")


def test_from_api_ipv6_prefix_list_and_group_refs():
    assert SgRule.from_api(api(CidrIpv6="2001:DB8::/32")).peer == "2001:db8::/32"
    pl = SgRule.from_api(api(PrefixListId="pl-0abc"))
    assert (pl.peer, pl.peer_kind) == ("pl-0abc", "pl")
    other = SgRule.from_api(api(ReferencedGroupInfo={"GroupId": SG2, "UserId": ACCT}))
    assert (other.peer, other.peer_kind) == (SG2, "sg")
    own = SgRule.from_api(api(ReferencedGroupInfo={"GroupId": SG}))
    assert (own.peer, own.peer_kind) == ("self", "sg")


def test_from_api_defaults_and_null_fields():
    r = SgRule.from_api({"GroupId": SG, "ReferencedGroupInfo": None, "Description": None, "IsEgress": True})
    assert (r.peer, r.peer_kind, r.proto, r.egress, r.description, r.rule_id) == ("?", "sg", "-1", True, "", "")
    assert r.direction == "egress"


def test_key_ignores_description_but_not_peer_or_direction():
    a = SgRule.from_api(api(CidrIpv4="10.0.0.0/8", Description="a"))
    b = SgRule.from_api(api(CidrIpv4="10.0.0.0/8", Description="b", SecurityGroupRuleId="sgr-2"))
    assert a.key() == b.key()
    assert a.key() != SgRule.from_api(api(CidrIpv4="10.0.0.0/16")).key()
    assert a.key() != SgRule.from_api(api(CidrIpv4="10.0.0.0/8", IsEgress=True)).key()


def test_self_references_in_different_groups_compare_equal():
    a = SgRule.from_api(api(ReferencedGroupInfo={"GroupId": SG}))
    b = SgRule.from_api(api(GroupId=SG2, ReferencedGroupInfo={"GroupId": SG2}))
    assert a.key() == b.key()


def test_expand_cidr_prefix_list_and_opaque():
    r = SgRule.from_api(api(CidrIpv4="10.0.0.0/8"))
    r.expand({})
    assert r.boxes == [("ipv4", ((6, 6), (443, 443), iv("10.0.0.0/8")))]

    pl = SgRule.from_api(api(PrefixListId="pl-1", IpProtocol="-1", FromPort=-1, ToPort=-1))
    pl.expand({"pl-1": ["192.168.0.0/24", "2001:db8::/48"]})
    assert pl.boxes == [("ipv4", (ALL_PROTOS, ALL_PORTS, iv("192.168.0.0/24"))),
                        ("ipv6", (ALL_PROTOS, ALL_PORTS, iv("2001:db8::/48")))]

    for entries in ({"pl-1": None}, {}):        # unreadable or never fetched: matched by id only
        pl.expand(entries)
        assert pl.boxes == [("pl:pl-1", (ALL_PROTOS, ALL_PORTS, (0, 0)))]

    ref = SgRule.from_api(api(ReferencedGroupInfo={"GroupId": SG2}))
    ref.expand({})
    assert ref.boxes == [(f"sg:{SG2}", ((6, 6), (443, 443), (0, 0)))]


def test_text_rendering():
    r = SgRule.from_api(api(CidrIpv4="10.0.0.0/8", Description="web"))
    assert r.access() == "tcp 443"
    assert str(r) == "tcp 443 from 10.0.0.0/8"
    assert r.ref() == f'{SG} sgr-1 tcp 443 from 10.0.0.0/8 "web"'
    e = SgRule.from_api(api(PrefixListId="pl-1", IsEgress=True, FromPort=5432, ToPort=5432))
    e.peer_label = "corp-db, 2 entries"
    assert str(e) == "tcp 5432 to pl-1 (corp-db, 2 entries)"
    assert e.ref() == f"{SG} sgr-1 tcp 5432 to pl-1 (corp-db, 2 entries)"


# --------------------------------------------------------------------------- #
# Target parsing
# --------------------------------------------------------------------------- #
def test_split_specs():
    assert split_specs([f"{SG}, {SG2}", "", " , ", "eni-0123456789abcdef0,"]) == [SG, SG2, "eni-0123456789abcdef0"]


def test_spec_accounts():
    specs = [f"arn:aws:ec2:us-east-1:{ACCT}:security-group/{SG}",
             "arn:aws:ec2:us-east-1:444455556666:network-interface/eni-0123456789abcdef0,"
             "arn:aws:lambda:us-east-1:777788889999:function:fn",
             SG]
    assert spec_accounts(specs) == {ACCT, "444455556666", "777788889999"}


def test_parse_target_arn_and_govcloud():
    assert parse_target(f"arn:aws:ec2:us-west-2:{ACCT}:security-group/{SG}", None) == (ACCT, "us-west-2", SG)
    assert parse_target(f"arn:aws-us-gov:ec2:us-gov-west-1:{ACCT}:security-group/{SG}", "us-east-1") == \
        (ACCT, "us-gov-west-1", SG)


def test_parse_target_bare_id_needs_region():
    assert parse_target(SG, "eu-west-1") == (None, "eu-west-1", SG)
    with pytest.raises(ValueError, match="needs --region"):
        parse_target(SG, None)


def test_parse_target_workloads_only_when_allowed():
    eni, inst = "eni-0123456789abcdef0", "i-0123456789abcdef0"
    with pytest.raises(ValueError, match="not a security group ARN or id"):
        parse_target(eni, "us-east-1")
    assert parse_target(eni, "us-east-1", allow_workloads=True) == (None, "us-east-1", eni)
    assert parse_target(inst, "us-east-1", allow_workloads=True) == (None, "us-east-1", inst)
    arn = f"arn:aws:ec2:us-east-1:{ACCT}:instance/{inst}"
    assert parse_target(arn, None, allow_workloads=True) == (ACCT, "us-east-1", inst)


def test_parse_target_lambda_arn():
    arn = f"arn:aws:lambda:eu-west-1:{ACCT}:function:my-fn:live"
    assert parse_target(arn, None, allow_workloads=True) == (ACCT, "eu-west-1", "lambda:my-fn:live")
    with pytest.raises(ValueError):
        parse_target(arn, None)


@pytest.mark.parametrize("bad", ["sg-xyz", "sg-1234567", "subnet-0123456789abcdef0", "vpc-01234567",
                                 f"arn:aws:ec2:us-east-1:12:security-group/{SG}", ""])
def test_parse_target_invalid(bad):
    with pytest.raises(ValueError):
        parse_target(bad, "us-east-1", allow_workloads=True)


def test_parse_account_targets_order_and_dedup():
    arn = f"arn:aws:ec2:us-east-1:{ACCT}:security-group/{SG2}"
    assert parse_account_targets([f"{SG},{arn}", SG, arn], "us-east-1") == \
        [(None, "us-east-1", SG), (ACCT, "us-east-1", SG2)]


def test_parse_account_targets_empty_and_groups_only():
    with pytest.raises(ValueError, match="no targets"):
        parse_account_targets([" , "], "us-east-1")
    with pytest.raises(ValueError):
        parse_account_targets(["eni-0123456789abcdef0"], "us-east-1", allow_workloads=False)


# --------------------------------------------------------------------------- #
# resolve_account_profiles (sts faked)
# --------------------------------------------------------------------------- #
def profile_args(profile=None, account_profile=None):
    return argparse.Namespace(profile=profile, account_profile=account_profile, exclude_profile_suffix="-priv,-cpar")


@pytest.fixture
def fake_sts(monkeypatch):
    accounts = {None: "999999999999", "a-ro": "111111111111", "b-ro": "222222222222", "liar": "333333333333"}
    monkeypatch.setattr(sgm, "caller_account", lambda p: accounts[p])
    return accounts


def test_resolve_profiles_by_account_id(aws_profiles, fake_sts):
    aws_profiles({"a-ro": {"aws_account_id": "111111111111"}, "a-priv": {"aws_account_id": "111111111111"},
                  "b-ro": {"sso_account_id": "222222222222"}})
    out, bare = sgm.resolve_account_profiles(profile_args(), {"111111111111", "222222222222"}, False)
    assert out == {"111111111111": ("a-ro", "local profile for account 111111111111"),
                   "222222222222": ("b-ro", "local profile for account 222222222222")}
    assert bare is None


def test_resolve_profiles_bare_ids(aws_profiles, fake_sts):
    aws_profiles({"a-ro": {"aws_account_id": "111111111111"}})
    # single ARN account: bare ids belong to it
    assert sgm.resolve_account_profiles(profile_args(), {"111111111111"}, True)[1] == "111111111111"
    # no ARNs: default credentials
    out, bare = sgm.resolve_account_profiles(profile_args(), set(), True)
    assert (bare, out) == ("999999999999", {"999999999999": (None, "default credentials")})
    # --profile wins for bare ids
    out, bare = sgm.resolve_account_profiles(profile_args(profile="b-ro"), {"111111111111"}, True)
    assert bare == "222222222222" and out["222222222222"] == ("b-ro", "--profile")


def test_resolve_profiles_ambiguous_bare_ids(aws_profiles, fake_sts):
    aws_profiles({"a-ro": {"aws_account_id": "111111111111"}, "b-ro": {"aws_account_id": "222222222222"}})
    with pytest.raises(ValueError, match="ambiguous"):
        sgm.resolve_account_profiles(profile_args(), {"111111111111", "222222222222"}, True)


def test_resolve_profiles_fails_closed(aws_profiles, fake_sts):
    aws_profiles({"a-priv": {"aws_account_id": "111111111111"},
                  "liar": {"role_arn": "arn:aws:iam::444444444444:role/ro"}})
    with pytest.raises(ValueError, match="no local AWS profile for account 111111111111"):
        sgm.resolve_account_profiles(profile_args(), {"111111111111"}, False)
    with pytest.raises(ValueError, match="profile liar is account 333333333333, expected 444444444444"):
        sgm.resolve_account_profiles(profile_args(), {"444444444444"}, False)


def test_resolve_profiles_override(aws_profiles, fake_sts):
    aws_profiles({})
    out, _ = sgm.resolve_account_profiles(profile_args(account_profile=["111111111111=a-ro"]), {"111111111111"}, False)
    assert out == {"111111111111": ("a-ro", "local profile for account 111111111111 (override)")}


# --------------------------------------------------------------------------- #
# Fake session for workload resolution
# --------------------------------------------------------------------------- #
class FakeLambda:
    def __init__(self, configs):
        self.configs = configs

    def get_function_configuration(self, FunctionName, Qualifier=None):
        return self.configs[(FunctionName, Qualifier)]


class FakeSession:
    def __init__(self, clients):
        self.clients = clients

    def client(self, service, config=None):
        return self.clients[service]


def test_resolve_workloads_lambda():
    lam = FakeLambda({
        ("in-vpc", "live"): {"FunctionArn": "arn:fn", "Runtime": "python3.13",
                             "VpcConfig": {"VpcId": "vpc-1", "SubnetIds": ["subnet-1"], "SecurityGroupIds": [SG, SG2]}},
        ("no-vpc", None): {"FunctionArn": "arn:fn2", "VpcConfig": {"SecurityGroupIds": []}},
    })
    out, entries, warnings = sgm.resolve_workloads(lambda region: FakeSession({"lambda": lam}),
                                                   [("us-east-1", "lambda:in-vpc:live"), ("us-east-1", "lambda:no-vpc"),
                                                    ("us-east-1", SG)])
    assert out == [("us-east-1", SG), ("us-east-1", SG2)]
    assert [(e["id"], e["kind"], e["vpc_id"], e["groups"]) for e in entries] == \
        [("in-vpc:live", "lambda", "vpc-1", [SG, SG2])]
    assert entries[0]["description"] == "Lambda python3.13, subnets subnet-1"
    assert warnings == ["Lambda no-vpc: not attached to a VPC, so no security groups apply; skipped"]


# --------------------------------------------------------------------------- #
# moto-backed loading
# --------------------------------------------------------------------------- #
@pytest.fixture
def ec2_env():
    with mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
        a = ec2.create_security_group(GroupName="web", Description="web tier", VpcId=vpc)["GroupId"]
        b = ec2.create_security_group(GroupName="db", Description="db tier", VpcId=vpc)["GroupId"]
        pl = ec2.create_managed_prefix_list(PrefixListName="corp", AddressFamily="IPv4", MaxEntries=5,
                                            Entries=[{"Cidr": "192.168.0.0/24"}, {"Cidr": "192.168.1.0/24"}]
                                            )["PrefixList"]["PrefixListId"]
        ec2.authorize_security_group_ingress(GroupId=a, IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]},
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "PrefixListIds": [{"PrefixListId": pl}]},
            {"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": a}]},
        ])
        ec2.authorize_security_group_ingress(GroupId=b, IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "UserIdGroupPairs": [{"GroupId": a}]}])
        yield {"ec2": ec2, "vpc": vpc, "subnet": subnet, "a": a, "b": b, "pl": pl}


def session_factory(region):
    return boto3.Session(region_name=region)


def test_load_groups_moto(ec2_env):
    a, b, pl = ec2_env["a"], ec2_env["b"], ec2_env["pl"]
    groups, rules, warnings = sgm.load_groups(session_factory, [("us-east-1", b), ("us-east-1", a)])
    assert [g.group_id for g in groups] == [b, a]                  # argument order
    assert (groups[1].name, groups[1].vpc_id, groups[1].region) == ("web", ec2_env["vpc"], "us-east-1")
    assert str(groups[1]) == f"{a} (web, {ec2_env['vpc']}, us-east-1)"
    assert warnings == []
    by_peer = {r.peer: r for r in rules[a] if not r.egress}
    assert set(by_peer) == {"10.0.0.0/8", pl, "self"}
    assert by_peer[pl].peer_label == "corp, 2 entries"
    assert sorted(sp for sp, _ in by_peer[pl].boxes) == ["ipv4", "ipv4"]
    assert by_peer["self"].boxes == [("sg:self", (ALL_PROTOS, ALL_PORTS, (0, 0)))]
    assert [str(r) for r in rules[b] if not r.egress] == [f"tcp 5432 from {a}"]
    # sorted by direction first: every ingress rule before every egress rule
    assert [r.egress for r in rules[a]] == sorted(r.egress for r in rules[a])


def test_load_groups_unknown_group_raises(ec2_env):
    with pytest.raises(ValueError, match="us-east-1"):
        sgm.load_groups(session_factory, [("us-east-1", "sg-0aaaaaaaaaaaaaaa0")])


class FakePaginator:
    def __init__(self, fn):
        self.fn = fn

    def paginate(self, **kw):
        return self.fn(**kw)


class FakePlEc2:
    """describe/get prefix list entries; 'pl-denied' raises AccessDenied."""
    def __init__(self, lists):
        self.lists = lists

    def get_paginator(self, op):
        def describe(PrefixListIds):
            if "pl-denied" in PrefixListIds:
                raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, op)
            return [{"PrefixLists": [{"PrefixListId": i, "PrefixListName": self.lists[i][0]} for i in PrefixListIds]}]

        def entries(PrefixListId):
            if PrefixListId == "pl-denied":
                raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, op)
            return [{"Entries": [{"Cidr": c} for c in self.lists[PrefixListId][1]]}]
        return FakePaginator({"describe_managed_prefix_lists": describe, "get_managed_prefix_list_entries": entries}[op])


def test_fetch_prefix_lists_unreadable():
    ec2 = FakePlEc2({"pl-1": ("corp", ["10.0.0.0/8", "10.1.0.0/16"])})
    entries, names, errors = sgm.fetch_prefix_lists(ec2, {"pl-1", "pl-denied"})
    assert entries == {"pl-1": ["10.0.0.0/8", "10.1.0.0/16"], "pl-denied": None}
    assert names == {}                     # one bad id fails the whole describe call; names are best effort
    assert errors == ["pl-denied: AccessDenied"]
    assert sgm.fetch_prefix_lists(ec2, set()) == ({}, {}, [])
    entries, names, errors = sgm.fetch_prefix_lists(ec2, {"pl-1"})
    assert names == {"pl-1": "corp"} and errors == []


def test_resolve_workloads_eni_and_instance(ec2_env):
    ec2 = ec2_env["ec2"]
    eni = ec2.create_network_interface(SubnetId=ec2_env["subnet"], Groups=[ec2_env["a"], ec2_env["b"]],
                                       Description="app nic")["NetworkInterface"]["NetworkInterfaceId"]
    inst = ec2.run_instances(ImageId="ami-12c6146b", MinCount=1, MaxCount=1, SubnetId=ec2_env["subnet"],
                             SecurityGroupIds=[ec2_env["b"]],
                             TagSpecifications=[{"ResourceType": "instance",
                                                 "Tags": [{"Key": "Name", "Value": "db-1"}]}]
                             )["Instances"][0]["InstanceId"]
    out, entries, warnings = sgm.resolve_workloads(session_factory, [("us-east-1", eni), ("us-east-1", inst)])
    assert out == [("us-east-1", ec2_env["a"]), ("us-east-1", ec2_env["b"])]   # b only once
    assert warnings == []
    assert entries[0]["kind"] == "eni" and entries[0]["description"] == "app nic"
    assert entries[1]["kind"] == "instance" and entries[1]["attachment"] == f"{inst} eth0"
    assert entries[1]["description"] == "db-1" and entries[1]["groups"] == [ec2_env["b"]]


def test_resolve_workloads_missing_eni(ec2_env):
    with pytest.raises(ValueError, match="us-east-1"):
        sgm.resolve_workloads(session_factory, [("us-east-1", "eni-0aaaaaaaaaaaaaaa0")])
