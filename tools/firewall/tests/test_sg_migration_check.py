import json

import boto3
import pytest
from moto import mock_aws

from conftest import load_tool, run_main
from lib.security_groups import SG, SgRule

smc = load_tool("sg_migration_check")
_n = iter(range(10000))


def rule(gid, peer, fp=443, tp=443, proto="tcp", egress=False, desc=""):
    d = {"GroupId": gid, "SecurityGroupRuleId": f"sgr-{next(_n)}", "IsEgress": egress, "IpProtocol": proto,
         "FromPort": fp, "ToPort": tp, "Description": desc}
    if peer.startswith("sg-"):
        d["ReferencedGroupInfo"] = {"GroupId": peer}
    else:
        d["CidrIpv4"] = peer
    r = SgRule.from_api(d)
    r.expand({})
    return r


def eni(groups, vpc="vpc-1", **kw):
    return {"NetworkInterfaceId": kw.pop("id", "eni-1"), "VpcId": vpc, "Groups": [{"GroupId": g} for g in groups], **kw}


GROUPS = {g: SG(g, g, "vpc-1", "1", "r") for g in ("sg-old", "sg-new", "sg-other")}
GROUPS["sg-far"] = SG("sg-far", "far", "vpc-2", "1", "r")
RENAME = {"sg:sg-old": "sg:sg-new"}


# --------------------------------------------------------------------------- #
# access arithmetic
# --------------------------------------------------------------------------- #
def test_access_of_unions_and_renames():
    rules = {"sg-a": [rule("sg-a", "10.0.0.0/9"), rule("sg-a", "10.128.0.0/9"), rule("sg-a", "sg-old"),
                      rule("sg-a", "0.0.0.0/0", egress=True)]}
    acc = smc.access_of(["sg-a", "sg-missing"], rules, False, RENAME)
    assert set(acc) == {"ipv4", "sg:sg-new"}
    assert smc.fmt_access(acc, False) == ["tcp 443 from 10.0.0.0/8, sg-new"]
    assert smc.fmt_access(acc, False, RENAME) == ["tcp 443 from 10.0.0.0/8, sg-new / sg-old"]
    assert smc.fmt_access(smc.access_of(["sg-a"], rules, True, {}), True) == ["tcp 443 to 0.0.0.0/0"]


def test_fmt_access_summarizes_broad_ranges():
    acc = smc.minus(smc.access_of(["a"], {"a": [rule("a", "10.0.0.0/8"), rule("a", "192.168.0.0/16")]}, False, {}),
                    smc.access_of(["b"], {"b": [rule("b", "10.1.2.0/24"), rule("b", "10.0.0.0/30"),
                                                rule("b", "192.168.4.0/24")]}, False, {}))
    # the /8 is named, not enumerated (its piece below 10.1.2.0 is not listed again); a /16 is enumerated
    assert smc.fmt_access(acc, False) == [
        "tcp 443 from part of 10.0.0.0/8, 192.168.0.0/22, 192.168.5.0/24, 192.168.6.0/23, 192.168.8.0/21, "
        "192.168.16.0/20, 192.168.32.0/19, 192.168.64.0/18, 192.168.128.0/17"]
    # a single broad CIDR, or two ranges each a CIDR, are shown as they are
    assert smc.fmt_ranges("ipv4", [(167772160, 176160767)]) == ["10.0.0.0/9"]
    assert smc.fmt_ranges("ipv4", [(167772160, 167772415), (184549120, 184549375)]) == ["10.0.0.0/24", "10.255.255.0/24"]
    # IPv6 is summarized above a /48
    v6 = smc.fmt_ranges("ipv6", [(0x20010db8 << 96, (0x20010db8 << 96) + (1 << 80) * 3 - 1)])
    assert v6 == ["part of 2001:db8::/46"]
    assert smc.fmt_ranges("sg:sg-1", [(0, 0)]) == ["sg-1"]


def test_minus():
    a = smc.access_of(["g"], {"g": [rule("g", "10.0.0.0/8", 80, 90), rule("g", "sg-x")]}, False, {})
    b = smc.access_of(["g"], {"g": [rule("g", "10.0.0.0/9", 80, 90)]}, False, {})
    gone = smc.minus(a, b)
    assert smc.fmt_access(gone, False) == ["tcp 80-90 from 10.128.0.0/9", "tcp 443 from sg-x"]
    assert smc.minus(b, a) == {}


def test_responsible():
    rules = {"sg-old": [rule("sg-old", "10.0.0.0/8", desc="app"), rule("sg-old", "192.168.0.0/16", fp=22, tp=22)]}
    gone = smc.access_of(["sg-old"], {"sg-old": rules["sg-old"][:1]}, False, {})   # only the 443 rule
    [line] = smc.responsible(gone, ["sg-old"], rules, False, {})
    assert line.startswith("sg-old sgr-") and line.endswith('tcp 443 from 10.0.0.0/8 "app"')


@pytest.mark.parametrize("n,out", [
    ({"Attachment": {"InstanceId": "i-1"}}, ("ec2-instance", "i-1")),
    ({"InterfaceType": "lambda", "Description": "AWS Lambda VPC ENI-my-fn-1a2b3c4d-1111-2222-3333-444455556666"},
     ("lambda", "my-fn")),
    ({"Description": "AWS Lambda VPC ENI-short"}, ("lambda", "short")),
    ({"Description": "ELB app/my-alb/123"}, ("load-balancer", "app/my-alb/123")),
    ({"Description": "RDSNetworkInterface"}, ("rds", "RDSNetworkInterface")),
    ({"InterfaceType": "vpc_endpoint", "Description": "VPC Endpoint Interface vpce-123"}, ("vpc-endpoint", "vpce-123")),
    ({"Description": "EFS mount target for fs-1"}, ("efs", "EFS mount target for fs-1")),
    ({"RequesterManaged": True, "RequesterId": "amazon-elb", "Description": ""}, ("managed (amazon-elb)", "eni-9")),
    ({}, ("interface", "eni-9")),
])
def test_resource_of(n, out):
    assert smc.resource_of({"NetworkInterfaceId": "eni-9", **n}) == out


# --------------------------------------------------------------------------- #
# review
# --------------------------------------------------------------------------- #
def rules_with(old, new, other=()):
    return {"sg-old": old, "sg-new": new, "sg-other": list(other), "sg-far": []}


def review(groups, rules, news=("sg-new",)):
    return smc.review(eni(groups), "1", "r", ["sg-old"], list(news), GROUPS, rules, RENAME)


def test_review_ready():
    rules = rules_with([rule("sg-old", "10.0.0.0/8")], [rule("sg-new", "10.0.0.0/8")])
    r = review(["sg-old", "sg-new"], rules)
    assert (r.status, r.severity, r.lost, r.old_attached, r.new_attached, r.new_missing) == \
        ("READY", "info", [], ["sg-old"], ["sg-new"], [])


def test_review_access_lost():
    rules = rules_with([rule("sg-old", "10.0.0.0/8"), rule("sg-old", "10.0.0.0/8", 22, 22)], [rule("sg-new", "10.0.0.0/8")])
    r = review(["sg-old", "sg-new"], rules)
    assert (r.status, r.severity) == ("ACCESS_LOST", "error")
    assert r.lost == ["[ingress] tcp 22 from 10.0.0.0/8"]
    assert len(r.lost_rules) == 1 and r.lost_rules[0].endswith("tcp 22 from 10.0.0.0/8")


def test_review_new_not_attached():
    rules = rules_with([rule("sg-old", "10.0.0.0/8")], [rule("sg-new", "10.0.0.0/8")])
    r = review(["sg-old"], rules)
    assert (r.status, r.new_missing, r.lost, r.projected_lost) == \
        ("NEW_NOT_ATTACHED", ["sg-new"], ["[ingress] tcp 443 from 10.0.0.0/8"], [])
    assert r.detail.endswith("; with the new group attached nothing would be lost")
    rules = rules_with([rule("sg-old", "10.0.0.0/8")], [rule("sg-new", "10.0.0.0/9"), rule("sg-new", "1.1.1.1/32", 53, 53)])
    r = review(["sg-old"], rules)
    assert r.projected_lost == ["[ingress] tcp 443 from 10.128.0.0/9"]
    assert r.projected_gained == ["[ingress] tcp 53 from 1.1.1.1/32"]
    assert not r.detail.endswith("nothing would be lost")


def test_review_old_redundant():
    rules = rules_with([rule("sg-old", "10.1.0.0/16")], [], [rule("sg-other", "10.0.0.0/8")])
    r = review(["sg-old", "sg-other"], rules)
    assert (r.status, r.severity, r.lost) == ("OLD_REDUNDANT", "warn", [])


def test_review_new_group_in_other_vpc():
    rules = rules_with([], [])
    r = review(["sg-old"], rules, news=("sg-far",))
    assert (r.status, r.severity) == ("NEW_IN_OTHER_VPC", "error")
    assert r.detail == "sg-far is in vpc-2, not the resource's VPC; cannot be attached here"


def test_review_reference_to_old_counts_as_new():
    # sg-other allows "from sg-old"; after the migration that reference reads as sg-new: nothing lost
    rules = rules_with([rule("sg-old", "10.0.0.0/8")], [rule("sg-new", "10.0.0.0/8")], [rule("sg-other", "sg-old", 5432, 5432)])
    r = review(["sg-old", "sg-new", "sg-other"], rules)
    assert r.status == "READY"


def test_change_groups_merges_identical_changes():
    rules = rules_with([rule("sg-old", "10.0.0.0/8")], [rule("sg-new", "10.0.0.0/8")])
    rows = [smc.review(eni(["sg-old"], id=f"eni-{i}", Attachment={"InstanceId": f"i-{i}"}), "1", "r", ["sg-old"],
                       ["sg-new"], GROUPS, rules, RENAME) for i in range(2)]
    rows.append(smc.review(eni(["sg-old", "sg-new"], id="eni-9", RequesterManaged=True, RequesterId="amazon-elb"),
                           "1", "r", ["sg-old"], ["sg-new"], GROUPS, rules, RENAME))
    out = smc.change_groups(rows)
    assert [(g["change_group"], g["status"], g["count"]) for g in out] == [("G1", "NEW_NOT_ATTACHED", 2), ("G2", "READY", 1)]
    assert out[0]["resources"] == ["ec2-instance i-0 (eni-0, vpc-1)", "ec2-instance i-1 (eni-1, vpc-1)"]
    assert out[1]["detail"].endswith("; requester-managed interfaces are changed through their service")
    assert [r.change_group for r in rows] == ["G1", "G1", "G2"]


def test_check_references():
    def api(gid, peer, rid, fp=443, egress=False):
        return {"GroupId": gid, "SecurityGroupRuleId": rid, "IsEgress": egress, "IpProtocol": "tcp", "FromPort": fp,
                "ToPort": fp, "ReferencedGroupInfo": {"GroupId": peer}}
    by_group = {"sg-x": [api("sg-x", "sg-old", "r1"), api("sg-x", "sg-new", "r2"),
                         api("sg-x", "sg-old", "r3", fp=22), api("sg-x", "sg-unrelated", "r4")]}
    out = smc.check_references(by_group, ["sg-old"], "1", "r", RENAME)
    assert [(x["rule_id"], x["status"], x["severity"]) for x in out] == \
        [("r1", "REFERENCE_MIRRORED", "info"), ("r3", "REFERENCE_NOT_MIRRORED", "warn")]
    out = smc.check_references(by_group, ["sg-old"], "1", "r", {})
    assert {x["status"] for x in out} == {"REFERENCE_NOT_MIRRORED"}
    assert "no matching rule references a new group" in out[0]["detail"]


def test_cut():
    long = "tcp 1 from " + ", ".join(f"10.0.0.{i}/32" for i in range(10))
    assert smc.cut([long, "tcp 2 to a"]) == [
        "tcp 1 from " + ", ".join(f"10.0.0.{i}/32" for i in range(8)) + ", ... 2 more", "tcp 2 to a"]


# --------------------------------------------------------------------------- #
# moto end to end
# --------------------------------------------------------------------------- #
def test_main_moto(monkeypatch, capsys, tmp_path):
    with mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
        mk = lambda n: ec2.create_security_group(GroupName=n, Description=n, VpcId=vpc)["GroupId"]  # noqa: E731
        old, new, client = mk("old"), mk("new"), mk("client")
        for g in (old, new):
            ec2.authorize_security_group_ingress(GroupId=g, IpPermissions=[
                {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}])
        ec2.authorize_security_group_egress(GroupId=client, IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "UserIdGroupPairs": [{"GroupId": old}]}])
        both = ec2.create_network_interface(SubnetId=subnet, Groups=[old, new])["NetworkInterface"]["NetworkInterfaceId"]
        only_old = ec2.create_network_interface(SubnetId=subnet, Groups=[old])["NetworkInterface"]["NetworkInterfaceId"]
        html = tmp_path / "m.html"
        rc = run_main(smc, monkeypatch, ["--old", old, "--new", new, "--json", "--no-save", "--html-out", str(html), "-q"])
        payload = json.loads(capsys.readouterr().out)
        assert rc == 1
        status = {r["eni_id"]: r["status"] for r in payload["resources"]}
        assert status == {both: "READY", only_old: "NEW_NOT_ATTACHED"}
        assert payload["rename"] == {old: new}
        assert [(x["group_id"], x["status"]) for x in payload["references"]] == [(client, "REFERENCE_NOT_MIRRORED")]
        assert html.exists()

        assert run_main(smc, monkeypatch, ["--old", old, "--new", old, "--no-save", "-q"]) == 2   # both old and new
        capsys.readouterr()
        assert run_main(smc, monkeypatch, ["--old", old, "--new", new, "--no-save", "--show-changes"]) == 1
        assert "NEW_NOT_ATTACHED" in capsys.readouterr().out
