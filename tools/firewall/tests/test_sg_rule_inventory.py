import hashlib
import json
import re

import boto3
import pytest
from moto import mock_aws

from conftest import load_tool, run_main
from lib.security_groups import SG, SgRule

inv = load_tool("sg_rule_inventory")
_n = iter(range(10000))


def rule(gid, peer, fp=443, tp=443, proto="tcp", egress=False, pls=None):
    d = {"GroupId": gid, "SecurityGroupRuleId": f"sgr-{next(_n)}", "IsEgress": egress, "IpProtocol": proto,
         "FromPort": fp, "ToPort": tp}
    if peer.startswith("pl-"):
        d["PrefixListId"] = peer
    elif peer.startswith("sg-"):
        d["ReferencedGroupInfo"] = {"GroupId": peer}
    else:
        d["CidrIpv4" if ":" not in peer else "CidrIpv6"] = peer
    r = SgRule.from_api(d)
    r.expand(pls or {})
    return r


def g(gid, vpc="vpc-1"):
    return SG(gid, f"name-{gid}", vpc, "111111111111", "us-east-1")


def test_also_granted_levels():
    r = rule("sg-a", "10.0.0.0/8")
    assert inv.also_granted(r, []) == ("no", [])
    level, hits = inv.also_granted(r, [rule("sg-b", "10.0.0.0/9"), rule("sg-b", "192.168.0.0/16")])
    assert level == "partly" and len(hits) == 1
    level, hits = inv.also_granted(r, [rule("sg-b", "10.0.0.0/9"), rule("sg-c", "10.128.0.0/9", 0, 65535)])
    assert level == "fully" and {h.group_id for h in hits} == {"sg-b", "sg-c"}


@pytest.mark.parametrize("proto,label", [("-1", "all"), ("tcp", "tcp"), ("6", "tcp"), ("58", "icmpv6"), ("50", "50")])
def test_proto_label(proto, label):
    assert inv.proto_label(rule("sg-a", "10.0.0.0/8", proto=proto, fp=-1, tp=-1)) == label


def test_rule_rows_compare_within_direction_only():
    rules = {"sg-a": [rule("sg-a", "10.0.0.0/8"), rule("sg-a", "10.0.0.0/8", egress=True)],
             "sg-b": [rule("sg-b", "10.0.0.0/8", 0, 65535)]}
    rows = inv.rule_rows([g("sg-a"), g("sg-b")], rules)
    assert [(r.group_id, r.direction, r.also_granted) for r in rows] == \
        [("sg-a", "ingress", "fully"), ("sg-a", "egress", "no"), ("sg-b", "ingress", "partly")]
    assert rows[0].overlaps == [f"sg-b (name-sg-b) {rules['sg-b'][0].rule_id} tcp all from 10.0.0.0/8"]
    assert (rows[0].access, rows[0].protocol, rows[0].peer_kind, rows[0].account) == ("tcp 443", "tcp", "ipv4", "111111111111")


def test_union_and_combined_access():
    rules = {"sg-a": [rule("sg-a", "10.0.0.0/9"), rule("sg-a", "sg-x")],
             "sg-b": [rule("sg-b", "10.128.0.0/9"), rule("sg-b", "2001:db8::/32", 22, 22)]}
    out = inv.combined_access([g("sg-a"), g("sg-b")], rules)
    assert [(c["direction"], c["access"], c["addresses"], c["granted_by"]) for c in out] == [
        ("ingress", "tcp 22", ["2001:db8::/32"], ["sg-b"]),
        ("ingress", "tcp 443", ["10.0.0.0/8", "sg-x"], ["sg-a", "sg-b"]),
    ]
    u = inv.union([("ipv4", b) for r in rules["sg-a"][:1] + rules["sg-b"][:1] for _, b in r.boxes])
    assert u == {"ipv4": [((6, 6), (443, 443), (167772160, 184549375))]}


def test_fix_self_refs_and_known_prefix_lists():
    rules = {"sg-a": [rule("sg-a", "sg-a"), rule("sg-a", "pl-ok", pls={"pl-ok": ["10.1.0.0/16", "10.0.0.0/16"]}),
                      rule("sg-a", "pl-unread")]}
    assert rules["sg-a"][0].peer == "self" and rules["sg-a"][0].boxes[0][0] == "sg:self"
    inv.fix_self_refs(rules)
    assert rules["sg-a"][0].boxes[0][0] == "sg:sg-a" and str(rules["sg-a"][0]) == "tcp 443 from self"
    assert inv.known_prefix_lists(rules) == {"pl-ok": ["10.0.0.0/16", "10.1.0.0/16"]}


def test_partition_tags_owners():
    a = {"ipv4": [((6, 6), (0, 10), (0, 0))]}
    b = {"ipv4": [((6, 6), (5, 20), (0, 0))]}
    parts = sorted((sp, box[1], sorted(who)) for sp, box, who in inv.partition({"e1": a, "e2": b}))
    assert parts == [("ipv4", (0, 4), ["e1"]), ("ipv4", (5, 10), ["e1", "e2"]), ("ipv4", (11, 20), ["e2"])]


def test_interface_deltas():
    rules = {"sg-a": [rule("sg-a", "10.0.0.0/8")], "sg-b": [rule("sg-b", "10.0.0.0/9")],
             "sg-c": [rule("sg-c", "10.0.0.0/8")]}
    nics = [{"id": "eni-1", "groups": ["sg-a"]}, {"id": "eni-2", "groups": ["sg-b"]}, {"id": "eni-3", "groups": ["sg-c"]}]
    d = inv.interface_deltas(nics, rules)
    assert d["interfaces"] == ["eni-1", "eni-2", "eni-3"]
    assert [x["group_id"] for x in d["groups"]] == ["sg-a", "sg-b", "sg-c"]
    [acc] = d["access"]
    assert (acc["access"], acc["addresses"], acc["allowed_on"], acc["missing_on"]) == \
        ("tcp 443", ["10.128.0.0/9"], ["eni-1", "eni-3"], ["eni-2"])
    assert len(acc["rules"]) == 2
    # same access written differently is not a difference
    same = inv.interface_deltas([{"id": "eni-1", "groups": ["sg-a"]}, {"id": "eni-3", "groups": ["sg-c"]}], rules)
    assert same["access"] == [] and len(same["groups"]) == 2
    assert inv.interface_deltas(nics[:1], rules) == {"interfaces": ["eni-1"], "groups": [], "access": []}


def test_tester_data_hash_and_escaping():
    groups = [g("sg-a")]
    rules = {"sg-a": [rule("sg-a", "2001:db8::/32")]}
    rules["sg-a"][0].description = "</script>"
    text, digest = inv.tester_data({"account": "1", "generated": "now"}, groups, rules, {})
    assert "<" not in text and hashlib.sha256(text.encode()).hexdigest() == digest
    data = json.loads(text)
    box = data["rules"][0]["boxes"][0]
    assert box[:5] == ["ipv6", 6, 6, 443, 443] and isinstance(box[5], str) and int(box[6]) > 2 ** 64
    assert data["rules"][0]["desc"] == "</script>"


def test_via_text_and_cut():
    one = {"accounts": [{"account": "1", "profile": "ro", "profile_source": "--profile"}]}
    assert inv.via_text(one) == "profile ro (--profile)"
    two = {"accounts": [{"account": "1", "profile": None, "profile_source": "x"},
                        {"account": "2", "profile": "b", "profile_source": "y"}]}
    assert inv.via_text(two) == "1 via default credentials; 2 via profile b (y)"
    assert inv.cut([str(i) for i in range(10)]) == "0, 1, 2, 3, 4, 5, 6, 7, ... 2 more"
    assert inv.cut(["a"]) == "a"


# --------------------------------------------------------------------------- #
# moto end to end
# --------------------------------------------------------------------------- #
def test_main_moto(monkeypatch, capsys, tmp_path):
    with mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
        a = ec2.create_security_group(GroupName="web", Description="web", VpcId=vpc)["GroupId"]
        b = ec2.create_security_group(GroupName="db", Description="db", VpcId=vpc)["GroupId"]
        ec2.authorize_security_group_ingress(GroupId=a, IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]},
            {"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": a}]}])
        ec2.authorize_security_group_ingress(GroupId=b, IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "10.1.0.0/16"}]}])
        e1 = ec2.create_network_interface(SubnetId=subnet, Groups=[a])["NetworkInterface"]["NetworkInterfaceId"]
        e2 = ec2.create_network_interface(SubnetId=subnet, Groups=[a, b])["NetworkInterface"]["NetworkInterfaceId"]

        html = tmp_path / "inv.html"
        assert run_main(inv, monkeypatch, [a, b, "--json", "--no-save", "--html-out", str(html), "-q"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert [x["group_id"] for x in payload["groups"]] == [a, b]
        levels = {(r["group_id"], r["peer"]): r["also_granted"] for r in payload["rules"] if r["direction"] == "ingress"}
        assert levels[(b, "10.1.0.0/16")] == "fully" and levels[(a, "10.0.0.0/8")] == "partly"
        page = html.read_text()
        m = re.search(r'<script id="extra-data" type="application/json">(.*?)</script>', page, re.S)
        assert hashlib.sha256(m.group(1).encode()).hexdigest() == payload["rule_data_sha256"]
        assert payload["rule_data_sha256"] in page

        # interfaces as targets: e2 has an extra group, so they differ -> exit 1
        assert run_main(inv, monkeypatch, [e1, e2, "--json", "--no-save", "-q"]) == 1
        payload = json.loads(capsys.readouterr().out)
        assert [x["id"] for x in payload["interfaces"]] == [e1, e2]
        assert payload["interface_deltas"]["groups"] == [{"group_id": b, "attached_to": [e2], "missing_on": [e1]}]
        assert run_main(inv, monkeypatch, ["sg-0aaaaaaaaaaaaaaa0", "--no-save", "-q"]) == 2
        assert run_main(inv, monkeypatch, [a, "--no-save", "--show-rules"]) == 0
        assert "tcp 443 from 10.0.0.0/8" in capsys.readouterr().out
