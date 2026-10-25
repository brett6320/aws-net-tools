import json

import boto3
from moto import mock_aws

from conftest import load_tool, run_main
from lib.security_groups import SG, SgRule

gap = load_tool("sg_access_gap")

LEFT = SG("sg-left", "left", "vpc-1", "111111111111", "us-east-1")
RIGHT = SG("sg-right", "right", "vpc-1", "111111111111", "us-east-1")
_n = iter(range(1000))


def rule(gid, peer, proto="tcp", fp=443, tp=443, egress=False, pls=None, desc=""):
    d = {"GroupId": gid, "SecurityGroupRuleId": f"sgr-{next(_n)}", "IsEgress": egress, "IpProtocol": proto,
         "FromPort": fp, "ToPort": tp, "Description": desc}
    if peer.startswith("pl-"):
        d["PrefixListId"] = peer
    elif peer.startswith("sg-"):
        d["ReferencedGroupInfo"] = {"GroupId": peer}
    else:
        d["CidrIpv4" if ":" not in peer else "CidrIpv6"] = peer
    r = SgRule.from_api(d)
    r.expand(pls or {})
    return r


def compare(left_rules, right_rules):
    return gap.compare_rules(left_rules, right_rules, LEFT, [RIGHT], "ingress")


def test_identical_ignores_description():
    [f] = compare([rule("sg-left", "10.0.0.0/8", desc="a")], [rule("sg-right", "10.0.0.0/8", desc="b")])
    assert (f.severity, f.code) == ("info", "IDENTICAL")
    assert f.related[0].startswith("sg-right sgr-")


def test_covered_by_wider_rule():
    [f] = compare([rule("sg-left", "10.1.0.0/16")], [rule("sg-right", "10.0.0.0/8", fp=0, tp=1000)])
    assert (f.code, f.uncovered) == ("COVERED", [])
    assert f.detail == "fully granted by different rule(s) in sg-right"


def test_covered_by_several_rules_combined():
    [f] = compare([rule("sg-left", "10.0.0.0/8", fp=80, tp=443)],
                  [rule("sg-right", "10.0.0.0/9", fp=80, tp=443), rule("sg-right", "10.128.0.0/9", fp=0, tp=65535)])
    assert f.code == "COVERED" and len(f.related) == 2


def test_partial_lists_uncovered_addresses_and_ports():
    [f] = compare([rule("sg-left", "10.0.0.0/8", fp=80, tp=90)], [rule("sg-right", "10.0.0.0/9", fp=80, tp=85)])
    assert (f.severity, f.code) == ("error", "PARTIAL")
    assert f.uncovered == ["tcp 80-85 from 10.128.0.0/9", "tcp 86-90 from 10.0.0.0/8"]


def test_missing_and_prefix_list_notes():
    fs = compare([rule("sg-left", "10.0.0.0/8", fp=22, tp=22), rule("sg-left", "pl-1", fp=22, tp=22)],
                 [rule("sg-right", "10.0.0.0/8")])
    assert [f.code for f in fs] == ["MISSING", "MISSING"]
    assert fs[0].uncovered == ["tcp 22 from 10.0.0.0/8"]
    assert fs[1].uncovered == ["tcp 22 from pl-1"]
    assert fs[1].detail == "nothing in sg-right grants any of this; prefix list unresolved, compared by id only"


def test_resolved_prefix_list_compared_by_cidrs():
    pls = {"pl-1": ["10.1.0.0/16", "10.2.0.0/16"]}
    [f] = compare([rule("sg-left", "pl-1", pls=pls)], [rule("sg-right", "10.0.0.0/8")])
    assert f.code == "COVERED"


def test_group_reference_matched_by_id():
    fs = compare([rule("sg-left", "sg-other"), rule("sg-left", "sg-third")], [rule("sg-right", "sg-other", fp=0, tp=65535)])
    assert sorted(f.code for f in fs) == ["COVERED", "MISSING"]


def test_ipv6_not_covered_by_ipv4():
    [f] = compare([rule("sg-left", "::/0")], [rule("sg-right", "0.0.0.0/0", proto="-1", fp=-1, tp=-1)])
    assert f.code == "MISSING" and f.uncovered == ["tcp 443 from ::/0"]


def test_sort_order_errors_first_missing_before_partial():
    fs = compare([rule("sg-left", "10.0.0.0/8"), rule("sg-left", "10.0.0.0/7", fp=1, tp=1),
                  rule("sg-left", "10.0.0.0/8", fp=8080, tp=8080)],
                 [rule("sg-right", "10.0.0.0/8"), rule("sg-right", "10.0.0.0/8", fp=1, tp=1)])
    assert [f.code for f in fs] == ["MISSING", "PARTIAL", "IDENTICAL"]


def test_fmt_remainder_egress():
    r = rule("sg-left", "10.0.0.0/8", egress=True)
    assert gap.fmt_remainder({"ipv4": [b for _, b in r.boxes]}, True) == ["tcp 443 to 10.0.0.0/8"]


def test_diff_groups_verdicts():
    rules = {"sg-left": [rule("sg-left", "10.0.0.0/8"), rule("sg-left", "10.1.0.0/16", fp=22, tp=22, egress=True)],
             "sg-right": [rule("sg-right", "10.0.0.0/9"), rule("sg-right", "10.0.0.0/8", fp=22, tp=22, egress=True)]}
    findings, [row] = gap.diff_groups([LEFT, RIGHT], rules)
    assert row == {"left": "sg-left", "right": "sg-right", "ingress": "1 gap(s)", "egress": "covered"}
    rules = {"sg-left": [rule("sg-left", "10.0.0.0/8")], "sg-right": [rule("sg-right", "10.0.0.0/8")]}
    assert gap.diff_groups([LEFT, RIGHT], rules)[1][0]["ingress"] == "identical"
    assert gap.diff_groups([LEFT, RIGHT], rules)[1][0]["egress"] == "identical"   # nothing to compare


def test_verdict_class():
    assert gap.verdict_class("2 gap(s)") == "error"
    assert gap.verdict_class("covered") == "ok"


# --------------------------------------------------------------------------- #
# moto end to end
# --------------------------------------------------------------------------- #
def test_main_moto(monkeypatch, capsys, tmp_path):
    with mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        a = ec2.create_security_group(GroupName="old", Description="old", VpcId=vpc)["GroupId"]
        b = ec2.create_security_group(GroupName="new", Description="new", VpcId=vpc)["GroupId"]
        ec2.authorize_security_group_ingress(GroupId=a, IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
             "IpRanges": [{"CidrIp": "10.0.0.0/8", "Description": "<script>x</script>"}]},
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "192.168.0.0/24"}]}])
        ec2.authorize_security_group_ingress(GroupId=b, IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "10.0.0.0/9"}]}])
        html, csv_path = tmp_path / "g.html", tmp_path / "g.csv"
        rc = run_main(gap, monkeypatch, [a, b, "--json", "--no-save", "--html-out", str(html),
                                         "--csv-out", str(csv_path), "-q"])
        out = json.loads(capsys.readouterr().out)
        assert rc == 1
        assert out["account"] == "123456789012"
        assert out["summary"] == [{"left": a, "right": b, "ingress": "2 gap(s)", "egress": "identical"}]
        by_code = {f["code"]: f for f in out["findings"]}
        assert by_code["MISSING"]["uncovered"] == ["tcp 22 from 192.168.0.0/24"]
        assert by_code["PARTIAL"]["uncovered"] == ["tcp 443 from 10.128.0.0/9"]
        text = html.read_text()
        assert "<script>x</script>" not in text and "&lt;script&gt;x&lt;/script&gt;" in text
        assert csv_path.read_text().splitlines()[0] == ",".join(gap.CSV_COLUMNS)

        # identical groups -> exit 0; a single group -> fatal
        assert run_main(gap, monkeypatch, [b, b, "--no-save", "-q"]) == 2
        assert run_main(gap, monkeypatch, [a, a + "," + a, "--no-save", "-q"]) == 2
        capsys.readouterr()


def test_main_text_report(monkeypatch, capsys):
    with mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        a = ec2.create_security_group(GroupName="a", Description="a", VpcId=vpc)["GroupId"]
        b = ec2.create_security_group(GroupName="b", Description="b", VpcId=vpc)["GroupId"]
        assert run_main(gap, monkeypatch, [a, b, "--no-save", "--show-covered"]) == 0
    out = capsys.readouterr().out
    assert f"=== access in {a} absent from {b}" in out
    assert "IDENTICAL" in out
