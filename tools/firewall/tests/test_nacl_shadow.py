import argparse
import ipaddress
import json

import boto3
import pytest
from moto import mock_aws

from conftest import run_main, load_tool
from lib.accounts import Target

ns = load_tool("nacl_shadow")


def e(number, action, cidr, proto="6", ports=None, icmp=None, egress=False):
    entry = {"RuleNumber": number, "RuleAction": action, "Protocol": proto, "Egress": egress}
    entry["Ipv6CidrBlock" if ":" in cidr else "CidrBlock"] = cidr
    if ports:
        entry["PortRange"] = {"From": ports[0], "To": ports[1]}
    if icmp:
        entry["IcmpTypeCode"] = {"Type": icmp[0], "Code": icmp[1]}
    return entry


def codes(entries):
    return [(code, r.number, [o.number for o in hits]) for code, r, hits, _ in ns.analyze_entries(entries)]


def test_from_api_text_and_box():
    r = ns.NaclRule.from_api(e(100, "ALLOW", "10.1.2.3/8", ports=(443, 443)))
    assert r.text == "#100 ingress allow tcp 443 10.0.0.0/8"
    assert (r.space, r.action, r.direction) == ("ipv4", "allow", "ingress")
    v6 = ns.NaclRule.from_api(e(5, "deny", "2001:db8::/32", proto="-1", egress=True))
    assert v6.text == "#5 egress deny all traffic 2001:db8::/32" and v6.space == "ipv6"
    icmp = ns.NaclRule.from_api(e(7, "allow", "0.0.0.0/0", proto="1", icmp=(8, -1)))
    assert icmp.text == "#7 ingress allow icmp type 8 0.0.0.0/0"
    assert ns.NaclRule.from_api({"RuleNumber": 1, "Protocol": "-1"}) is None


def test_shadowed_conflict():
    assert codes([e(100, "allow", "10.0.0.0/8", ports=(443, 443)),
                  e(200, "deny", "10.1.0.0/16", ports=(443, 443))]) == [("SHADOWED_CONFLICT", 200, [100])]


def test_redundant_same_action():
    out = ns.analyze_entries([e(100, "allow", "0.0.0.0/0", ports=(0, 65535)), e(110, "allow", "10.0.0.0/8", ports=(22, 22))])
    assert [(c, r.number, eff) for c, r, _, eff in out] == [("REDUNDANT", 110, [])]


def test_partially_shadowed_lists_what_still_matches():
    out = ns.analyze_entries([e(100, "deny", "10.0.0.0/16", ports=(22, 22)),
                              e(200, "allow", "10.0.0.0/8", ports=(22, 22))])
    [(code, rule, hits, effective)] = out
    assert (code, rule.number, [h.number for h in hits]) == ("PARTIALLY_SHADOWED", 200, [100])
    want = sorted(ipaddress.ip_network("10.0.0.0/8").address_exclude(ipaddress.ip_network("10.0.0.0/16")))
    assert effective == ["tcp 22 " + ", ".join(map(str, want))]


def test_partial_overlap_same_action_and_port_remainder():
    out = ns.analyze_entries([e(100, "allow", "10.0.0.0/8", ports=(80, 90)),
                              e(200, "allow", "10.0.0.0/8", ports=(85, 100))])
    assert [(c, eff) for c, _, _, eff in out] == [("PARTIAL_OVERLAP_SAME_ACTION", ["tcp 91-100 10.0.0.0/8"])]


def test_rule_number_order_not_list_order():
    assert codes([e(200, "deny", "10.1.0.0/16", ports=(443, 443)),
                  e(100, "allow", "10.0.0.0/8", ports=(443, 443))]) == [("SHADOWED_CONFLICT", 200, [100])]


def test_all_traffic_deny_shadows_tcp_allow():
    assert codes([e(10, "deny", "0.0.0.0/0", proto="-1"), e(20, "allow", "10.0.0.0/8", ports=(443, 443))]) == \
        [("SHADOWED_CONFLICT", 20, [10])]


def test_icmp_type_covers_specific_code():
    assert codes([e(100, "allow", "0.0.0.0/0", proto="1", icmp=(8, -1)),
                  e(200, "deny", "10.0.0.0/8", proto="1", icmp=(8, 0)),
                  e(300, "deny", "10.0.0.0/8", proto="1", icmp=(0, 0))]) == [("SHADOWED_CONFLICT", 200, [100])]


def test_directions_and_address_families_are_separate():
    assert codes([e(100, "deny", "0.0.0.0/0", proto="-1", egress=True),
                  e(200, "allow", "10.0.0.0/8", ports=(443, 443)),                 # ingress: not hidden by egress
                  e(300, "allow", "::/0", proto="-1", egress=True)]) == []         # ipv6: not hidden by ipv4


def test_default_rules_are_ignored():
    entries = [e(32767, "deny", "0.0.0.0/0", proto="-1"), e(32768, "deny", "::/0", proto="-1"),
               e(100, "allow", "10.0.0.0/8", ports=(443, 443))]
    assert codes(entries) == []


def test_ipv6_partial_shadow():
    out = ns.analyze_entries([e(10, "deny", "2001:db8::/33", proto="-1"), e(20, "allow", "2001:db8::/32", proto="-1")])
    assert [(c, eff) for c, _, _, eff in out] == [("PARTIALLY_SHADOWED", ["all traffic 2001:db8:8000::/33"])]


def nargs(**kw):
    return argparse.Namespace(**{"vpc": None, "nacl": None, "fmmanaged_only": False, **kw})


def test_nacl_filters():
    nacl = {"VpcId": "vpc-1", "NetworkAclId": "acl-1", "Tags": [{"Key": "FMManaged", "Value": "TRUE"}]}
    assert ns.is_fmmanaged(nacl) and not ns.is_fmmanaged({"Tags": None})
    assert ns.nacl_matches(nacl, nargs())
    assert ns.nacl_matches(nacl, nargs(vpc=["vpc-1"], nacl=["acl-1"], fmmanaged_only=True))
    assert not ns.nacl_matches(nacl, nargs(vpc=["vpc-2"]))
    assert not ns.nacl_matches(nacl, nargs(nacl=["acl-2"]))
    assert not ns.nacl_matches({**nacl, "Tags": []}, nargs(fmmanaged_only=True))


@pytest.mark.parametrize("target,code", [(Target("1", None, False, "no local profile"), "NO_PROFILE"),
                                         (Target("1", "p", False, "profile p resolves to 2"), "PROFILE_ACCOUNT_MISMATCH"),
                                         (Target("1", "p", False, "profile p: expired"), "ACCOUNT_ERROR")])
def test_unscannable(target, code):
    f = ns.unscannable(target)
    assert (f.severity, f.code, f.account, f.detail) == ("error", code, "1", target.note)


def test_run_skips_unusable_accounts_and_counts_dead_rules(monkeypatch):
    def fake_scan(t, region, args, stats):
        stats["nacls"] += 1
        return [ns.Finding("warn", "REDUNDANT", account=t.account, region=region, rule_number=5),
                ns.Finding("info", "PARTIAL_OVERLAP_SAME_ACTION", account=t.account, region=region, rule_number=3)]
    monkeypatch.setattr(ns, "scan", fake_scan)
    findings, stats = ns.run(nargs(), [Target("2", "p"), Target("1", None, False, "no local profile")], ["r1", "r2"])
    assert (stats["accounts"], stats["accounts_skipped"], stats["nacls"], stats["dead_rules"]) == (1, 1, 2, 2)
    assert stats["by_code"] == {"NO_PROFILE": 1, "REDUNDANT": 2, "PARTIAL_OVERLAP_SAME_ACTION": 2}
    assert [(f.account, f.region, f.rule_number) for f in findings][:3] == [("1", "", ""), ("2", "r1", 3), ("2", "r1", 5)]


# --------------------------------------------------------------------------- #
# moto end to end
# --------------------------------------------------------------------------- #
def test_main_moto(monkeypatch, capsys, tmp_path):
    with mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        acl = ec2.create_network_acl(VpcId=vpc, TagSpecifications=[{"ResourceType": "network-acl", "Tags": [
            {"Key": "FMManaged", "Value": "true"}]}])["NetworkAcl"]["NetworkAclId"]
        for n, action, cidr in ((100, "allow", "10.0.0.0/8"), (200, "deny", "10.1.0.0/16")):
            ec2.create_network_acl_entry(NetworkAclId=acl, RuleNumber=n, Protocol="6", RuleAction=action,
                                         Egress=False, CidrBlock=cidr, PortRange={"From": 443, "To": 443})
        html = tmp_path / "r.html"
        rc = run_main(ns, monkeypatch, ["--region", "us-east-1", "--fmmanaged-only", "--json", "--no-save",
                                        "--html-out", str(html), "-q"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert out["stats"]["nacls"] == 1 and out["stats"]["dead_rules"] == 1
    [f] = out["findings"]
    assert (f["code"], f["nacl_id"], f["vpc_id"], f["fmmanaged"], f["account"]) == \
        ("SHADOWED_CONFLICT", acl, vpc, "yes", "123456789012")
    assert f["shadowed_by"] == ["#100 ingress allow tcp 443 10.0.0.0/8"]
    assert "NACL shadowed rules" in html.read_text()


def test_print_report(capsys):
    f = ns.Finding("warn", "PARTIALLY_SHADOWED", account="1", profile="p", region="r", nacl_id="acl-1",
                   vpc_id="vpc-1", direction="ingress", rule="#200 ingress allow tcp 22 10.0.0.0/8",
                   shadowed_by=["#100 ..."], effective=["tcp 22 " + ", ".join(f"10.{i}.0.0/16" for i in range(10))],
                   detail="d")
    info = ns.Finding("info", "PARTIAL_OVERLAP_SAME_ACTION", account="1", region="r", nacl_id="acl-1")
    ns.print_report([f, info], {"accounts": 1, "accounts_skipped": 0, "regions": 1, "nacls": 1, "rules": 2,
                                "dead_rules": 0, "by_code": {"PARTIALLY_SHADOWED": 1}}, show_info=False)
    out = capsys.readouterr().out
    assert "earlier: #100 ..." in out
    assert "... 2 more (see CSV/JSON)" in out
    assert "(1 info findings hidden; --show-info to list)" in out
