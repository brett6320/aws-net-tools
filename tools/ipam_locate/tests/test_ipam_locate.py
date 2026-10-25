import copy
import ipaddress
import json
import logging
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import il_core as core  # noqa: E402
import ipam_locate  # noqa: E402
from fake_ipam import STATE, FakeEC2, _res  # noqa: E402
from il_export import render_html  # noqa: E402


def bundle_for(q, ec2=None, regions=None):
    b = core.collect(ec2 or FakeEC2(), core.parse_query(q), regions=regions)
    return json.loads(json.dumps(b, default=str))


# ---------- query parsing / matching ----------

def test_parse_query_address_and_cidr():
    assert str(core.parse_query("10.1.2.3")) == "10.1.2.3/32"
    assert str(core.parse_query(" 10.1.0.0/16 ")) == "10.1.0.0/16"
    assert str(core.parse_query("2001:db8::1")) == "2001:db8::1/128"


@pytest.mark.parametrize("bad", ["10.1.2.3/16", "not-an-ip", "10.1.2.300", ""])
def test_parse_query_rejects(bad):
    with pytest.raises(core.ValidationError):
        core.parse_query(bad)


def test_relation():
    q = ipaddress.ip_network("10.1.1.0/24")
    assert core.relation("10.1.0.0/16", q) == core.CONTAINS
    assert core.relation("10.1.1.0/24", q) == core.CONTAINS
    assert core.relation("10.1.1.25/32", q) == core.WITHIN
    assert core.relation("10.2.0.0/16", q) is None
    assert core.relation("2001:db8::/32", q) is None
    assert core.relation("garbage", q) is None


# ---------- locate ----------

def test_private_ip_resolves_to_instance():
    loc = core.locate(bundle_for("10.1.1.25"))
    assert loc["status"] == "resource"
    c = loc["candidates"][0]
    assert (c["account"], c["region"]) == ("222222222222", "us-east-1")
    assert c["vpc"]["ResourceId"] == "vpc-0app" and c["subnet"]["ResourceId"] == "subnet-0appa"
    assert c["resource"]["ResourceId"] == "eni-0app1"
    assert c["instance"]["ResourceId"] == "i-0app1"  # current history only; i-0old has ended
    assert c["leaf_kind"] == "instance" and c["cidr"] == "10.1.1.25/32"
    assert [p["IpamPoolId"] for p in loc["pool_chains"][0]] == ["ipam-pool-0top", "ipam-pool-0use1",
                                                                "ipam-pool-0prod"]
    assert loc["allocation"]["ResourceId"] == "vpc-0app"
    assert loc["most_specific"] == {"cidr": "10.1.1.25/32", "source": "resource"}


def test_ip_in_subnet_without_eni_stops_at_subnet():
    loc = core.locate(bundle_for("10.1.1.200"))
    assert loc["status"] == "network"
    c = loc["candidates"][0]
    assert c["leaf_kind"] == "subnet" and c["resource"] is None
    assert loc["most_specific"]["cidr"] == "10.1.1.0/24"


def test_pool_only_returns_most_specific_pool():
    loc = core.locate(bundle_for("10.9.5.5"))
    assert loc["status"] == "pool" and not loc["candidates"]
    assert loc["deepest_pool"]["IpamPoolId"] == "ipam-pool-0rsv"
    assert loc["most_specific"] == {"cidr": "10.9.0.0/16", "source": "pool"}


def test_not_found():
    loc = core.locate(bundle_for("192.168.1.1"))
    assert loc["status"] == "none" and loc["most_specific"] is None and not loc["pool_chains"]


def test_cidr_query_lists_resources_inside():
    loc = core.locate(bundle_for("10.1.1.0/24"))
    assert loc["candidates"][0]["leaf_kind"] == "subnet"
    assert [r["ResourceId"] for r in loc["within"]] == ["eni-0app1", "eni-0app2"]


def test_public_ip_resolves_to_service():
    b = bundle_for("203.0.113.10")
    loc = core.locate(b)
    assert loc["status"] == "resource"
    c = loc["candidates"][0]
    assert c["account"] == "222222222222" and c["leaf_kind"] == "service"
    assert c["public"]["ServiceResource"] == "nat-0abc" and c["eni_id"] == "eni-0nat"


def test_may_be_public():
    assert not core.may_be_public(core.parse_query("10.1.1.25"))
    assert not core.may_be_public(core.parse_query("fd00::1"))
    assert core.may_be_public(core.parse_query("203.0.113.10"))
    assert core.may_be_public(core.parse_query("0.0.0.0/0"))


def test_public_eip_and_address_merge_into_one_candidate():
    loc = core.locate(bundle_for("203.0.113.10"))
    assert len(loc["candidates"]) == 1
    c = loc["candidates"][0]
    assert c["resource"]["ResourceId"] == "eipalloc-0nat"
    assert c["vpc"]["ResourceId"] == "vpc-0app" and c["subnet"]["ResourceId"] == "subnet-0pub"


def test_private_query_skips_public_address_lookup():
    ec2 = FakeEC2()
    bundle_for("10.1.1.25", ec2)
    assert not any(op == "get_ipam_discovered_public_addresses" for op, _ in ec2.calls)


def test_reused_range_lists_every_owner_most_specific_first():
    state = copy.deepcopy(STATE)
    state["resource_cidrs"]["us-east-1"] += [
        _res("vpc", "vpc-0dup", "10.1.0.0/20", "333333333333", "us-east-1"),
        _res("subnet", "subnet-0dup", "10.1.1.0/24", "333333333333", "us-east-1", "vpc-0dup"),
    ]
    loc = core.locate(bundle_for("10.1.1.25", FakeEC2(state)))
    assert [c["account"] for c in loc["candidates"]] == ["222222222222", "333333333333"]
    assert loc["candidates"][0]["leaf_kind"] == "instance" and loc["candidates"][1]["leaf_kind"] == "subnet"


def test_ipv6_uses_ipv6_pools_only():
    loc = core.locate(bundle_for("2001:db8::5"))
    assert loc["deepest_pool"]["IpamPoolId"] == "ipam-pool-0v6"


def test_regions_filter_limits_search():
    ec2 = FakeEC2()
    bundle_for("10.2.1.5", ec2, regions=["us-east-1"])
    searched = {p["ResourceRegion"] for op, p in ec2.calls if op == "get_ipam_discovered_resource_cidrs"}
    assert searched == {"us-east-1"}


def test_api_errors_become_warnings():
    b = bundle_for("10.1.1.25", FakeEC2(fail={"get_ipam_address_history": "AccessDenied"}))
    assert any("GetIpamAddressHistory failed (AccessDenied)" in w for w in b["warnings"])
    assert core.locate(b)["candidates"][0]["leaf_kind"] == "eni"  # still narrowed, just no instance


def test_several_ipams_need_ipam_id():
    state = copy.deepcopy(STATE)
    state["ipams"].append(dict(state["ipams"][0], IpamId="ipam-0bbb"))
    with pytest.raises(core.ValidationError, match="--ipam-id"):
        core.collect(FakeEC2(state), core.parse_query("10.1.1.25"))


def test_no_ipam_in_region():
    with pytest.raises(LookupError, match="IPAM's home Region"):
        core.collect(FakeEC2(dict(STATE, ipams=[])), core.parse_query("10.1.1.25"))


def test_paginate_follows_next_token():
    class Paged:
        def can_paginate(self, op):
            return False

        def get_thing(self, NextToken=None):
            return {"Items": [1, 2], "NextToken": "t"} if NextToken is None else {"Items": [3]}

    assert list(core._paginate(Paged(), "get_thing", "Items")) == [1, 2, 3]


# ---------- links / reports ----------

def test_console_urls():
    assert core.console_url("vpc", "vpc-1", "us-east-1") == \
        "https://us-east-1.console.aws.amazon.com/vpcconsole/home?region=us-east-1#VpcDetails:VpcId=vpc-1"
    assert core.console_url("pool", "ipam-pool-1", "us-gov-west-1", "aws-us-gov").startswith(
        "https://console.amazonaws-us-gov.com/ipam/home?region=us-gov-west-1#")
    assert core.console_url("vpc", None, "us-east-1") is None


def test_report_path_uses_owner_account(tmp_path):
    b = bundle_for("10.1.1.25")
    p = core.report_path(b, tmp_path)
    assert p.parts[-3] == b["generated"][:10] and p.parts[-2] == "222222222222"
    assert p.name == "ipam-locate_10.1.1.25_32.html"
    # Pool-only: no owner found, so it's filed under the IPAM owner.
    assert core.report_path(bundle_for("10.9.5.5"), tmp_path).parts[-2] == "111111111111"


# ---------- HTML ----------

def test_html_report_has_hierarchy_and_links():
    html = render_html([bundle_for("10.1.1.25")])
    assert "<script src" not in html and "<link" not in html and "http://" not in html
    for s in ("Resource found", "Hierarchy", "ipam-pool-0top", "ipam-pool-0prod", "vpc-0app", "subnet-0appa",
              "eni-0app1", "i-0app1", "#InstanceDetails:instanceId=i-0app1", "#PoolDetails:poolId=ipam-pool-0prod"):
        assert s in html, s
    # Tree order: top pool, then prod pool, then VPC, then instance, then the query marker.
    tree = html[html.index("<h3>Hierarchy"):]
    order = [tree.index(s) for s in ('poolId=ipam-pool-0top"', 'poolId=ipam-pool-0prod"', "VpcId=vpc-0app",
                                     "instanceId=i-0app1", 'class="tn hit"')]
    assert order == sorted(order)


def test_html_pool_only_links_to_pool():
    html = render_html([bundle_for("10.9.5.5")])
    assert "Pool only" in html and "#PoolDetails:poolId=ipam-pool-0rsv" in html and "10.9.0.0/16" in html


def test_html_escapes_values():
    state = copy.deepcopy(STATE)
    state["resource_cidrs"]["us-east-1"][0]["ResourceTags"] = [{"Key": "Name", "Value": "<script>x</script>"}]
    html = render_html([bundle_for("10.1.1.25", FakeEC2(state))])
    assert "<script>x" not in html and "&lt;script&gt;x" in html


def test_html_themes():
    b = bundle_for("10.1.1.25")
    assert 'data-theme="dark"' in render_html([b])
    assert 'data-theme="light"' in render_html([b], theme="light")
    with pytest.raises(ValueError):
        render_html([b], theme="neon")


# ---------- CLI ----------

def test_cli_writes_report_and_json_without_profile(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(ipam_locate, "_ec2", lambda args: FakeEC2())
    js = tmp_path / "b.json"
    rc = ipam_locate.main(["10.1.1.25", "--profile", "secret-profile", "--reports-dir", str(tmp_path / "r"),
                           "--json-out", str(js)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "account 222222222222 · us-east-1 · vpc-0app · subnet-0appa · eni-0app1 · i-0app1" in out
    reports = list((tmp_path / "r").rglob("*.html"))
    assert len(reports) == 1
    for f in (reports[0], js):
        assert "secret-profile" not in f.read_text()

    # Offline re-render from the saved bundle.
    out_html = tmp_path / "again.html"
    assert ipam_locate.main(["--from-json", str(js), "-o", str(out_html)]) == 0
    assert "i-0app1" in out_html.read_text()


def test_cli_pool_only_summary(monkeypatch, capsys):
    monkeypatch.setattr(ipam_locate, "_ec2", lambda args: FakeEC2())
    assert ipam_locate.main(["10.9.5.5", "--no-report"]) == 0
    out = capsys.readouterr().out
    assert "pool only" in out and "ipam-pool-0rsv  10.9.0.0/16" in out and "#PoolDetails:poolId=ipam-pool-0rsv" in out


def test_cli_bad_query_exits_1(caplog):
    caplog.set_level(logging.ERROR)
    assert ipam_locate.main(["10.1.2.3/16", "--no-report"]) == 1
    assert "not an IP address or CIDR" in caplog.text


def test_cli_requires_query():
    assert ipam_locate.main(["--no-report"]) == 1
