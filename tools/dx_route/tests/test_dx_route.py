import copy
import datetime as dt
import html
import ipaddress
import json
import re
import sys
from pathlib import Path

import pytest
from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import dr_cisco as cisco  # noqa: E402
import dr_core as core  # noqa: E402
import dx_route  # noqa: E402
from dr_export import render_html  # noqa: E402

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "core_dxgw.json"
DXGW = "dxgw-0a1b2c3d4e5f60718"
VGW = "vgw-0f1e2d3c4b5a69788"
NYC1, NYC2, CHI, LAX = "dxvif-exnyc001", "dxvif-exnyc002", "dxvif-exchi001", "dxvif-exlax001"


@pytest.fixture
def bundle():
    return json.loads(FIXTURE.read_text())


def cmd(text):
    return dx_route.parse_command(text.split())


def paths_of(bundle, prefix, table=DXGW):
    return {p["vif"]: p for p in core.select(bundle)[table][prefix]["paths"]}


# ---------- prefixes and attributes ----------

def test_parse_prefix_forms():
    assert str(core.parse_prefix("10.1.2.3")) == "10.1.2.3/32"
    assert str(core.parse_prefix("10.1.0.0/16")) == "10.1.0.0/16"
    assert str(core.parse_prefix("10.0.0.0 255.0.0.0")) == "10.0.0.0/8"
    assert str(core.parse_prefix("2001:db8::/32")) == "2001:db8::/32"


@pytest.mark.parametrize("bad", ["10.1.2.3/16", "nope", "10.0.0.300", ""])
def test_parse_prefix_rejects(bad):
    with pytest.raises(core.ValidationError):
        core.parse_prefix(bad)


def test_as_path_length_and_text():
    ap = [{"type": "seq", "path": [65020, 65020]}, {"type": "set", "path": [65100, 65101]}]
    assert core.as_path_length(ap) == 3          # an AS_SET counts once
    assert core.as_path_text(ap) == "65020 65020 {65100,65101}"
    assert core.as_path_length([]) == 0
    assert core.as_path_length([{"type": "set", "path": []}]) == 0


@pytest.mark.parametrize("communities,region,expected", [
    (["7224:7300"], "us-west-2", (300, "community 7224:7300")),
    (["7224:7100"], "us-east-1", (100, "community 7224:7100")),
    (["65000:1", "7224:7200"], "us-west-2", (200, "community 7224:7200")),
    ([], "us-east-1", (200, "default: location associated with us-east-1")),
    ([], "us-east-2", (150, "default: location associated with us-east-2")),
])
def test_local_pref(communities, region, expected):
    assert core.local_pref({"communities": communities}, {"region": region}, "us-east-1") == expected


def test_addr_strips_mask():
    assert core.addr("169.254.10.1/30") == "169.254.10.1"
    assert core.addr(None) is None


@pytest.mark.parametrize("vif,ok,why", [
    ({"state": "available", "peers": [{"family": "ipv4", "status": "up", "state": "available"}]}, True, None),
    ({"state": "down", "peers": []}, False, "VIF down"),
    ({"state": "available", "peers": [{"family": "ipv4", "status": "down", "state": "available"}]}, False, "BGP down"),
    ({"state": "available", "peers": [{"family": "ipv4", "status": "up", "state": "deleted"}]}, False, "BGP peer deleted"),
])
def test_path_valid(vif, ok, why):
    assert core.path_valid(vif, "ipv4") == (ok, why)


# ---------- selection: AWS's documented order ----------

def test_ecmp_on_equal_communities(bundle):
    entry = core.select(bundle)[DXGW]["10.0.0.0/8"]
    p = {x["vif"]: x for x in entry["paths"]}
    assert entry["multipath_count"] == 2
    assert p[NYC1]["best"] and p[NYC1]["multipath"]
    assert p[NYC2]["multipath"] and not p[NYC2]["best"]
    assert p[NYC2]["evaluation"] == "Multipath candidate (equal cost; MED not visible)"
    assert p[CHI]["evaluation"].startswith("Lower local preference")


def test_local_preference_beats_as_path(bundle):
    p = paths_of(bundle, "10.20.0.0/16")
    assert p[NYC1]["best"] and p[NYC1]["local_pref"] == 300
    # chi-backup has no tag and is in another Region: modeled 150, above nyc-secondary's explicit low (100)
    order = [x["vif"] for x in core.select(bundle)[DXGW]["10.20.0.0/16"]["paths"]]
    assert order == [NYC1, CHI, NYC2]
    assert p[NYC2]["evaluation"] == "Lower local preference"


def test_assumption_flagged_when_remote_default_meets_low():
    b = {"from_region": "us-east-1", "vifs": [
        {"id": "a", "region": "us-east-2", "state": "available", "type": "transit", "dx_gateway": "dxgw-1", "peers": []},
        {"id": "b", "region": "us-east-1", "state": "available", "type": "transit", "dx_gateway": "dxgw-1", "peers": []}],
         "routes": [
        {"vif": "a", "cidr": "10.0.0.0/8", "direction": "accepted", "family": "ipv4",
         "as_path": [{"type": "seq", "path": [1]}], "communities": []},
        {"vif": "b", "cidr": "10.0.0.0/8", "direction": "accepted", "family": "ipv4",
         "as_path": [{"type": "seq", "path": [1]}], "communities": ["7224:7100"]}]}
    p = {x["vif"]: x for x in core.select(b)["dxgw-1"]["10.0.0.0/8"]["paths"]}
    assert p["a"]["best"]
    assert "assumed" in p["b"]["evaluation"]


def test_as_path_prepend_loses_with_equal_local_pref(bundle):
    p = paths_of(bundle, "10.20.30.0/24")
    assert p[NYC2]["best"] and p[NYC2]["as_path_len"] == 1
    assert p[NYC1]["as_path_len"] == 3 and p[NYC1]["evaluation"] == "Longer AS path"
    assert p[CHI]["evaluation"] == "Lower local preference"


def test_equal_tags_share_traffic_across_regions():
    """AWS: the same community on VIFs homed to different Regions load-balances (ECMP)."""
    def vif(i, region):
        return {"id": i, "region": region, "state": "available", "type": "transit", "dx_gateway": "dxgw-1", "peers": []}
    def route(i):
        return {"vif": i, "cidr": "10.0.0.0/8", "direction": "accepted", "family": "ipv4",
                "as_path": [{"type": "seq", "path": [1]}], "communities": ["7224:7200"]}
    b = {"from_region": "us-east-1", "vifs": [vif("a", "us-east-1"), vif("b", "eu-west-1")], "routes": [route("a"), route("b")]}
    assert core.select(b)["dxgw-1"]["10.0.0.0/8"]["multipath_count"] == 2


def test_invalid_path_never_best(bundle):
    entry = core.select(bundle)[DXGW]["0.0.0.0/0"]
    p = {x["vif"]: x for x in entry["paths"]}
    assert p[CHI]["best"]                       # longer AS path, but lax-dr's BGP session is down
    assert not p[LAX]["valid"] and p[LAX]["evaluation"] == "Path not valid (BGP down)"
    nobest = core.select(bundle)[DXGW]["192.168.50.0/24"]
    assert nobest["best"] is None and nobest["multipath_count"] == 0


def test_gateways_do_not_compete(bundle):
    tables = core.select(bundle)
    assert set(tables) == {DXGW, VGW}
    assert [p["vif"] for p in tables[VGW]["10.20.0.0/16"]["paths"]] == ["dxvif-exlgc001"]


def test_public_vifs_use_as_path_then_home_region():
    def vif(i, region):
        return {"id": i, "region": region, "state": "available", "type": "public", "peers": []}
    def route(i, path, comm=()):
        return {"vif": i, "cidr": "198.51.100.0/24", "direction": "accepted", "family": "ipv4",
                "as_path": [{"type": "seq", "path": path}], "communities": list(comm)}
    b = {"from_region": "us-east-1", "vifs": [vif("a", "us-west-2"), vif("b", "us-east-1"), vif("c", "us-east-1")],
         "routes": [route("a", [1], ["7224:7300"]), route("b", [1]), route("c", [1, 1])]}
    tables = core.select(b)
    assert set(tables) == {"public:us-west-2", "public:us-east-1"}
    east = {p["vif"]: p for p in tables["public:us-east-1"]["198.51.100.0/24"]["paths"]}
    assert east["b"]["best"] and east["c"]["evaluation"] == "Longer AS path"
    one = {"from_region": "us-east-1", "vifs": [dict(vif("a", "us-west-2"), region="us-east-1"), vif("b", "us-east-1")],
           "routes": [route("a", [1], ["7224:7300"]), route("b", [1])]}
    # local preference communities don't apply to public VIFs: equal AS paths, same Region -> ECMP
    assert core.select(one)["public:us-east-1"]["198.51.100.0/24"]["multipath_count"] == 2


def test_home_region_breaks_public_tie():
    b = {"from_region": "us-east-1", "vifs": [
        {"id": "a", "region": "us-west-2", "state": "available", "type": "public", "dx_gateway": None, "peers": []},
        {"id": "b", "region": "us-east-1", "state": "available", "type": "public", "dx_gateway": None, "peers": []}],
        "routes": []}
    # Same table only if same Region key; compare the ranking function directly
    p_home = {"valid": True, "type": "public", "as_path_len": 1, "home_region": True, "local_pref": 200}
    p_away = dict(p_home, home_region=False)
    assert core._rank(p_home) < core._rank(p_away)
    assert core._reason(p_away, p_home, public=True) == "Not from the home Region"
    assert core.select(b) == {}


def test_matching_helpers(bundle):
    table = core.select(bundle)[DXGW]
    q = ipaddress.ip_network("10.20.30.7/32")
    assert core.covering(table, q) == ["10.20.30.0/24", "10.20.0.0/16", "10.0.0.0/8", "0.0.0.0/0"]
    assert core.longest_match(table, q) == "10.20.30.0/24"
    assert core.longest_match(table, ipaddress.ip_network("192.168.50.9/32")) == "0.0.0.0/0"
    assert core.longer_prefixes(table, ipaddress.ip_network("10.0.0.0/8")) == ["10.0.0.0/8", "10.20.0.0/16",
                                                                               "10.20.30.0/24"]
    assert core.longest_match(table, ipaddress.ip_network("2001:db8:100::/48")) == "2001:db8:100::/40"


# ---------- command parsing ----------

@pytest.mark.parametrize("text,expect", [
    ("show ip bgp 10.20.30.0/24", {"kind": "bgp", "afi": "ip", "longer": False}),
    ("ip bgp", {"kind": "bgp", "prefix": None}),
    ("show ip bgp 10.0.0.0 255.0.0.0 longer-prefixes", {"kind": "bgp", "longer": True}),
    ("show ip bgp summary", {"kind": "summary"}),
    ("show ip bgp vrf dxgw-1 summary", {"kind": "summary", "table": "dxgw-1"}),
    ("show ip bgp neighbors 169.254.10.1 advertised-routes", {"kind": "neighbors", "neighbor": "169.254.10.1",
                                                             "which": "advertised-routes"}),
    ("show ip bgp neighbors received-routes", {"kind": "neighbors", "neighbor": None, "which": "received-routes"}),
    ("show ip bgp neighbors dxvif-1 routes", {"kind": "neighbors", "which": "received-routes"}),
    ("sh ipv6 route 2001:db8::1", {"kind": "route", "afi": "ipv6"}),
    ("show ip route vrf vgw-1 10.1.1.1", {"kind": "route", "table": "vgw-1"}),
])
def test_parse_command(text, expect):
    c = cmd(text)
    for k, v in expect.items():
        assert c[k] == v, k
    assert c["text"].startswith("show ")


def test_parse_command_prefix_values():
    assert str(cmd("show ip bgp 10.0.0.0 255.0.0.0 longer-prefixes")["prefix"]) == "10.0.0.0/8"
    assert str(cmd("show ip route 10.20.30.7")["prefix"]) == "10.20.30.7/32"


@pytest.mark.parametrize("text", ["show ip", "show interfaces", "show ip bgp neighbors 1.1.1.1",
                                  "show ip bgp longer-prefixes", "show ipv6 bgp 10.0.0.0/8",
                                  "show ip bgp 2001:db8::/32", "show ip route 10.0.0.0/8 extra words"])
def test_parse_command_rejects(text):
    with pytest.raises(core.ValidationError):
        cmd(text)


# ---------- Cisco views ----------

def test_bgp_table_layout(bundle):
    out = cisco.render(bundle, cmd("show ip bgp"))
    assert "Routing Table: dxgw-0a1b2c3d4e5f60718 (core-dxgw), Amazon ASN 64512" in out
    assert "Routing Table: vgw-0f1e2d3c4b5a69788 (virtual private gateway), Amazon ASN 64600" in out
    assert "     Network          Next Hop            Metric LocPrf Weight Path" in out
    lines = out.splitlines()
    i = lines.index(next(x for x in lines if x.startswith(" *>  10.0.0.0/8")))
    assert re.match(r" \*>  10\.0\.0\.0/8\s+169\.254\.10\.1\s+200\s+0 65010$", lines[i])
    assert re.match(r" \*m\s+169\.254\.11\.1\s+200\s+0 65010$", lines[i + 1])
    assert re.match(r" \*\s+169\.254\.20\.1\s+100\s+0 65020 65010$", lines[i + 2])
    assert re.search(r"^     192\.168\.50\.0/24\s+169\.254\.30\.1", out, re.M)   # no valid path: no '*'
    assert "65020 {65100,65101}" in out
    assert "  169.254.10.1  dxvif-exnyc001 (nyc-primary), us-east-1\n" \
           "                  Location Equinix DC2/DC11, Ashburn, VA (EqDC2)\n" \
           "                  Connection dxcon-ex000001 (nyc-xc-a): dedicated, 10Gbps" in out


def test_long_network_wraps_like_ios():
    lines = cisco._row("*>", "2001:db8:100::/40", "2001:db8:ffff:10::1", 200, "65010")
    assert lines[0] == " *>  2001:db8:100::/40"
    assert lines[1].startswith(" " * 22 + "2001:db8:ffff:10::1")


def test_bgp_entry_explains_each_path(bundle):
    out = cisco.render(bundle, cmd("show ip bgp 10.20.30.0/24"))
    assert "BGP routing table entry for 10.20.30.0/24, version 1" in out
    assert "Paths: (3 available, best #1, table dxgw-0a1b2c3d4e5f60718)" in out
    assert "169.254.11.1 (dxvif-exnyc002) from 169.254.11.1 (dxvif-exnyc002)" in out
    assert "localpref 200, valid, external, best" in out          # single best: no 'multipath'
    assert out.count("Best Path Evaluation: Longer AS path") == 1
    assert "Best Path Evaluation: Lower local preference" in out
    assert "Updated 06:17:51 ago" in out
    assert "Less specific prefixes that also cover 10.20.30.0/24:" in out
    assert "  0.0.0.0/0          best via 169.254.20.1 (dxvif-exchi001)" in out


def test_bgp_entry_longest_match_and_multipath(bundle):
    out = cisco.render(bundle, cmd("show ip bgp vrf dxgw-0a1b2c3d4e5f60718 10.99.0.0/16"))
    assert "BGP routing table entry for 10.0.0.0/8" in out
    assert "Longest match for 10.99.0.0/16" in out
    assert "Multipath: eBGP (2 paths share traffic)" in out
    assert "valid, external, multipath, best" in out
    assert "vgw-" not in out


def test_bgp_entry_shows_invalid_longest_match(bundle):
    out = cisco.render(bundle, cmd("show ip bgp vrf dxgw-0a1b2c3d4e5f60718 192.168.50.1"))
    assert "BGP routing table entry for 192.168.50.0/24" in out
    assert "no best path" in out and "not valid" in out


def test_route_entry_and_fallback(bundle):
    out = cisco.render(bundle, cmd("show ip route 10.20.30.7"))
    assert "Routing entry for 10.20.30.0/24 (longest match for 10.20.30.7/32)" in out
    assert 'Known via "bgp 64512", distance 20, metric 0' in out
    assert "  * 169.254.11.1, from 169.254.11.1, 06:17:51 ago, via dxvif-exnyc002" in out
    assert "Routing entry for 10.20.0.0/16 (longest match for 10.20.30.7/32)" in out    # the VGW table
    fb = cisco.render(bundle, cmd("show ip route vrf dxgw-0a1b2c3d4e5f60718 192.168.50.1"))
    assert "192.168.50.0/24 is in the BGP table but has no valid path (BGP down)" in fb
    assert "Routing entry for 0.0.0.0/0" in fb


def test_route_entry_ecmp_blocks(bundle):
    out = cisco.render(bundle, cmd("show ipv6 route 2001:db8:100:5::/64"))
    assert "  * 2001:db8:ffff:10::1, from 2001:db8:ffff:10::1" in out
    assert "    2001:db8:ffff:11::1, from 2001:db8:ffff:11::1" in out


def test_route_table(bundle):
    out = cisco.render(bundle, cmd("show ip route"))
    assert "Gateway of last resort is 169.254.20.1 to network 0.0.0.0/0" in out
    assert "Gateway of last resort is not set" in out
    assert "B        10.0.0.0/8 [20/0] via 169.254.10.1, 2d03h, dxvif-exnyc001" in out
    assert "[20/0] via 169.254.11.1, 4d08h, dxvif-exnyc002" in out       # ECMP continuation line
    assert "192.168.50.0" not in out                                      # no valid path, not in the RIB
    longer = cisco.render(bundle, cmd("show ip route 10.20.0.0 255.255.0.0 longer-prefixes"))
    assert "10.20.30.0/24" in longer and "10.0.0.0/8" not in longer


def test_summary(bundle):
    out = cisco.render(bundle, cmd("show ip bgp summary"))
    assert "BGP router identifier dxgw-0a1b2c3d4e5f60718, local AS number 64512" in out
    assert re.search(r"^169\.254\.10\.1\s+4\s+65010\s+-\s+-\s+1\s+0\s+0 never\s+3$", out, re.M)
    assert re.search(r"^169\.254\.30\.1\s+4\s+65030 .* Active$", out, re.M)


def test_summary_states():
    b = {"from_region": "us-east-1", "gateways": [], "routes": [], "vifs": [
        {"id": "dxvif-a", "state": "down", "dx_gateway": "dxgw-1", "peers": [{"family": "ipv4"}]},
        {"id": "dxvif-b", "state": "unreadable", "unreadable": True, "dx_gateway": "dxgw-1", "peers": []}]}
    out = cisco.render(b, cmd("show ip bgp summary"))
    assert "Idle (Admin)" in out and "NoAccess" in out
    assert "local AS number ?" in out


def test_neighbor_routes(bundle):
    out = cisco.render(bundle, cmd("show ip bgp neighbors 169.254.10.1 advertised-routes"))
    assert "Neighbor 169.254.10.1, dxvif-exnyc001 (nyc-primary), us-east-1, advertised-routes:" in out
    assert "  Connection dxcon-ex000001 (nyc-xc-a): dedicated, 10Gbps" in out
    assert re.search(r"^ \*   10\.100\.0\.0/16\s+169\.254\.10\.2\s+0 64512$", out, re.M)   # next hop: Amazon side
    assert "Total number of prefixes 2" in out
    assert "vgw-" not in out
    rec = cisco.render(bundle, cmd("show ip bgp neighbors received-routes"))
    assert rec.count("received-routes:") == 5
    assert cisco.render(bundle, cmd("show ip bgp neighbors 10.9.9.9 received-routes")) == "% No such neighbor 10.9.9.9\n"


def test_neighbor_routes_without_advertised_collection(bundle):
    bundle["directions"] = ["accepted"]
    out = cisco.render(bundle, cmd("show ip bgp neighbors dxvif-exnyc001 advertised-routes"))
    assert "% Advertised routes were not collected for this bundle" in out


def test_not_in_table_and_no_vifs(bundle):
    out = cisco.render(bundle, cmd("show ipv6 bgp 2001:db8:999::/48"))
    assert out.count("% Network not in table") == 2
    assert cisco.render({"vifs": [], "routes": []}, cmd("show ip bgp")) == "% No Direct Connect virtual interfaces in scope\n"


@pytest.mark.parametrize("secs,text", [(5, "00:00:05"), (3 * 3600 + 61, "03:01:01"), (86400 * 2 + 3 * 3600, "2d03h"),
                                       (86400 * 9, "1w2d")])
def test_uptime(secs, text):
    now = dt.datetime(2026, 10, 25, tzinfo=dt.timezone.utc)
    assert cisco.uptime((now - dt.timedelta(seconds=secs)).isoformat(), now) == text


def test_uptime_unknown():
    assert cisco.uptime(None) == "never"
    assert cisco.uptime("garbage") == "never"


# ---------- HTML ----------

def test_html_report(bundle):
    c = cmd("show ip bgp 10.20.30.0/24")
    page = render_html(bundle, c, cisco.render(bundle, c))
    assert "Router# show ip bgp 10.20.30.0/24" in page
    assert "Path selection" in page and "Longer AS path" in page
    assert "core-dxgw: 10.20.30.0/24 via dxvif-exnyc002" in page
    assert "Virtual interfaces" in page
    no = render_html(bundle, cmd("show ipv6 bgp 2001:db8:999::/48"), "")
    assert "No route to 2001:db8:999::/48" in no
    with pytest.raises(ValueError):
        render_html(bundle, c, "", theme="neon")


def test_html_escapes_aws_values(bundle):
    evil = "</pre><script>alert(1)</script>"
    bundle["vifs"][0]["name"] = evil
    bundle["warnings"] = [evil]
    c = cmd("show ip bgp 10.20.30.0/24")
    page = render_html(bundle, c, cisco.render(bundle, c))
    assert evil not in page
    assert html.escape(evil) in page


# ---------- collection against a fake Direct Connect API ----------

class FakeDX:
    """The Direct Connect calls collect() makes, with nextToken paging on routes."""

    def __init__(self, vifs, routes, attachments=(), gateways=(), page=2, fail=(), connections=(), lags=(),
                 locations=None, fail_locations=False):
        self.vifs, self.routes, self.attachments, self.gateways = vifs, routes, list(attachments), list(gateways)
        self.page, self.fail, self.calls = page, set(fail), []
        self.connections, self.lags = list(connections), list(lags)
        self.locations = [{"locationCode": "EqDC2", "locationName": "Equinix DC2/DC11, Ashburn, VA", "region": "us-east-1"}] \
            if locations is None else locations
        self.fail_locations = fail_locations

    def describe_locations(self):
        if self.fail_locations:
            raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "no"}}, "DescribeLocations")
        return {"locations": self.locations}

    def describe_connections(self, connectionId):
        if connectionId == "dxcon-denied":
            raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "no"}}, "DescribeConnections")
        return {"connections": [c for c in self.connections if c["connectionId"] == connectionId]}

    def describe_lags(self, lagId):
        return {"lags": [x for x in self.lags if x["lagId"] == lagId]}

    def describe_virtual_interfaces(self, virtualInterfaceId=None, nextToken=None):
        self.calls.append(("describe_virtual_interfaces", virtualInterfaceId))
        items = [v for v in self.vifs if not virtualInterfaceId or v["virtualInterfaceId"] == virtualInterfaceId]
        if virtualInterfaceId and not items:
            raise ClientError({"Error": {"Code": "DirectConnectClientException", "Message": "not found"}}, "Describe")
        return {"virtualInterfaces": items}

    def list_virtual_interface_routes(self, virtualInterfaceId, filters, maxResults, nextToken=None):
        self.calls.append(("list_virtual_interface_routes", virtualInterfaceId, filters["routeDirection"], nextToken))
        if virtualInterfaceId in self.fail:
            raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "no"}}, "ListVirtualInterfaceRoutes")
        items = [r for r in self.routes.get(virtualInterfaceId, [])
                 if r["routeDirection"] == filters["routeDirection"]
                 and r["addressFamily"] == filters.get("addressFamily", r["addressFamily"])]
        start = int(nextToken or 0)
        chunk = items[start:start + self.page]
        more = start + self.page < len(items)
        return {"routes": chunk, **({"nextToken": str(start + self.page)} if more else {})}

    def describe_direct_connect_gateways(self, directConnectGatewayId=None):
        return {"directConnectGateways": [g for g in self.gateways if g["directConnectGatewayId"] == directConnectGatewayId]}

    def get_paginator(self, name):
        assert name == "describe_direct_connect_gateway_attachments"
        dx = self

        class P:
            def paginate(self, directConnectGatewayId):
                yield {"directConnectGatewayAttachments": [a for a in dx.attachments
                                                           if a["directConnectGatewayId"] == directConnectGatewayId]}
        return P()


def api_vif(i, region="us-east-1", owner="111122223333", gw="dxgw-1", status="up"):
    return {"virtualInterfaceId": i, "virtualInterfaceName": f"name-{i}", "virtualInterfaceType": "transit",
            "virtualInterfaceState": "available", "ownerAccount": owner, "region": region, "location": "EqDC2",
            "connectionId": "dxcon-1", "vlan": 10, "asn": 65010, "amazonSideAsn": 64512,
            "directConnectGatewayId": gw, "virtualGatewayId": "",
            "bgpPeers": [{"addressFamily": "ipv4", "asn": 65010, "customerAddress": "169.254.1.1/30",
                          "amazonAddress": "169.254.1.2/30", "bgpPeerState": "available", "bgpStatus": status,
                          "awsDeviceV2": "EqDC2-x"}]}


def api_route(cidr, path, direction="accepted", comm=(), fam="ipv4"):
    return {"cidr": cidr, "routeDirection": direction, "addressFamily": fam,
            "asPath": [{"pathType": "seq", "path": path}], "communities": list(comm),
            "awsLogicalDeviceId": "EqDC2-x", "routeInstalledAt": dt.datetime(2026, 10, 1, tzinfo=dt.timezone.utc)}


class FakeSessions(core.Sessions):
    def __init__(self, clients, caller="111122223333", overrides=None, pmap=None):
        self.region, self.overrides, self._caller = "us-east-1", dict(overrides or {}), caller
        self._pmap, self._cache, self._config_file = pmap or {}, {}, None
        self.clients = clients
        self.base = ("session", caller)

    def for_account(self, account):
        if not account or account == self._caller:
            return self.base
        if account in self.overrides or account in self._pmap:
            return ("session", account)
        return None


@pytest.fixture
def patch_client(monkeypatch):
    def install(sessions):
        monkeypatch.setattr(core, "get_client", lambda svc, session, region=None: sessions.clients[session[1]])
    return install


def test_collect_region_paginates_and_filters_family(patch_client):
    dx = FakeDX([api_vif("dxvif-a"), api_vif("dxvif-b", status="down")],
                {"dxvif-a": [api_route("10.0.0.0/8", [65010]), api_route("10.1.0.0/16", [65010]),
                             api_route("10.2.0.0/16", [65010, 65010]), api_route("2001:db8::/32", [65010], fam="ipv6"),
                             api_route("10.9.0.0/16", [64512], direction="advertised")],
                 "dxvif-b": [api_route("10.0.0.0/8", [65010, 65010])]},
                gateways=[{"directConnectGatewayId": "dxgw-1", "directConnectGatewayName": "core", "amazonSideAsn": 64512}])
    s = FakeSessions({"111122223333": dx})
    patch_client(s)
    b = core.collect(s, ipaddress.ip_network("10.1.2.0/24"), regions=["us-east-1"], from_region="us-east-1")
    assert {r["cidr"] for r in b["routes"]} == {"10.0.0.0/8", "10.1.0.0/16", "10.2.0.0/16"}
    assert all(r["direction"] == "accepted" for r in b["routes"])
    tokens = [c[3] for c in dx.calls if c[0] == "list_virtual_interface_routes" and c[1] == "dxvif-a"]
    assert tokens == [None, "2"]                                  # 3 IPv4 routes, page size 2
    assert b["vifs"][0]["peers"][0]["customer_address"] == "169.254.1.1/30"
    assert b["gateways"] == [{"id": "dxgw-1", "name": "core", "amazon_asn": 64512, "owner": None, "state": None}]
    assert b["routes"][0]["installed"].startswith("2026-10-01")
    json.dumps(b)                                                  # JSON-serializable
    table = core.select(b)["dxgw-1"]["10.0.0.0/8"]
    assert table["best"]["vif"] == "dxvif-a" and table["paths"][1]["evaluation"] == "Path not valid (BGP down)"


def test_collect_dx_gateway_cross_account(patch_client):
    gw = {"directConnectGatewayId": "dxgw-1", "directConnectGatewayName": "core", "amazonSideAsn": 64512,
          "ownerAccount": "111122223333", "directConnectGatewayState": "available"}
    atts = [{"directConnectGatewayId": "dxgw-1", "virtualInterfaceId": "dxvif-a", "virtualInterfaceRegion": "us-east-1",
             "virtualInterfaceOwnerAccount": "111122223333", "attachmentState": "attached"},
            {"directConnectGatewayId": "dxgw-1", "virtualInterfaceId": "dxvif-b", "virtualInterfaceRegion": "us-west-2",
             "virtualInterfaceOwnerAccount": "444455556666", "attachmentState": "attached"},
            {"directConnectGatewayId": "dxgw-1", "virtualInterfaceId": "dxvif-c", "virtualInterfaceRegion": "us-west-2",
             "virtualInterfaceOwnerAccount": "777788889999", "attachmentState": "attached"},
            {"directConnectGatewayId": "dxgw-1", "virtualInterfaceId": "dxvif-old", "virtualInterfaceRegion": "us-east-1",
             "virtualInterfaceOwnerAccount": "111122223333", "attachmentState": "detached"}]
    own = FakeDX([api_vif("dxvif-a")], {"dxvif-a": [api_route("10.0.0.0/8", [65010], comm=["7224:7100"])]},
                 attachments=atts, gateways=[gw])
    other = FakeDX([api_vif("dxvif-b", region="us-west-2", owner="444455556666")],
                   {"dxvif-b": [api_route("10.0.0.0/8", [65020])]})
    s = FakeSessions({"111122223333": own, "444455556666": other}, overrides={"444455556666": "other-ro"})
    patch_client(s)
    b = core.collect(s, None, regions=["us-east-1"], from_region="us-east-1", dx_gateway="dxgw-1")
    ids = {v["id"]: v for v in b["vifs"]}
    assert set(ids) == {"dxvif-a", "dxvif-b", "dxvif-c"}          # detached attachment skipped
    assert ids["dxvif-c"]["unreadable"]
    assert any("777788889999" in w and "--account-profile" in w for w in b["warnings"])
    entry = core.select(b)["dxgw-1"]["10.0.0.0/8"]
    # dxvif-b: no tag, us-west-2 location -> 150 beats dxvif-a's explicit low (100)
    assert entry["best"]["vif"] == "dxvif-b"
    assert "NoAccess" in cisco.render(b, cmd("show ip bgp summary"))


def test_collect_errors_become_warnings(patch_client):
    dx = FakeDX([api_vif("dxvif-a")], {}, fail={"dxvif-a"})
    s = FakeSessions({"111122223333": dx})
    patch_client(s)
    b = core.collect(s, None, regions=["us-east-1"], from_region="us-east-1", vif_ids=["dxvif-a", "dxvif-zz"])
    assert any("ListVirtualInterfaceRoutes (accepted) failed: AccessDeniedException" in w for w in b["warnings"])
    assert any("dxvif-zz: not found" in w for w in b["warnings"])
    assert b["routes"] == []


def test_collect_unknown_gateway(patch_client):
    s = FakeSessions({"111122223333": FakeDX([], {})})
    patch_client(s)
    with pytest.raises(core.ValidationError):
        core.collect(s, None, regions=["us-east-1"], from_region="us-east-1", dx_gateway="dxgw-none")


def test_collect_advertised_direction(patch_client):
    dx = FakeDX([api_vif("dxvif-a")], {"dxvif-a": [api_route("10.0.0.0/8", [65010]),
                                                   api_route("10.9.0.0/16", [64512], direction="advertised")]})
    s = FakeSessions({"111122223333": dx})
    patch_client(s)
    b = core.collect(s, None, regions=["us-east-1"], from_region="us-east-1",
                     directions=(core.ACCEPTED, core.ADVERTISED), fam="ipv4")
    assert {r["direction"] for r in b["routes"]} == {"accepted", "advertised"}


def test_collect_connections_and_locations(patch_client):
    vifs = [api_vif("dxvif-ded"), api_vif("dxvif-lag"), api_vif("dxvif-hc"), api_vif("dxvif-hv"), api_vif("dxvif-den")]
    vifs[0]["connectionId"], vifs[1]["connectionId"], vifs[2]["connectionId"] = "dxcon-1", "dxlag-1", "dxcon-2"
    vifs[3]["connectionId"], vifs[4]["connectionId"] = "dxcon-partner", "dxcon-denied"
    vifs[2]["location"] = "XyZ1"
    dx = FakeDX(vifs, {}, connections=[
        {"connectionId": "dxcon-1", "connectionName": "xc-a", "bandwidth": "10Gbps", "connectionState": "available",
         "location": "EqDC2", "ownerAccount": "111122223333"},
        {"connectionId": "dxcon-2", "connectionName": "hc", "bandwidth": "500Mbps", "connectionState": "down",
         "partnerName": "ExampleNet", "location": "XyZ1"}],
        lags=[{"lagId": "dxlag-1", "lagName": "lag-b", "numberOfConnections": 4, "connectionsBandwidth": "100Gbps",
               "lagState": "available"}])
    s = FakeSessions({"111122223333": dx})
    patch_client(s)
    b = core.collect(s, None, regions=["us-east-1"], from_region="us-east-1")
    v = {x["id"]: x for x in b["vifs"]}
    assert v["dxvif-ded"]["location_name"] == "Equinix DC2/DC11, Ashburn, VA"
    assert v["dxvif-hc"]["location_name"] is None                       # unknown code: just the code is shown
    assert core.location_text(v["dxvif-hc"]) == "XyZ1"
    assert core.connection_text(v["dxvif-ded"]["connection_detail"]) == "dxcon-1 (xc-a): dedicated, 10Gbps"
    assert core.connection_text(v["dxvif-lag"]["connection_detail"]) == "dxlag-1 (lag-b): LAG, 4 x 100Gbps"
    assert core.connection_text(v["dxvif-hc"]["connection_detail"]) == "dxcon-2 (hc): hosted by ExampleNet, 500Mbps, down"
    assert core.connection_text(v["dxvif-hv"]["connection_detail"]) == \
        "dxcon-partner: owned by another account (hosted VIF)"
    assert any("dxcon-denied: describing the connection failed: AccessDeniedException" in w for w in b["warnings"])
    page = render_html(b, cmd("show ip bgp summary"), "")
    assert "4 x 100Gbps" in page and "hosted by ExampleNet" in page and "Equinix DC2/DC11, Ashburn, VA" in page


def test_collect_locations_failure_falls_back_to_codes(patch_client):
    dx = FakeDX([api_vif("dxvif-a")], {}, fail_locations=True)
    s = FakeSessions({"111122223333": dx})
    patch_client(s)
    b = core.collect(s, None, regions=["us-east-1"], from_region="us-east-1")
    assert b["vifs"][0]["location_name"] is None
    assert any("DescribeLocations failed in us-east-1" in w for w in b["warnings"])


def test_connection_text_lag_member():
    c = {"id": "dxcon-9", "type": "dedicated", "lag": "dxlag-9", "bandwidth": "10Gbps", "state": "available"}
    assert core.connection_text(c) == "dxcon-9: dedicated, member of dxlag-9, 10Gbps"
    assert core.connection_text(None) is None


# ---------- profiles ----------

def test_profile_account_map(tmp_path):
    cfg = tmp_path / "config"
    cfg.write_text("""
[default]
region = us-east-1
[profile net-ro]
sso_account_id = 111122223333
[profile app-ro]
role_arn = arn:aws:iam::444455556666:role/ReadOnly
[profile app-priv]
sso_account_id = 444455556666
[profile x-cpar]
role_arn = arn:aws:iam::777788889999:role/Admin
[sso-session corp]
sso_region = us-east-1
""")
    assert core.profile_account_map(str(cfg)) == {"111122223333": ["net-ro"], "444455556666": ["app-ro"]}


def test_parse_account_profiles():
    assert core.parse_account_profiles(["111122223333=net-ro"]) == {"111122223333": "net-ro"}
    for bad in ["111122223333", "abc=x", "111122223333="]:
        with pytest.raises(core.ValidationError):
            core.parse_account_profiles([bad])


def test_sessions_resolve_profiles(tmp_path, monkeypatch):
    cfg = tmp_path / "config"
    cfg.write_text("[profile app-ro]\nsso_account_id = 444455556666\n")
    made = []
    monkeypatch.setattr(core, "get_session", lambda profile, region: made.append(profile) or ("s", profile))
    s = core.Sessions("me", "us-east-1", {"777788889999": "manual"}, config_file=str(cfg))
    s._caller = "111122223333"
    assert s.for_account("111122223333") == ("s", "me")
    assert s.for_account("777788889999") == ("s", "manual")
    assert s.for_account("444455556666") == ("s", "app-ro")
    assert s.for_account("000000000000") is None
    assert s.for_account(None) == ("s", "me")


# ---------- CLI ----------

def test_cli_offline(bundle, tmp_path, capsys):
    f = tmp_path / "b.json"
    f.write_text(json.dumps(bundle))
    out = tmp_path / "r.html"
    rc = dx_route.main(["--from-json", str(f), "-o", str(out), "show", "ip", "bgp", "10.20.30.0/24"])
    assert rc == 0
    assert "BGP routing table entry for 10.20.30.0/24" in capsys.readouterr().out
    assert out.read_text().startswith("<!doctype html>")


def test_cli_no_route_exit_code(bundle, tmp_path, capsys):
    f = tmp_path / "b.json"
    f.write_text(json.dumps(bundle))
    assert dx_route.main(["--from-json", str(f), "--no-report", "show", "ipv6", "route", "2001:db8:999::1"]) == 2
    assert "% Network not in table" in capsys.readouterr().out


def test_cli_json_and_report_path(bundle, tmp_path, capsys, monkeypatch):
    f = tmp_path / "b.json"
    f.write_text(json.dumps(bundle))
    monkeypatch.chdir(tmp_path)
    assert dx_route.main(["--from-json", str(f), "--json", "show", "ip", "bgp", "10.20.30.7"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert list(data["tables"][DXGW]) == ["0.0.0.0/0", "10.0.0.0/8", "10.20.0.0/16", "10.20.30.0/24"]
    assert data["tables"][DXGW]["10.20.30.0/24"]["best"]["vif"] == NYC2
    report = tmp_path / "reports" / "2026-10-25" / "us-east-1" / "dx-route_show-ip-bgp-10.20.30.7.html"
    assert report.exists()


def test_cli_from_region_override(bundle, tmp_path, capsys):
    f = tmp_path / "b.json"
    f.write_text(json.dumps(bundle))
    dx_route.main(["--from-json", str(f), "--no-report", "--from-region", "us-east-2", "show", "ip", "bgp",
                   "10.20.30.0/24"])
    out = capsys.readouterr().out
    # from us-east-2, chi-backup's untagged route gets medium and the NYC routes drop to 150
    assert "169.254.20.1 (dxvif-exchi001) from 169.254.20.1 (dxvif-exchi001)\n" \
           "      Origin not reported, metric not reported, localpref 200, valid, external, best" in out


def test_cli_errors(caplog, tmp_path):
    assert dx_route.main(["show", "interfaces"]) == 1
    f = tmp_path / "b.json"
    f.write_text(json.dumps(json.loads(FIXTURE.read_text()) | {"directions": ["accepted"]}))
    assert dx_route.main(["--from-json", str(f), "--no-report", "show", "ip", "bgp", "neighbors",
                          "advertised-routes"]) == 0
    assert "no advertised routes" in caplog.text


def test_cli_live_path(monkeypatch, tmp_path, capsys, bundle):
    seen = {}

    def fake_collect(sessions, query, **kw):
        seen.update(kw, query=query)
        return copy.deepcopy(bundle)
    monkeypatch.setattr(core, "collect", fake_collect)
    monkeypatch.setattr(core.Sessions, "__init__", lambda self, *a, **k: setattr(self, "region", "us-east-1"))
    rc = dx_route.main(["--region", "us-east-1", "--no-report", "--dx-gateway", DXGW, "--vif", NYC1,
                        "--account-profile", "444455556666=other", "show", "ip", "bgp", "neighbors", NYC1,
                        "advertised-routes"])
    assert rc == 0
    assert seen["directions"] == ("accepted", "advertised")
    assert seen["dx_gateway"] == DXGW and seen["vif_ids"] == [NYC1] and seen["from_region"] == "us-east-1"
    assert "advertised-routes:" in capsys.readouterr().out


def test_cli_aws_error(monkeypatch):
    def boom(*a, **k):
        raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "denied"}}, "DescribeVirtualInterfaces")
    monkeypatch.setattr(core, "collect", boom)
    monkeypatch.setattr(core.Sessions, "__init__", lambda self, *a, **k: setattr(self, "region", "us-east-1"))
    assert dx_route.main(["--region", "us-east-1", "--no-report", "show", "ip", "bgp"]) == 1
