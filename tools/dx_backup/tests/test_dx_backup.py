import copy
import datetime as dt
import json
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import db_core as core  # noqa: E402
import db_diff  # noqa: E402
import db_restore  # noqa: E402
import dx_backup  # noqa: E402
from db_export import render_html  # noqa: E402

ACCOUNT, OTHER = "111122223333", "444455556666"
DXGW = "dxgw-0a1b2c3d4e5f60718"
VGW, TGW = "vgw-0f1e2d3c4b5a69788", "tgw-0123456789abcdef0"
CON, LAG, HOSTED = "dxcon-ex000001", "dxlag-ex000002", "dxcon-ex000003"
VIF_PRIV, VIF_TRANSIT, VIF_PUB = "dxvif-exnyc001", "dxvif-exnyc002", "dxvif-expub001"
SECRET = "s3cr3t-md5-key"


def denied(op):
    return ClientError({"Error": {"Code": "AccessDeniedException", "Message": "no"}}, op)


def tags(**kv):
    return [{"key": k, "value": v} for k, v in kv.items()]


def api_data():
    """Synthetic DescribeX responses for one account in us-east-1."""
    return {
        "connections": [
            {"connectionId": CON, "connectionName": "nyc-xc-a", "connectionState": "available", "region": "us-east-1",
             "location": "EqDC2", "bandwidth": "10Gbps", "ownerAccount": ACCOUNT, "encryptionMode": "no_encrypt",
             "loaIssueTime": dt.datetime(2026, 1, 2, tzinfo=dt.timezone.utc), "tags": tags(Name="nyc-xc-a")},
            {"connectionId": HOSTED, "connectionName": "chi-hosted", "connectionState": "available",
             "region": "us-east-1", "location": "EqCH2", "bandwidth": "1Gbps", "partnerName": "ExampleNet",
             "ownerAccount": ACCOUNT},
        ],
        "lags": [
            {"lagId": LAG, "lagName": "nyc-lag-b", "lagState": "available", "region": "us-east-1", "location": "CSVA1",
             "numberOfConnections": 2, "connectionsBandwidth": "10Gbps", "minimumLinks": 1, "ownerAccount": ACCOUNT,
             "connections": [{"connectionId": "dxcon-exlag001"}, {"connectionId": "dxcon-exlag002"}], "tags": []},
        ],
        "vifs": [
            {"virtualInterfaceId": VIF_PRIV, "virtualInterfaceName": "nyc-primary", "virtualInterfaceType": "private",
             "virtualInterfaceState": "available", "ownerAccount": ACCOUNT, "region": "us-east-1", "location": "EqDC2",
             "connectionId": CON, "vlan": 101, "asn": 65010, "asnLong": 65010, "amazonSideAsn": 64512,
             "authKey": SECRET, "amazonAddress": "169.254.10.2/30", "customerAddress": "169.254.10.1/30",
             "addressFamily": "ipv4", "mtu": 9001, "directConnectGatewayId": DXGW, "virtualGatewayId": "",
             "siteLinkEnabled": False, "customerRouterConfig": f"neighbor password {SECRET}",
             "bgpPeers": [
                 {"bgpPeerId": "dxpeer-ex01", "asn": 65010, "authKey": SECRET, "addressFamily": "ipv4",
                  "amazonAddress": "169.254.10.2/30", "customerAddress": "169.254.10.1/30",
                  "bgpPeerState": "available", "bgpStatus": "up", "awsDeviceV2": "EqDC2-abc"},
                 {"bgpPeerId": "dxpeer-ex02", "asn": 65010, "authKey": SECRET + "6", "addressFamily": "ipv6",
                  "amazonAddress": "2001:db8:10::2/125", "customerAddress": "2001:db8:10::1/125",
                  "bgpPeerState": "available", "bgpStatus": "up"}],
             "tags": tags(Name="nyc-primary", env="prod")},
            {"virtualInterfaceId": VIF_TRANSIT, "virtualInterfaceName": "nyc-transit", "virtualInterfaceType": "transit",
             "virtualInterfaceState": "available", "ownerAccount": ACCOUNT, "region": "us-east-1", "location": "CSVA1",
             "connectionId": LAG, "vlan": 202, "asn": 4200000001, "asnLong": 4200000001, "amazonSideAsn": 64512,
             "amazonAddress": "169.254.20.2/30", "customerAddress": "169.254.20.1/30", "addressFamily": "ipv4",
             "mtu": 8500, "directConnectGatewayId": DXGW, "siteLinkEnabled": True,
             "bgpPeers": [{"bgpPeerId": "dxpeer-ex03", "asn": 0, "asnLong": 4200000001, "addressFamily": "ipv4",
                           "amazonAddress": "169.254.20.2/30", "customerAddress": "169.254.20.1/30",
                           "bgpPeerState": "available", "bgpStatus": "down"}], "tags": []},
            {"virtualInterfaceId": VIF_PUB, "virtualInterfaceName": "public-1", "virtualInterfaceType": "public",
             "virtualInterfaceState": "available", "ownerAccount": ACCOUNT, "region": "us-east-1", "location": "EqDC2",
             "connectionId": CON, "vlan": 303, "asn": 65030, "amazonAddress": "198.51.100.2/30",
             "customerAddress": "198.51.100.1/30", "addressFamily": "ipv4",
             "routeFilterPrefixes": [{"cidr": "203.0.113.0/24"}], "bgpPeers": [], "tags": []},
        ],
        "routes": {
            VIF_PRIV: [
                {"cidr": "10.20.0.0/16", "routeDirection": "accepted", "addressFamily": "ipv4",
                 "asPath": [{"pathType": "seq", "path": ["65010"]}], "communities": ["7224:7300"],
                 "routeInstalledAt": dt.datetime(2026, 10, 20, tzinfo=dt.timezone.utc)},
                {"cidr": "10.30.0.0/16", "routeDirection": "accepted", "addressFamily": "ipv4",
                 "asPath": [{"pathType": "seq", "path": ["65010", "65010"]}, {"pathType": "set", "path": ["65100"]}]},
                {"cidr": "172.31.0.0/16", "routeDirection": "advertised", "addressFamily": "ipv4", "asPath": []},
            ],
            VIF_TRANSIT: [{"cidr": "10.40.0.0/16", "routeDirection": "accepted", "addressFamily": "ipv4",
                           "routeInstalledAt": 1792000000}],
        },
        "gateways": [{"directConnectGatewayId": DXGW, "directConnectGatewayName": "core-dxgw", "amazonSideAsn": 64512,
                      "ownerAccount": ACCOUNT, "directConnectGatewayState": "available", "tags": tags(team="net")}],
        "associations": [
            {"directConnectGatewayId": DXGW, "associationId": "assoc-ex0001", "associationState": "associated",
             "associatedGateway": {"id": TGW, "type": "transitGateway", "ownerAccount": ACCOUNT, "region": "us-east-1"},
             "allowedPrefixesToDirectConnectGateway": [{"cidr": "172.31.0.0/16"}, {"cidr": "172.30.0.0/16"}]},
            {"directConnectGatewayId": DXGW, "associationId": "assoc-ex0002", "associationState": "associated",
             "associatedGateway": {"id": VGW, "type": "virtualPrivateGateway", "ownerAccount": OTHER,
                                   "region": "us-east-2"},
             "allowedPrefixesToDirectConnectGateway": [{"cidr": "10.99.0.0/16"}]},
        ],
        "attachments": [
            {"directConnectGatewayId": DXGW, "virtualInterfaceId": VIF_PRIV, "virtualInterfaceRegion": "us-east-1",
             "virtualInterfaceOwnerAccount": ACCOUNT, "attachmentState": "attached"},
            {"directConnectGatewayId": DXGW, "virtualInterfaceId": VIF_TRANSIT, "virtualInterfaceRegion": "us-east-1",
             "virtualInterfaceOwnerAccount": ACCOUNT, "attachmentState": "attached"},
            {"directConnectGatewayId": DXGW, "virtualInterfaceId": "dxvif-exother1", "virtualInterfaceRegion": "us-west-2",
             "virtualInterfaceOwnerAccount": OTHER, "attachmentState": "attached"},
        ],
    }


class FakeDX:
    """The Direct Connect calls collect() makes, with nextToken paging (page size 1)."""

    def __init__(self, data, fail=()):
        self.data, self.fail = data, set(fail)

    def _page(self, op, key, items, nextToken=None):
        if op in self.fail:
            raise denied(op)
        i = int(nextToken or 0)
        return {key: copy.deepcopy(items[i:i + 1]), **({"nextToken": str(i + 1)} if i + 1 < len(items) else {})}

    def describe_connections(self, nextToken=None):
        return self._page("describe_connections", "connections", self.data["connections"], nextToken)

    def describe_lags(self, nextToken=None):
        return self._page("describe_lags", "lags", self.data["lags"], nextToken)

    def describe_virtual_interfaces(self, nextToken=None):
        return self._page("describe_virtual_interfaces", "virtualInterfaces", self.data["vifs"], nextToken)

    def list_virtual_interface_routes(self, virtualInterfaceId, filters, maxResults, nextToken=None):
        if ("routes", virtualInterfaceId) in self.fail:
            raise denied("ListVirtualInterfaceRoutes")
        items = [r for r in self.data["routes"].get(virtualInterfaceId, [])
                 if r["routeDirection"] == filters["routeDirection"]]
        return self._page("routes", "routes", items, nextToken)

    def describe_direct_connect_gateways(self, nextToken=None):
        return self._page("describe_direct_connect_gateways", "directConnectGateways", self.data["gateways"], nextToken)

    def describe_direct_connect_gateway_associations(self, directConnectGatewayId, nextToken=None):
        items = [a for a in self.data["associations"] if a["directConnectGatewayId"] == directConnectGatewayId]
        return self._page("describe_direct_connect_gateway_associations", "directConnectGatewayAssociations", items,
                          nextToken)

    def describe_direct_connect_gateway_attachments(self, directConnectGatewayId, nextToken=None):
        items = [a for a in self.data["attachments"] if a["directConnectGatewayId"] == directConnectGatewayId]
        return self._page("describe_direct_connect_gateway_attachments", "directConnectGatewayAttachments", items,
                          nextToken)

    def describe_direct_connect_gateway_association_proposals(self, directConnectGatewayId, nextToken=None):
        return self._page("describe_direct_connect_gateway_association_proposals",
                          "directConnectGatewayAssociationProposals", [], nextToken)


@pytest.fixture
def fake(monkeypatch):
    holder = {"dx": FakeDX(api_data())}
    monkeypatch.setattr(core, "get_client", lambda svc, session, region=None: holder["dx"])
    return holder


def snapshot(fake, data=None, generated=None, **kw):
    if data is not None:
        fake["dx"] = FakeDX(data)
    snap = core.collect(object(), ["us-east-1"], account=ACCOUNT, **kw)
    if generated:
        snap["manifest"]["generated"] = generated
    return snap


# ---------- secrets ----------

def test_fingerprint_is_salted_and_stable():
    a = core.fingerprint(VIF_PRIV, SECRET)
    assert a == core.fingerprint(VIF_PRIV, SECRET) and a.startswith("sha256:")
    assert a != core.fingerprint(VIF_TRANSIT, SECRET)
    assert core.is_fingerprint(a) and not core.is_fingerprint(SECRET) and not core.is_fingerprint(None)


def test_redact_vif_removes_every_copy_of_the_key():
    v = core.redact_vif(api_data()["vifs"][0])
    assert "customerRouterConfig" not in v
    assert SECRET not in json.dumps(v)
    assert core.is_fingerprint(v["authKey"]) and all(core.is_fingerprint(p["authKey"]) for p in v["bgpPeers"])


# ---------- collection ----------

def test_collect_reads_every_object_with_paging(fake):
    snap = snapshot(fake)
    assert core.counts(snap) == {"connection": 2, "lag": 1, "vif": 3, "dx-gateway": 1, "routes": 3}
    gw = snap["objects"][f"dx-gateway/{DXGW}"]
    assert len(gw["associations"]) == 2 and len(gw["attachments"]) == 3 and gw["proposals"] == []
    routes = snap["objects"][f"routes/{VIF_PRIV}"]
    assert [r["cidr"] for r in routes["accepted"]] == ["10.20.0.0/16", "10.30.0.0/16"]
    assert routes["accepted"][1]["as_path"] == [{"type": "seq", "path": [65010, 65010]}, {"type": "set", "path": [65100]}]
    assert [r["cidr"] for r in routes["advertised"]] == ["172.31.0.0/16"]
    assert snap["objects"][f"routes/{VIF_TRANSIT}"]["accepted"][0]["installed"].startswith("2026-")
    m = snap["manifest"]
    assert m["account"] == ACCOUNT and m["routes"] is True and m["warnings"] == [] and m["format"] == core.FORMAT
    assert SECRET not in json.dumps(snap)
    assert snap["objects"][f"connection/{CON}"]["item"]["loaIssueTime"].startswith("2026-01-02")


def test_collect_without_routes_and_with_failures(fake):
    fake["dx"] = FakeDX(api_data(), fail={"describe_lags", ("routes", VIF_PRIV),
                                          "describe_direct_connect_gateway_attachments"})
    snap = core.collect(object(), ["us-east-1"], account=ACCOUNT)
    w = " ".join(snap["manifest"]["warnings"])
    assert "describe_lags failed: AccessDeniedException" in w
    assert f"{VIF_PRIV}: ListVirtualInterfaceRoutes (advertised) failed" in w
    assert snap["objects"][f"routes/{VIF_PRIV}"]["accepted"] is None
    assert snap["objects"][f"dx-gateway/{DXGW}"]["attachments"] is None
    assert core.counts(snap)["lag"] == 0
    fake["dx"] = FakeDX(api_data(), fail={"describe_direct_connect_gateways"})
    snap = core.collect(object(), ["us-east-1"], account=ACCOUNT, routes=False)
    assert core.counts(snap)["routes"] == 0 and core.counts(snap)["dx-gateway"] == 0
    assert "DescribeDirectConnectGateways failed" in snap["manifest"]["warnings"][0]


def test_collect_needs_a_region():
    with pytest.raises(core.ValidationError):
        core.collect(object(), [], account=ACCOUNT)


def test_caller_account(monkeypatch):
    class STS:
        def __init__(self, ok):
            self.ok = ok

        def get_caller_identity(self):
            if not self.ok:
                raise denied("GetCallerIdentity")
            return {"Account": ACCOUNT}
    monkeypatch.setattr(core, "get_client", lambda svc, session, region=None: STS(True))
    assert core.caller_account(object()) == ACCOUNT
    monkeypatch.setattr(core, "get_client", lambda svc, session, region=None: STS(False))
    assert core.caller_account(object()) == "unknown-account"


# ---------- storage ----------

def test_write_and_load_round_trip(fake, tmp_path):
    snap = snapshot(fake, generated="2026-10-26T12:00:00+00:00")
    root = core.write_backup(snap, tmp_path)
    assert root == tmp_path / ACCOUNT / "20261026T120000Z"
    assert (root / "vifs" / f"{VIF_PRIV}.json").is_file() and (root / "dx-gateways" / f"{DXGW}.json").is_file()
    for f in root.rglob("*.json"):
        assert SECRET not in f.read_text()
    loaded = core.load_backup(root / "manifest.json")
    assert loaded["objects"] == snap["objects"]
    assert loaded["manifest"]["counts"]["vif"] == 3 and loaded["manifest"]["path"] == str(root)
    with pytest.raises(core.ValidationError, match="already exists"):
        core.write_backup(snap, tmp_path)


def test_load_flags_edits_and_missing_files(fake, tmp_path):
    root = core.write_backup(snapshot(fake, generated="2026-10-26T12:00:00+00:00"), tmp_path)
    f = root / "lags" / f"{LAG}.json"
    f.write_text(f.read_text().replace("nyc-lag-b", "edited"))
    (root / "connections" / f"{CON}.json").unlink()
    loaded = core.load_backup(root)
    w = " ".join(loaded["manifest"]["warnings"])
    assert "don't match the manifest hash" in w and "missing" in w
    assert f"connection/{CON}" not in loaded["objects"]


def test_load_rejects_non_backups(tmp_path):
    with pytest.raises(core.ValidationError, match="no manifest.json"):
        core.load_backup(tmp_path)
    (tmp_path / "manifest.json").write_text(json.dumps({"tool": "other"}))
    with pytest.raises(core.ValidationError, match="not written by dx_backup"):
        core.load_backup(tmp_path)
    (tmp_path / "manifest.json").write_text(json.dumps({"tool": "dx_backup", "format": 99}))
    with pytest.raises(core.ValidationError, match="format 99"):
        core.load_backup(tmp_path)


def test_resolve_latest_and_previous(fake, tmp_path):
    with pytest.raises(core.ValidationError):
        core.resolve("latest", tmp_path)
    a = core.write_backup(snapshot(fake, generated="2026-10-24T12:00:00+00:00"), tmp_path)
    with pytest.raises(core.ValidationError, match="No 'previous' backup"):
        core.resolve("previous", tmp_path)
    b = core.write_backup(snapshot(fake, generated="2026-10-25T12:00:00+00:00"), tmp_path)
    other = snapshot(fake, generated="2026-10-26T12:00:00+00:00")
    other["manifest"]["account"] = OTHER
    c = core.write_backup(other, tmp_path)
    (tmp_path / "junk" / "x").mkdir(parents=True)
    (tmp_path / "junk" / "x" / "manifest.json").write_text("{not json")
    assert core.resolve("latest", tmp_path) == c
    assert core.resolve("latest", tmp_path, ACCOUNT) == b
    assert core.resolve("previous", tmp_path, ACCOUNT) == a
    with pytest.raises(core.ValidationError, match="Only one backup of account"):
        core.resolve("previous", tmp_path)
    assert core.resolve("some/dir", tmp_path) == Path("some/dir")


# ---------- diff ----------

def changed(data_fn, fake, state=False):
    old = snapshot(fake, api_data())
    data = api_data()
    data_fn(data)
    new = snapshot(fake, data)
    return db_diff.diff(old, new, state=state)


def fields(changes, key):
    return {p: (a, b) for c in changes if c["key"] == key for p, a, b in c["fields"]}


def test_diff_identical_and_state_only(fake):
    assert changed(lambda d: None, fake) == []

    def flap(d):
        d["vifs"][0]["bgpPeers"][0]["bgpStatus"] = "down"
        d["vifs"][0]["virtualInterfaceState"] = "down"
        d["routes"][VIF_PRIV][0]["routeInstalledAt"] = dt.datetime(2026, 10, 25, tzinfo=dt.timezone.utc)
    assert changed(flap, fake) == []
    f = fields(changed(flap, fake, state=True), f"vif/{VIF_PRIV}")
    assert f["bgpPeers[ipv4 169.254.10.1/30].bgpStatus"] == ("up", "down")
    assert f["virtualInterfaceState"] == ("available", "down")


def test_diff_config_changes(fake):
    def edit(d):
        v = d["vifs"][0]
        v["vlan"] = 111
        v["authKey"] = "new-key"
        v["bgpPeers"][0]["authKey"] = "new-key"
        v["bgpPeers"].pop(1)
        v["tags"] = tags(Name="nyc-primary", env="dev", owner="netops")
        d["vifs"][2]["routeFilterPrefixes"] = [{"cidr": "203.0.113.0/24"}, {"cidr": "192.0.2.0/24"}]
        d["associations"][0]["allowedPrefixesToDirectConnectGateway"] = [{"cidr": "172.31.0.0/16"}]
        d["routes"][VIF_PRIV][1]["asPath"] = [{"pathType": "seq", "path": ["65010"]}]
        d["routes"][VIF_PRIV].append({"cidr": "10.50.0.0/16", "routeDirection": "accepted", "addressFamily": "ipv4"})
    ch = changed(edit, fake)
    f = fields(ch, f"vif/{VIF_PRIV}")
    assert f["vlan"] == (101, 111)
    assert core.is_fingerprint(f["authKey"][0]) and f["authKey"][0] != f["authKey"][1]
    assert f["bgpPeers[ipv6 2001:db8:10::1/125]"][1] is None
    assert f["tags[env]"] == ("prod", "dev") and f["tags[owner]"] == (None, "netops")
    assert fields(ch, f"vif/{VIF_PUB}")["routeFilterPrefixes[192.0.2.0/24]"] == (None, True)
    g = fields(ch, f"dx-gateway/{DXGW}")
    assert g[f"associations[{TGW}].allowedPrefixesToDirectConnectGateway[172.30.0.0/16]"] == (True, None)
    r = fields(ch, f"routes/{VIF_PRIV}")
    assert r["accepted[10.30.0.0/16].as_path"] == ("65010 65010 {65100}", "65010")
    assert r["accepted[10.50.0.0/16]"][0] is None
    text = db_diff.render_text(ch, {"account": ACCOUNT, "regions": ["us-east-1"]}, {"path": "b"})
    assert "~ authKey: auth key changed" in text and SECRET not in text and "new-key" not in text
    assert "+ routeFilterPrefixes[192.0.2.0/24]" in text and "- associations[" in text
    assert "~ vlan: 101 -> 111" in text and "~ VIF dxvif-exnyc001 (nyc-primary), us-east-1" in text
    assert db_diff.summary(ch) == {"+": 0, "-": 0, "~": 4}


def test_diff_added_and_removed_objects(fake):
    def edit(d):
        d["lags"] = []
        d["vifs"].append({**d["vifs"][2], "virtualInterfaceId": "dxvif-expub002", "virtualInterfaceName": "public-2"})
    ch = changed(edit, fake)
    ops = {c["key"]: c["op"] for c in ch}
    assert ops[f"lag/{LAG}"] == "-" and ops["vif/dxvif-expub002"] == "+"
    text = db_diff.render_text(ch, {}, {})
    assert "- LAG dxlag-ex000002 (nyc-lag-b)" in text and "+ VIF dxvif-expub002 (public-2)" in text


def test_canonical_helpers():
    assert db_diff.canonical([{"connectionId": "a"}, {"connectionId": "a"}], "connections") == \
        {"a": {"connectionId": "a"}, "a #2": {"connectionId": "a"}}
    assert db_diff.canonical([1, 2], "other") == [1, 2]
    assert db_diff.show([1, {"a": None}]) == "[1, {a: (none)}]"
    assert db_diff.show(db_diff.PrefixSet()) == "(empty)"
    assert db_diff.field_line("x", 1, None) == "- x: 1"
    assert db_diff._as_path_text([]) == "(empty)"
    assert db_diff.render_text([], {}, {}).endswith("No configuration changes.\n")


# ---------- restore plan ----------

def plan_for(fake, target_edit=None, current_edit=None):
    t, c = api_data(), api_data()
    if target_edit:
        target_edit(t)
    if current_edit:
        current_edit(c)
    target = snapshot(fake, t)
    current = snapshot(fake, c)
    return db_restore.plan(target, current)


def bash_ok(text, tmp_path):
    if not shutil.which("bash"):
        return True
    f = tmp_path / "plan.sh"
    f.write_text(text)
    return subprocess.run(["bash", "-n", str(f)], capture_output=True).returncode == 0


def test_plan_nothing_to_do(fake, tmp_path):
    p = plan_for(fake)
    assert p.empty() and "Nothing to do" in p.text and "I_REVIEWED_THIS_PLAN" in p.text
    assert bash_ok(p.text, tmp_path)


def test_plan_recreates_a_deleted_gateway_and_vifs(fake, tmp_path):
    def gone(d):
        d["gateways"], d["associations"], d["attachments"] = [], [], []
        d["vifs"] = [d["vifs"][2]]
        d["routes"] = {}
    p = plan_for(fake, current_edit=gone)
    text = p.text
    assert bash_ok(text, tmp_path)
    assert "DXGW_DXGW_0A1B2C3D4E5F60718=$(aws directconnect create-direct-connect-gateway --region us-east-1 " \
           "--direct-connect-gateway-name core-dxgw --amazon-side-asn 64512" in text
    assert f"--gateway-id {TGW} --add-allowed-prefixes-to-direct-connect-gateway cidr=172.31.0.0/16 " \
           "cidr=172.30.0.0/16" in text
    assert "create-direct-connect-gateway-association-proposal --region us-east-2" in text   # cross-account VGW
    assert "create-private-virtual-interface --region us-east-1 --connection-id dxcon-ex000001" in text
    assert '"directConnectGatewayId":"\'"$DXGW_DXGW_0A1B2C3D4E5F60718"\'"' in text
    assert '"authKey":"\'"$BGP_AUTH_KEY_DXVIF_EXNYC001"\'"' in text
    assert ': "${BGP_AUTH_KEY_DXVIF_EXNYC001:?BGP MD5 key of dxvif-exnyc001}"' in text
    assert "create-bgp-peer --region us-east-1 --virtual-interface-id \"$VIF_DXVIF_EXNYC001\"" in text
    assert "BGP_AUTH_KEY_DXVIF_EXNYC001_IPV6" in text
    assert "create-transit-virtual-interface" in text and "--query virtualInterface.virtualInterfaceId" in text
    assert '"asnLong":4200000001' in text and '"enableSiteLink":true' in text
    assert SECRET not in text
    line = next(x for x in text.splitlines() if "create-private-virtual-interface" in x)
    spec = json.loads(next(a for a in shlex.split(line) if a.startswith('{"virtualInterfaceName"')))
    assert spec["vlan"] == 101 and spec["mtu"] == 9001 and spec["tags"][0]["key"] == "Name"
    assert "Route differences" in text and f"{VIF_PRIV} accepted: missing 10.20.0.0/16, 10.30.0.0/16" in text


def test_plan_updates_in_place(fake, tmp_path):
    def target(d):
        v = d["vifs"][0]
        v["virtualInterfaceName"], v["mtu"], v["siteLinkEnabled"], v["rateLimit"] = "nyc-primary-1", 1500, True, 100
        v["tags"] = tags(Name="nyc-primary", env="prod", owner="it's netops")
        d["vifs"][1]["siteLinkEnabled"] = False
        d["connections"][0]["connectionName"] = "nyc-xc-a2"
        d["connections"][0]["encryptionMode"] = "must_encrypt"
        d["lags"][0]["minimumLinks"] = 2
        d["gateways"][0]["directConnectGatewayName"] = "core"
        d["associations"][0]["allowedPrefixesToDirectConnectGateway"] = [{"cidr": "172.31.0.0/16"},
                                                                        {"cidr": "172.29.0.0/16"}]
        d["vifs"][2]["vlan"] = 999
        d["vifs"][2]["routeFilterPrefixes"] = []

    def current(d):
        d["vifs"][0]["tags"] = tags(Name="nyc-primary", stale="x")
        d["vifs"][0]["bgpPeers"].pop(1)
        d["vifs"][0]["bgpPeers"][0]["authKey"] = "other"
        d["vifs"][1]["bgpPeers"][0]["asnLong"] = 4200000009
    p = plan_for(fake, target, current)
    t = p.text
    assert bash_ok(t, tmp_path)
    assert "update-virtual-interface-attributes --region us-east-1 --virtual-interface-id dxvif-exnyc001 " \
           "--virtual-interface-name nyc-primary-1 --mtu 1500 --enable-site-link --rate-limit 100" in t
    assert "--virtual-interface-id dxvif-exnyc002 --no-enable-site-link" in t
    assert "update-connection --region us-east-1 --connection-id dxcon-ex000001 --connection-name nyc-xc-a2 " \
           "--encryption-mode must_encrypt" in t
    assert "update-lag --region us-east-1 --lag-id dxlag-ex000002 --minimum-links 2" in t
    assert f"update-direct-connect-gateway --region us-east-1 --direct-connect-gateway-id {DXGW} " \
           "--new-direct-connect-gateway-name core" in t
    assert "update-direct-connect-gateway-association --region us-east-1 --association-id assoc-ex0001 " \
           "--add-allowed-prefixes-to-direct-connect-gateway cidr=172.29.0.0/16 " \
           "--remove-allowed-prefixes-to-direct-connect-gateway cidr=172.30.0.0/16" in t
    assert "tag-resource --region us-east-1 --resource-arn " \
           f"arn:aws:directconnect:us-east-1:{ACCOUNT}:dxvif/dxvif-exnyc001" in t
    assert "untag-resource --region us-east-1 --resource-arn " \
           f"arn:aws:directconnect:us-east-1:{ACCOUNT}:dxvif/dxvif-exnyc001 --tag-keys stale" in t
    assert "it'\"'\"'s netops" in t                     # quoting survives an apostrophe
    assert "create-bgp-peer --region us-east-1 --virtual-interface-id dxvif-exnyc001 --new-bgp-peer" in t
    assert "# dxvif-exnyc002 peer ipv4 169.254.20.1/30: ASN or auth key differs" in t
    assert ': "${BGP_AUTH_KEY_DXVIF_EXNYC001_IPV6:?' in t
    assert "# The manual steps below also need: BGP_AUTH_KEY_DXVIF_EXNYC001_IPV4" in t
    assert "#   aws directconnect delete-bgp-peer --region us-east-1 --virtual-interface-id dxvif-exnyc002 " \
           "--bgp-peer-id dxpeer-ex03" in t
    assert "# dxvif-expub001: can't be changed in place" in t and "vlan: 303 -> 999" in t
    assert "through an AWS Support case" in t
    assert not p.empty()


def test_plan_deletes_and_manual_steps_are_comments(fake, tmp_path):
    def target(d):
        d["vifs"] = d["vifs"][:1]
        d["vifs"][0]["bgpPeers"].pop(1)
        d["gateways"][0]["amazonSideAsn"] = 64999
        d["associations"] = d["associations"][1:]
        d["attachments"].append({"directConnectGatewayId": DXGW, "virtualInterfaceId": "dxvif-exother9",
                                 "virtualInterfaceOwnerAccount": OTHER, "attachmentState": "attached"})
        d["lags"].append({"lagId": "dxlag-ex000009", "lagName": "new-lag", "region": "us-east-1",
                          "location": "EqDC2", "numberOfConnections": 2, "connectionsBandwidth": "10Gbps",
                          "tags": tags(Name="new-lag")})
        d["connections"].append({"connectionId": "dxcon-ex000009", "connectionName": "lost", "region": "us-east-1",
                                 "location": "EqDC2", "bandwidth": "10Gbps", "lagId": "dxlag-ex000009",
                                 "tags": tags(Name="lost")})
        d["connections"].append({"connectionId": "dxcon-ex000010", "connectionName": "lost-hosted",
                                 "region": "us-east-1", "bandwidth": "500Mbps", "partnerName": "ExampleNet"})
        d["vifs"].append({"virtualInterfaceId": "dxvif-exhost01", "virtualInterfaceName": "hosted",
                          "virtualInterfaceType": "private", "ownerAccount": OTHER, "region": "us-east-1",
                          "connectionId": "dxcon-ex000099", "vlan": 5})
        d["vifs"].append({"virtualInterfaceId": "dxvif-exnew01", "virtualInterfaceName": "orphan",
                          "virtualInterfaceType": "public", "ownerAccount": ACCOUNT, "region": "us-east-1",
                          "connectionId": "dxcon-ex000099", "vlan": 6, "asn": 65000, "addressFamily": "ipv4",
                          "customerAddress": "198.51.100.5/30", "amazonAddress": "198.51.100.6/30"})

    def current(d):
        d["gateways"].append({"directConnectGatewayId": "dxgw-0ffffffffffffffff", "directConnectGatewayName": "extra",
                              "ownerAccount": ACCOUNT})
    p = plan_for(fake, target, current)
    t = p.text
    assert bash_ok(t, tmp_path)
    for cmd in ("delete-virtual-interface --region us-east-1 --virtual-interface-id dxvif-exnyc002",
                "delete-bgp-peer --region us-east-1 --virtual-interface-id dxvif-exnyc001 --bgp-peer-id dxpeer-ex02",
                "delete-direct-connect-gateway-association --region us-east-1 --association-id assoc-ex0001",
                "delete-direct-connect-gateway --region us-east-1 --direct-connect-gateway-id dxgw-0ffffffffffffffff"):
        line = next(x for x in t.splitlines() if cmd in x)
        assert line.startswith("# ")
    assert "Amazon side ASN was 64999" in t
    assert "VIF dxvif-exother9 was attached" in t
    assert "# physical connection dxcon-ex000009 needs a new cross-connect" in t and "--lag-id dxlag-ex000009" in t
    assert "# LAG dxlag-ex000009 needs new connections" in t and "create-lag --region us-east-1" in t
    assert "hosted connection dxcon-ex000010 (lost-hosted, 500Mbps) from ExampleNet" in t
    assert f"hosted VIF owned by account {OTHER}" in t
    assert "create-public-virtual-interface" in t and "isn't in the current configuration" in t
    assert '"routeFilterPrefixes":[]' in t
    live = [x for x in t.splitlines() if x.startswith("aws ") or "=$(aws " in x]
    assert all("delete-" not in x and "create-connection" not in x and "create-lag" not in x for x in live)


def test_plan_helpers():
    assert db_restore.sh("plain") == "plain"
    assert db_restore.sh("") == "''"
    assert db_restore.sh(db_restore.ref("X")) == '"$X"'
    assert db_restore.partition("cn-north-1") == "aws-cn" and db_restore.partition("us-gov-west-1") == "aws-us-gov"
    gw = {"kind": "dx-gateway", "id": DXGW, "item": {}}
    assert db_restore.arn(gw, ACCOUNT, "us-east-1") == f"arn:aws:directconnect::{ACCOUNT}:dx-gateway/{DXGW}"
    p = db_restore.Plan({"manifest": {}, "objects": {}}, {"manifest": {}, "objects": {}})
    vif = {"customerAddress": "169.254.1.1/30", "asn": 1, "authKey": None, "addressFamily": "ipv4"}
    assert p._peers(vif)[0]["customerAddress"] == "169.254.1.1/30"
    assert db_restore.Plan._delete_peer("dxvif-x", None, {"asn": 1, "customerAddress": "a"}) == \
        "aws directconnect delete-bgp-peer --virtual-interface-id dxvif-x --asn 1 --customer-address a"


# ---------- HTML ----------

def test_html_report(fake):
    old = snapshot(fake)
    data = api_data()
    data["vifs"][0]["virtualInterfaceName"] = "<b>nyc</b>"
    data["vifs"][0]["authKey"] = "rotated"
    data["lags"] = []
    new = snapshot(fake, data)
    new["manifest"]["warnings"] = ["a <warning>"]
    ch = db_diff.diff(old, new)
    out = render_html(ch, old, new, plan_text="echo <plan>", theme="light")
    assert "&lt;b&gt;nyc&lt;/b&gt;" in out and "<b>nyc</b>" not in out
    assert "auth key (changed)" in out and "rotated" not in out and SECRET not in out
    assert "1 removed" in out and "a &lt;warning&gt;" in out and "echo &lt;plan&gt;" in out
    assert 'data-theme="light"' in out
    assert "No configuration changes" in render_html([], old, old)
    with pytest.raises(ValueError):
        render_html([], old, old, theme="neon")
    no_key = api_data()
    no_key["vifs"][0]["bgpPeers"][1].pop("authKey")
    gained = db_diff.diff(snapshot(fake, no_key), snapshot(fake, api_data()))
    assert "auth key set" in render_html(gained, old, new)


# ---------- CLI ----------

@pytest.fixture
def cli_env(fake, monkeypatch, tmp_path):
    monkeypatch.setattr(core, "get_session", lambda profile, region: type("S", (), {"region_name": region})())
    monkeypatch.setattr(core, "caller_account", lambda session: ACCOUNT)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_cli_backup_diff_restore(cli_env, fake, capsys):
    assert dx_backup.main(["backup", "--region", "us-east-1"]) == 0
    out = capsys.readouterr().out
    assert "2 connections, 1 LAGs, 3 VIFs, 1 Direct Connect gateways, routes for 3 VIFs" in out
    first = core.resolve("latest", "backups")
    # same second -> refuse; move the first backup back in time
    first.rename(first.with_name("20261001T000000Z"))
    m = first.with_name("20261001T000000Z") / "manifest.json"
    m.write_text(m.read_text().replace('"generated": "', '"generated": "2026-10-01T00:00:00+00:00", "was": "'))
    data = api_data()
    data["vifs"][0]["mtu"] = 1500
    fake["dx"] = FakeDX(data)
    assert dx_backup.main(["backup", "--region", "us-east-1", "--json", "--no-routes"]) == 0
    assert json.loads(capsys.readouterr().out)["counts"]["routes"] == 0

    assert dx_backup.main(["diff", "previous", "latest", "-q"]) == 2
    out = capsys.readouterr().out
    assert "~ mtu: 9001 -> 1500" in out and "- routes of VIF" in out
    reports = list(Path("reports").rglob("*.html"))
    assert len(reports) == 1 and reports[0].name.startswith("dx-backup_diff_20261001T000000Z_")

    assert dx_backup.main(["diff", "latest", "--no-report"]) == 0          # vs live: same
    assert "No configuration changes" in capsys.readouterr().out
    assert dx_backup.main(["diff", "previous", "latest", "--json", "--no-report"]) == 2
    assert json.loads(capsys.readouterr().out)["summary"]["~"] == 1

    assert dx_backup.main(["restore-plan", "previous", "--against", "latest", "-o", "plan.sh"]) == 2
    assert "--mtu 9001" in Path("plan.sh").read_text()
    assert dx_backup.main(["restore-plan", "latest"]) == 0                  # live matches
    assert "Nothing to do" in capsys.readouterr().out
    assert dx_backup.main(["restore-plan", "live"]) == 1
    assert dx_backup.main(["diff", "nope/missing"]) == 1


def test_cli_live_account_mismatch_and_errors(cli_env, fake, monkeypatch, caplog):
    collect = core.collect
    assert dx_backup.main(["backup", "--regions", "us-east-1"]) == 0
    monkeypatch.setattr(core, "caller_account", lambda session: OTHER)
    assert dx_backup.main(["diff", "latest", "live", "--no-report", "-v"]) == 0
    assert "not the backup's account" in caplog.text

    def boom(*a, **k):
        raise ClientError({"Error": {"Code": "Throttling", "Message": "slow"}}, "X")
    monkeypatch.setattr(core, "collect", boom)
    assert dx_backup.main(["backup", "--region", "us-east-1"]) == 1

    def nocreds(*a, **k):
        from botocore.exceptions import NoCredentialsError
        raise NoCredentialsError()
    monkeypatch.setattr(core, "collect", nocreds)
    assert dx_backup.main(["backup", "--region", "us-east-1"]) == 1
    monkeypatch.setattr(core, "collect", collect)
    monkeypatch.setattr(core, "get_session", lambda profile, region: type("S", (), {"region_name": None})())
    for name in ("DXB_REGION", "DXB_REGIONS", "AWS_REGION", "AWS_DEFAULT_REGION"):
        monkeypatch.delenv(name, raising=False)
    assert dx_backup.main(["backup"]) == 1                                  # no region anywhere
