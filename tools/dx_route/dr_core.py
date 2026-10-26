"""Direct Connect route collection and BGP path selection for dx_route.

Two halves:

  collect()  reads the virtual interfaces in scope (one Region's VIFs, a Direct
             Connect gateway's attachments in any Region or account, or named VIFs)
             and every route each VIF has accepted from (or advertises to) the
             customer router, through ListVirtualInterfaceRoutes. Returns a
             JSON-serializable *bundle*. The AWS profile is never written into it.

  select()   pure function over a bundle: for every prefix, ranks the paths the way
             AWS documents for traffic leaving AWS toward on-premises, and says why
             each losing path lost. The Cisco-style views (dr_cisco) and the HTML
             report (dr_export) both use it, so a saved bundle re-renders offline.

AWS route selection toward on-premises (private and transit VIFs), as documented in
"Direct Connect routing policies and BGP communities":

  1. Longest prefix match.
  2. Local preference. Set by the community 7224:7300 (high), 7224:7200 (medium) or
     7224:7100 (low). Without one, a route from a Direct Connect location whose
     associated Region is the sending Region gets medium, and any other gets a lower,
     undocumented value.
  3. Shortest AS_PATH.
  4. Lowest MED. ListVirtualInterfaceRoutes doesn't return MED, so it can't be
     evaluated; routes still tied here are shown as equal-cost (ECMP) candidates.
  5. ECMP across the remaining paths.

Public VIFs use longest prefix and AS_PATH, then prefer the home Region; local
preference communities don't apply.

ListVirtualInterfaceRoutes has no "best" flag, so the result is a simulation of the
documented rules, not AWS's actual forwarding table.
"""
from __future__ import annotations

import configparser
import datetime as dt
import ipaddress
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

log = logging.getLogger("dx_route")

Network = ipaddress.IPv4Network | ipaddress.IPv6Network

ACCEPTED = "accepted"
ADVERTISED = "advertised"

# Modeled local preference values. The communities map to a documented order only;
# the numbers are for display and comparison.
LP_HIGH, LP_MEDIUM, LP_LOW = 300, 200, 100
LP_REMOTE_DEFAULT = 150   # "a lower value" than medium; AWS doesn't say how it compares with 7224:7100
LP_COMMUNITIES = {"7224:7300": LP_HIGH, "7224:7200": LP_MEDIUM, "7224:7100": LP_LOW}
LP_NAMES = {LP_HIGH: "high", LP_MEDIUM: "medium", LP_LOW: "low", LP_REMOTE_DEFAULT: "remote-Region default"}

PUBLIC = "public"
WORKERS = 8
PROFILE_EXCLUDE_SUFFIXES = ("-priv", "-cpar")


class ValidationError(ValueError):
    pass


# ---------- query ----------

def parse_prefix(value: str) -> Network:
    """'10.1.2.3' -> 10.1.2.3/32, '10.1.0.0/16' -> itself. Host bits are an error, so a
    typo like 10.1.2.3/16 isn't silently widened. Cisco's 'A.B.C.D M.M.M.M' form is
    accepted as two words joined by a space."""
    text = value.strip()
    parts = text.split()
    if len(parts) == 2 and "/" not in text:
        text = f"{parts[0]}/{parts[1]}"
    try:
        return ipaddress.ip_network(text, strict=True)
    except ValueError as e:
        raise ValidationError(f"Not a valid IP address or prefix: {value!r} ({e})") from None


def family(net: Network) -> str:
    return "ipv4" if net.version == 4 else "ipv6"


def net(cidr: str) -> Network:
    return ipaddress.ip_network(cidr, strict=False)


# ---------- sessions and profiles ----------

def get_session(profile: str | None, region: str | None) -> boto3.Session:
    return boto3.Session(profile_name=profile, region_name=region)


def get_client(service: str, session: boto3.Session, region: str | None = None):
    config = Config(retries={"max_attempts": 5, "mode": "adaptive"})
    return session.client(service, region_name=region, config=config)


def profile_account_map(config_file: str | None = None) -> dict[str, list[str]]:
    """Account ID -> profile names, from sso_account_id or the role_arn in the local AWS
    config. Profiles ending in -priv or -cpar are never picked automatically."""
    path = Path(config_file or os.getenv("AWS_CONFIG_FILE") or Path.home() / ".aws" / "config").expanduser()
    cp = configparser.RawConfigParser()
    try:
        cp.read(path)
    except configparser.Error as e:
        log.warning("Could not read %s: %s", path, e)
        return {}
    out: dict[str, list[str]] = {}
    for section in cp.sections():
        name = section[len("profile "):] if section.startswith("profile ") else section
        if section != "default" and not section.startswith("profile "):
            continue
        if name.endswith(PROFILE_EXCLUDE_SUFFIXES):
            continue
        acct = cp.get(section, "sso_account_id", fallback=None)
        if not acct:
            m = re.match(r"arn:aws[\w-]*:iam::(\d{12}):", cp.get(section, "role_arn", fallback="") or "")
            acct = m.group(1) if m else None
        if acct:
            out.setdefault(acct, []).append(name)
    return out


class Sessions:
    """boto3 sessions per account: the caller's own profile for its account, then
    --account-profile overrides, then the local AWS config (first matching profile)."""

    def __init__(self, profile: str | None, region: str | None, overrides: dict[str, str] | None = None,
                 config_file: str | None = None):
        self.base = get_session(profile, region)
        self.region = region or self.base.region_name
        self.overrides = dict(overrides or {})
        self._config_file = config_file
        self._pmap: dict[str, list[str]] | None = None
        self._caller: str | None = None
        self._cache: dict[str, boto3.Session | None] = {}

    @property
    def caller_account(self) -> str | None:
        if self._caller is None:
            try:
                self._caller = get_client("sts", self.base).get_caller_identity()["Account"]
            except ClientError as e:
                log.warning("Could not identify the caller account: %s", e)
                self._caller = ""
        return self._caller or None

    def for_account(self, account: str | None) -> boto3.Session | None:
        if not account or account == self.caller_account:
            return self.base
        if account not in self._cache:
            profile = self.overrides.get(account)
            if not profile:
                if self._pmap is None:
                    self._pmap = profile_account_map(self._config_file)
                profile = (self._pmap.get(account) or [None])[0]
            self._cache[account] = get_session(profile, self.region) if profile else None
            if profile:
                log.debug("Account %s: using a profile from the local AWS config", account)
        return self._cache[account]


def parse_account_profiles(values: Iterable[str]) -> dict[str, str]:
    out = {}
    for v in values or []:
        acct, sep, prof = v.partition("=")
        if not sep or not re.fullmatch(r"\d{12}", acct.strip()) or not prof.strip():
            raise ValidationError(f"--account-profile expects ACCOUNT_ID=PROFILE, got {v!r}")
        out[acct.strip()] = prof.strip()
    return out


# ---------- collection ----------

def _code(e: ClientError) -> str:
    return e.response.get("Error", {}).get("Code", "Error")


def _token_pages(call: Callable[..., dict], key: str, **params) -> Iterator[dict]:
    """Yield items across nextToken pages (Direct Connect has few paginators)."""
    token = None
    while True:
        page = call(**params, **({"nextToken": token} if token else {}))
        yield from page.get(key) or []
        token = page.get("nextToken")
        if not token:
            return


def _parallel(fn: Callable, items: Iterable) -> list:
    items = list(items)
    if len(items) <= 1:
        return [fn(i) for i in items]
    with ThreadPoolExecutor(max_workers=min(WORKERS, len(items))) as pool:
        return list(pool.map(fn, items))


def _vif_record(v: dict) -> dict:
    """The fields of a DescribeVirtualInterfaces item that the views need."""
    peers = [{"family": p.get("addressFamily"), "asn": p.get("asnLong") or p.get("asn"),
              "customer_address": p.get("customerAddress"), "amazon_address": p.get("amazonAddress"),
              "state": p.get("bgpPeerState"), "status": p.get("bgpStatus"),
              "device": p.get("awsLogicalDeviceId") or p.get("awsDeviceV2")}
             for p in v.get("bgpPeers") or []]
    if not peers and v.get("customerAddress"):
        peers = [{"family": v.get("addressFamily"), "asn": v.get("asnLong") or v.get("asn"),
                  "customer_address": v.get("customerAddress"), "amazon_address": v.get("amazonAddress"),
                  "state": None, "status": None, "device": v.get("awsLogicalDeviceId") or v.get("awsDeviceV2")}]
    name = next((t.get("value") for t in v.get("tags") or [] if t.get("key") == "Name"), None)
    return {
        "id": v["virtualInterfaceId"],
        "name": v.get("virtualInterfaceName") or name,
        "type": v.get("virtualInterfaceType"),
        "state": v.get("virtualInterfaceState"),
        "owner": v.get("ownerAccount"),
        "region": v.get("region"),
        "location": v.get("location"),
        "connection": v.get("connectionId"),
        "vlan": v.get("vlan"),
        "asn": v.get("asnLong") or v.get("asn"),
        "amazon_asn": v.get("amazonSideAsn"),
        "dx_gateway": v.get("directConnectGatewayId") or None,
        "vgw": v.get("virtualGatewayId") or None,
        "peers": peers,
    }


def gateway_key(vif: dict) -> str:
    """Paths only compete inside one gateway: a Direct Connect gateway, a virtual
    private gateway, or the public VIFs of a Region."""
    if vif.get("type") == PUBLIC:
        return f"public:{vif.get('region')}"
    return vif.get("dx_gateway") or vif.get("vgw") or f"unattached:{vif['id']}"


def _route_record(vif_id: str, r: dict) -> dict:
    installed = r.get("routeInstalledAt")
    if isinstance(installed, (int, float)):
        installed = dt.datetime.fromtimestamp(installed, dt.timezone.utc)
    return {
        "vif": vif_id,
        "cidr": r.get("cidr"),
        "direction": r.get("routeDirection"),
        "family": r.get("addressFamily"),
        "as_path": [{"type": s.get("pathType") or "seq", "path": [int(a) for a in s.get("path") or []]}
                    for s in r.get("asPath") or []],
        "communities": list(r.get("communities") or []),
        "device": r.get("awsLogicalDeviceId"),
        "installed": installed.isoformat() if hasattr(installed, "isoformat") else installed,
    }


def list_vif_routes(dx, vif_id: str, direction: str, fam: str | None) -> list[dict]:
    filters: dict[str, Any] = {"routeDirection": direction}
    if fam:
        filters["addressFamily"] = fam
    return [_route_record(vif_id, r) for r in
            _token_pages(dx.list_virtual_interface_routes, "routes", virtualInterfaceId=vif_id,
                         filters=filters, maxResults=100)]


def _discover_vifs(sessions: Sessions, *, regions: list[str], dx_gateway: str | None, vif_ids: list[str],
                   warnings: list[str]) -> tuple[list[dict], list[dict]]:
    """VIF records in scope, and the Direct Connect gateways involved."""
    gateways: list[dict] = []
    wanted: list[tuple[str, str | None, str | None]] = []   # (vif id, region, owner account)
    if dx_gateway:
        dx = get_client("directconnect", sessions.base, regions[0])
        gws = dx.describe_direct_connect_gateways(directConnectGatewayId=dx_gateway).get("directConnectGateways") or []
        if not gws:
            raise ValidationError(f"Direct Connect gateway {dx_gateway} not found")
        gateways = gws
        for a in dx.get_paginator("describe_direct_connect_gateway_attachments").paginate(
                directConnectGatewayId=dx_gateway):
            for att in a.get("directConnectGatewayAttachments") or []:
                if att.get("attachmentState") not in (None, "attached", "attaching"):
                    continue
                wanted.append((att["virtualInterfaceId"], att.get("virtualInterfaceRegion"),
                               att.get("virtualInterfaceOwnerAccount")))
    for vid in vif_ids:
        wanted.append((vid, None, None))

    vifs: dict[str, dict] = {}
    if wanted:
        for vid, region, owner in wanted:
            session = sessions.for_account(owner)
            if session is None:
                warnings.append(f"{vid}: owned by account {owner}, and no profile for it was found "
                                f"(pass --account-profile {owner}=PROFILE); its routes are not shown")
                vifs[vid] = {"id": vid, "region": region, "owner": owner, "dx_gateway": dx_gateway,
                             "state": "unreadable", "peers": [], "unreadable": True}
                continue
            found = None
            for r in [region] if region else regions:
                try:
                    items = get_client("directconnect", session, r).describe_virtual_interfaces(
                        virtualInterfaceId=vid).get("virtualInterfaces") or []
                except ClientError as e:
                    if _code(e) in ("DirectConnectClientException",) and not region:
                        continue
                    warnings.append(f"{vid}: DescribeVirtualInterfaces failed in {r}: {_code(e)}")
                    items = []
                if items:
                    found = items[0]
                    break
            if found:
                vifs[vid] = _vif_record(found)
            else:
                warnings.append(f"{vid}: not found" + (f" in {region}" if region else f" in {', '.join(regions)}"))
    else:
        for r in regions:
            dx = get_client("directconnect", sessions.base, r)
            for v in _token_pages(dx.describe_virtual_interfaces, "virtualInterfaces"):
                vifs[v["virtualInterfaceId"]] = _vif_record(v)
    return list(vifs.values()), gateways


def connection_record(c: dict) -> dict:
    """A DescribeConnections item: dedicated, hosted (from a partner) or a LAG member."""
    kind = "hosted" if c.get("partnerName") else "dedicated"
    return {"id": c.get("connectionId"), "name": c.get("connectionName"), "type": kind,
            "bandwidth": c.get("bandwidth"), "state": c.get("connectionState"), "partner": c.get("partnerName"),
            "provider": c.get("providerName"), "lag": c.get("lagId"), "owner": c.get("ownerAccount"),
            "location": c.get("location"), "visible": True}


def lag_record(lag: dict) -> dict:
    """A DescribeLags item. Bandwidth is the member count times the member bandwidth."""
    n, each = lag.get("numberOfConnections"), lag.get("connectionsBandwidth")
    return {"id": lag.get("lagId"), "name": lag.get("lagName"), "type": "LAG",
            "bandwidth": f"{n} x {each}" if n and each else each, "state": lag.get("lagState"), "partner": None,
            "provider": lag.get("providerName"), "lag": lag.get("lagId"), "owner": lag.get("ownerAccount"),
            "location": lag.get("location"), "visible": True}


def _collect_connections(sessions: Sessions, vifs: list[dict], warnings: list[str]) -> None:
    """Add the full location name and the connection (or LAG) details to each VIF record.
    A hosted VIF's connection belongs to the partner's account, so it isn't visible."""
    location_names: dict[str, dict[str, str]] = {}
    for region in sorted({v.get("region") for v in vifs if v.get("region") and not v.get("unreadable")}):
        try:
            dx = get_client("directconnect", sessions.base, region)
            location_names[region] = {loc["locationCode"]: loc.get("locationName")
                                      for loc in dx.describe_locations().get("locations") or []}
        except ClientError as e:
            warnings.append(f"DescribeLocations failed in {region}: {_code(e)}; showing location codes only")

    def fetch(v):
        cid = v.get("connection")
        if not cid:
            return None
        try:
            dx = get_client("directconnect", sessions.for_account(v.get("owner")), v.get("region"))
            if cid.startswith("dxlag-"):
                items = dx.describe_lags(lagId=cid).get("lags") or []
                return lag_record(items[0]) if items else None
            items = dx.describe_connections(connectionId=cid).get("connections") or []
            return connection_record(items[0]) if items else None
        except ClientError as e:
            if _code(e) not in ("DirectConnectClientException",):
                warnings.append(f"{cid}: describing the connection failed: {_code(e)}")
            return None

    readable = [v for v in vifs if not v.get("unreadable")]
    for v, conn in zip(readable, _parallel(fetch, readable)):
        names = location_names.get(v.get("region")) or {}
        v["location_name"] = names.get(v.get("location"))
        v["connection_detail"] = conn or ({"id": v["connection"], "visible": False,
                                           "note": "owned by another account (hosted VIF)"} if v.get("connection") else None)


def collect(sessions: Sessions, query: Network | None, *, regions: list[str], from_region: str,
            dx_gateway: str | None = None, vif_ids: list[str] | None = None,
            directions: tuple[str, ...] = (ACCEPTED,), fam: str | None = None) -> dict:
    """Read the VIFs in scope and their routes (all of them, for the address family) into
    a bundle. Matching against the query happens offline in select()."""
    warnings: list[str] = []
    fam = fam or (family(query) if query else None)
    vifs, gateways = _discover_vifs(sessions, regions=regions, dx_gateway=dx_gateway,
                                    vif_ids=list(vif_ids or []), warnings=warnings)
    readable = [v for v in vifs if not v.get("unreadable")]

    def fetch(job):
        v, direction = job
        try:
            session = sessions.for_account(v.get("owner"))
            dx = get_client("directconnect", session, v.get("region"))
            return list_vif_routes(dx, v["id"], direction, fam)
        except ClientError as e:
            warnings.append(f"{v['id']}: ListVirtualInterfaceRoutes ({direction}) failed: {_code(e)}")
            return []

    jobs = [(v, d) for v in readable for d in directions]
    routes = [r for batch in _parallel(fetch, jobs) for r in batch]
    _collect_connections(sessions, vifs, warnings)

    gw_ids = {v.get("dx_gateway") for v in vifs if v.get("dx_gateway")} - {g["directConnectGatewayId"] for g in gateways}
    for gid in sorted(gw_ids):
        try:
            dx = get_client("directconnect", sessions.base, regions[0])
            gateways += dx.describe_direct_connect_gateways(directConnectGatewayId=gid).get("directConnectGateways") or []
        except ClientError as e:
            warnings.append(f"{gid}: DescribeDirectConnectGateways failed: {_code(e)}")
    return {
        "tool": "dx_route",
        "generated": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "query": str(query) if query else None,
        "family": fam,
        "from_region": from_region,
        "regions": regions,
        "dx_gateway": dx_gateway,
        "directions": list(directions),
        "gateways": [{"id": g["directConnectGatewayId"], "name": g.get("directConnectGatewayName"),
                      "amazon_asn": g.get("amazonSideAsn"), "owner": g.get("ownerAccount"),
                      "state": g.get("directConnectGatewayState")} for g in gateways],
        "vifs": sorted(vifs, key=lambda v: (gateway_key(v), v.get("region") or "", v["id"])),
        "routes": routes,
        "warnings": warnings,
    }


# ---------- path attributes ----------

def as_path_length(as_path: list[dict]) -> int:
    """BGP AS_PATH length: every ASN in an AS_SEQUENCE counts, an AS_SET counts as one."""
    return sum(len(s["path"]) if s.get("type") != "set" else (1 if s["path"] else 0) for s in as_path)


def as_path_text(as_path: list[dict]) -> str:
    """Cisco notation: '65010 65010 {65020,65030}'."""
    parts = []
    for s in as_path:
        if s.get("type") == "set":
            parts.append("{" + ",".join(str(a) for a in s["path"]) + "}")
        else:
            parts.extend(str(a) for a in s["path"])
    return " ".join(parts)


def local_pref(route: dict, vif: dict, from_region: str) -> tuple[int, str]:
    """(modeled value, how it was set) for a route on a private or transit VIF."""
    for c in route.get("communities") or []:
        if c in LP_COMMUNITIES:
            return LP_COMMUNITIES[c], f"community {c}"
    if vif.get("region") == from_region:
        return LP_MEDIUM, f"default: location associated with {from_region}"
    return LP_REMOTE_DEFAULT, f"default: location associated with {vif.get('region') or 'another Region'}"


def location_text(v: dict) -> str | None:
    """'Equinix DC2, Ashburn, VA (EqDC2)', or just the code when the name isn't known."""
    code, name = v.get("location"), v.get("location_name")
    return f"{name} ({code})" if name and code else name or code


def connection_text(c: dict | None) -> str | None:
    """'dxcon-1 (name): dedicated, 10Gbps', 'dxlag-1: LAG, 2 x 10Gbps', 'dxcon-1: hosted by Partner, 1Gbps'."""
    if not c:
        return None
    head = c["id"] + (f" ({c['name']})" if c.get("name") else "")
    if not c.get("visible", True):
        return f"{head}: {c.get('note') or 'not visible'}"
    kind = f"hosted by {c['partner']}" if c.get("type") == "hosted" and c.get("partner") else c.get("type") or "?"
    if c.get("type") == "dedicated" and c.get("lag"):
        kind += f", member of {c['lag']}"
    bits = [kind, c.get("bandwidth")]
    if c.get("state") and c["state"] != "available":
        bits.append(c["state"])
    return f"{head}: " + ", ".join(b for b in bits if b)


def addr(value: str | None) -> str | None:
    """'169.254.10.1/30' -> '169.254.10.1' (Direct Connect returns peer addresses with a mask)."""
    return value.split("/")[0] if value else None


def peer_for(vif: dict, fam: str | None) -> dict:
    for p in vif.get("peers") or []:
        if not fam or p.get("family") == fam:
            return p
    return (vif.get("peers") or [{}])[0]


def path_valid(vif: dict, fam: str | None) -> tuple[bool, str | None]:
    """Whether the VIF and its BGP session for the family can carry traffic."""
    if vif.get("state") not in ("available", None):
        return False, f"VIF {vif.get('state')}"
    p = peer_for(vif, fam)
    if p.get("status") == "down":
        return False, "BGP down"
    if p.get("state") not in (None, "available", "verifying", "pending"):
        return False, f"BGP peer {p.get('state')}"
    return True, None


# ---------- selection ----------

def _rank(path: dict) -> tuple:
    """Sort key, best first. Private and transit VIFs: local preference, then AS_PATH
    (paths with equal tags share traffic whatever their home Region). Public VIFs:
    AS_PATH, then the home Region."""
    if path["type"] == PUBLIC:
        return (not path["valid"], path["as_path_len"], not path["home_region"])
    return (not path["valid"], -path["local_pref"], path["as_path_len"])


def _reason(p: dict, best: dict, public: bool) -> str:
    """IOS-XE style 'Best Path Evaluation' text for a path that is not the best."""
    if not p["valid"]:
        return f"Path not valid ({p['invalid_reason']})"
    if not public and p["local_pref"] != best["local_pref"]:
        note = ""
        if LP_REMOTE_DEFAULT in (p["local_pref"], best["local_pref"]) and LP_LOW in (p["local_pref"], best["local_pref"]):
            note = " (assumed: AWS doesn't document how its remote-Region default compares with 7224:7100)"
        return f"Lower local preference{note}"
    if p["as_path_len"] != best["as_path_len"]:
        return "Longer AS path"
    if public and p["home_region"] != best["home_region"]:
        return "Not from the home Region"
    return "Multipath candidate (equal cost; MED not visible)"


def select(bundle: dict, direction: str = ACCEPTED) -> dict:
    """For each gateway: {prefix: entry}, where entry has the ranked paths, the best
    path, its multipath (ECMP) siblings, and the reason each other path lost."""
    vifs = {v["id"]: v for v in bundle.get("vifs") or []}
    from_region = bundle.get("from_region")
    out: dict[str, dict[str, dict]] = {}
    for r in bundle.get("routes") or []:
        if r.get("direction") != direction or r["vif"] not in vifs:
            continue
        vif = vifs[r["vif"]]
        public = vif.get("type") == PUBLIC
        valid, why = path_valid(vif, r.get("family"))
        lp, lp_src = (LP_MEDIUM, "not used on public VIFs") if public else local_pref(r, vif, from_region)
        peer = peer_for(vif, r.get("family"))
        path = {
            "vif": vif["id"], "vif_name": vif.get("name"), "region": vif.get("region"), "location": vif.get("location"),
            "location_name": vif.get("location_name"), "connection": vif.get("connection_detail"),
            "type": vif.get("type"), "owner": vif.get("owner"),
            "next_hop": addr(peer.get("customer_address")), "amazon_address": addr(peer.get("amazon_address")),
            "peer_asn": peer.get("asn") or vif.get("asn"),
            "as_path": r["as_path"], "as_path_text": as_path_text(r["as_path"]), "as_path_len": as_path_length(r["as_path"]),
            "communities": r.get("communities") or [], "local_pref": lp, "local_pref_source": lp_src,
            "home_region": vif.get("region") == from_region,
            "valid": valid, "invalid_reason": why, "installed": r.get("installed"), "device": r.get("device"),
        }
        entry = out.setdefault(gateway_key(vif), {}).setdefault(r["cidr"], {"prefix": r["cidr"], "paths": [], "public": public})
        entry["paths"].append(path)
    for table in out.values():
        for entry in table.values():
            paths = sorted(entry["paths"], key=lambda p: (_rank(p), p["vif"]))
            entry["paths"] = paths
            best = paths[0] if paths and paths[0]["valid"] else None
            entry["best"] = best
            for i, p in enumerate(paths):
                p["best"] = p is best
                p["multipath"] = bool(best) and p["valid"] and _rank(p) == _rank(best)
                p["evaluation"] = ("Overall best path" if p["best"] else
                                   _reason(p, best, entry["public"]) if best else f"Path not valid ({p['invalid_reason']})")
            entry["multipath_count"] = sum(1 for p in paths if p["multipath"])
    return out


def sort_prefixes(prefixes: Iterable[str]) -> list[str]:
    """Most specific first: longest prefix length, then network address."""
    return sorted(prefixes, key=lambda c: (net(c).version, -net(c).prefixlen, net(c).network_address))


def covering(table: dict[str, dict], query: Network) -> list[str]:
    """Prefixes in the table that contain the query, longest first."""
    hits = [c for c in table if net(c).version == query.version and query.subnet_of(net(c))]
    return sorted(hits, key=lambda c: -net(c).prefixlen)


def longest_match(table: dict[str, dict], query: Network) -> str | None:
    """The most specific prefix that contains the query and has a usable path."""
    for c in covering(table, query):
        if table[c]["best"]:
            return c
    return None


def longer_prefixes(table: dict[str, dict], query: Network) -> list[str]:
    """Prefixes equal to or inside the query (Cisco 'longer-prefixes')."""
    return sort_prefixes(c for c in table if net(c).version == query.version and net(c).subnet_of(query))


# ---------- report path ----------

def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-")[:80] or "all"


def report_path(bundle: dict, command: str, reports_dir: str | Path) -> Path:
    """<reports_dir>/<YYYY-MM-DD>/<scope>/dx-route_<command>.html, where the scope is the
    Direct Connect gateway or the Region."""
    day = (bundle.get("generated") or dt.datetime.now(dt.timezone.utc).isoformat())[:10]
    scope = bundle.get("dx_gateway") or "-".join(bundle.get("regions") or []) or "dx"
    return Path(reports_dir) / day / _slug(scope) / f"dx-route_{_slug(command.replace('/', '_'))}.html"
