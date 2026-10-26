"""Cisco IOS-style views over a dx_route bundle.

Each Direct Connect gateway (or virtual private gateway, or a Region's public VIFs) is
shown as its own routing table, the way IOS shows a VRF. Where AWS doesn't report a
field IOS would print (origin, MED, message counters), the view says so instead of
inventing a value:

  show ip bgp [PREFIX [longer-prefixes]]        BGP table, or one entry with every path
  show ip bgp summary                           one line per VIF BGP session
  show ip bgp neighbors [ADDR|VIF] received-routes | advertised-routes
  show ip route [PREFIX]                        routing table, or the longest-match entry

'ipv6' works in place of 'ip' everywhere.
"""
from __future__ import annotations

import datetime as dt
import ipaddress

import dr_core as core

STATUS_LEGEND = (
    "Status codes: s suppressed, d damped, h history, * valid, > best, i - internal,\n"
    "              r RIB-failure, S Stale, m multipath, b backup-path, f RT-Filter,\n"
    "              x best-external, a additional-path, c RIB-compressed,\n"
    "Origin codes: not reported by AWS (ListVirtualInterfaceRoutes has no origin attribute)\n"
    "LocPrf: modeled from 7224:7300/7200/7100 = 300/200/100; untagged routes get 200 from a location\n"
    "        associated with the sending Region and 150 from any other. Metric (MED) is not reported.\n"
)
ROUTE_CODES = (
    "Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP\n"
    "       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area\n"
    "       + - replicated route, % - next hop override\n"
)
TABLE_HEAD = "     Network          Next Hop            Metric LocPrf Weight Path"


# ---------- helpers ----------

def uptime(iso: str | None, now: dt.datetime | None = None) -> str:
    """IOS age: hh:mm:ss under a day, 2d03h under a week, then 1w2d. 'never' if unknown."""
    if not iso:
        return "never"
    try:
        then = dt.datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
    except ValueError:
        return "never"
    if then.tzinfo is None:
        then = then.replace(tzinfo=dt.timezone.utc)
    secs = max(0, int(((now or dt.datetime.now(dt.timezone.utc)) - then).total_seconds()))
    d, rem = divmod(secs, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    if d == 0:
        return f"{h:02d}:{m:02d}:{s:02d}"
    if d < 7:
        return f"{d}d{h:02d}h"
    return f"{d // 7}w{d % 7}d"


def _now(bundle: dict) -> dt.datetime:
    """Ages are relative to when the bundle was collected, so a saved bundle re-renders the same."""
    try:
        return dt.datetime.fromisoformat(bundle["generated"])
    except (KeyError, TypeError, ValueError):
        return dt.datetime.now(dt.timezone.utc)


def _gateways(bundle: dict) -> dict[str, dict]:
    return {g["id"]: g for g in bundle.get("gateways") or []}


def table_header(bundle: dict, key: str) -> str:
    """'Routing Table: dxgw-... (name), Amazon ASN 64512' for one gateway."""
    vifs = bundle.get("vifs") or []
    if key.startswith("public:"):
        return f"Routing Table: public VIFs in {key.split(':', 1)[1]}"
    if key.startswith("unattached:"):
        return f"Routing Table: {key.split(':', 1)[1]} (not attached to a gateway)"
    g = _gateways(bundle).get(key) or {}
    name = f" ({g['name']})" if g.get("name") else ""
    asn_value = local_asn(bundle, key, vifs)
    asn = f", Amazon ASN {asn_value}" if asn_value != "?" else ""
    kind = "" if key.startswith("dxgw-") else " (virtual private gateway)"
    return f"Routing Table: {key}{name}{kind}{asn}"


def local_asn(bundle: dict, key: str, vifs: list[dict]) -> str:
    g = _gateways(bundle).get(key) or {}
    if g.get("amazon_asn"):
        return str(g["amazon_asn"])
    for v in vifs:
        if gateway_of(v) == key and v.get("amazon_asn"):
            return str(v["amazon_asn"])
    return "7224" if key.startswith("public:") else "?"


def gateway_of(vif: dict) -> str:
    return core.gateway_key(vif)


def vif_label(v: dict) -> str:
    bits = [b for b in (v.get("name"), v.get("location"), v.get("region")) if b]
    return f"{v['id']} ({', '.join(bits)})" if bits else v["id"]


def _status(p: dict) -> str:
    if not p["valid"]:
        return ""
    return "*>" if p["best"] else "*m" if p["multipath"] else "*"


def _row(status: str, network: str, next_hop: str | None, lp, path: str) -> list[str]:
    """One IOS BGP table line; a network longer than 16 characters gets its own line."""
    nh = next_hop or "0.0.0.0"
    lp_text = "" if lp is None else str(lp)
    tail = f"{nh:<20}{'':>6}{lp_text:>7}{0:>7} {path}".rstrip()
    if len(network) > 16:
        return [f" {status:<4}{network}", f" {'':<4}{'':<17}{tail}"]
    return [f" {status:<4}{network:<17}{tail}"]


def next_hop_legend(paths: list[dict]) -> list[str]:
    seen: dict[str, str] = {}
    for p in paths:
        if p.get("next_hop") and p["next_hop"] not in seen:
            bits = [b for b in (p.get("vif_name"), p.get("location"), p.get("region")) if b]
            seen[p["next_hop"]] = f"{p['vif']} ({', '.join(bits)})" if bits else p["vif"]
    if not seen:
        return []
    width = max(len(k) for k in seen)
    return ["", "Next hops:"] + [f"  {k:<{width}}  {v}" for k, v in seen.items()]


# ---------- show ip bgp ----------

def bgp_table(bundle: dict, tables: dict[str, dict], key: str, prefixes: list[str] | None = None) -> list[str]:
    table = tables.get(key) or {}
    prefixes = core.sort_prefixes(table) if prefixes is None else prefixes
    lines = [table_header(bundle, key),
             f"BGP table version is 1, local router ID is {key.split(':', 1)[-1]}",
             STATUS_LEGEND, TABLE_HEAD]
    shown = []
    for c in prefixes:
        for i, p in enumerate(table[c]["paths"]):
            lines += _row(_status(p), c if i == 0 else "", p["next_hop"],
                          None if p["type"] == core.PUBLIC else p["local_pref"], p["as_path_text"])
            shown.append(p)
    if not prefixes:
        lines.append("% Network not in table")
    lines += next_hop_legend(shown)
    return lines


def bgp_entry(bundle: dict, tables: dict[str, dict], key: str, query: ipaddress._BaseNetwork) -> list[str]:
    """'show ip bgp PREFIX': the exact prefix if AWS has it, else the longest match, with
    every path and why each non-best path lost."""
    table = tables.get(key) or {}
    cover = core.covering(table, query)
    exact = str(query) if str(query) in table else None
    prefix = exact or (cover[0] if cover else None)   # the BGP table shows invalid paths too
    lines = [table_header(bundle, key)]
    if not prefix:
        return lines + ["% Network not in table"]
    entry = table[prefix]
    paths = entry["paths"]
    best_no = next((i for i, p in enumerate(paths, 1) if p["best"]), None)
    now = _now(bundle)
    lines.append(f"BGP routing table entry for {prefix}, version 1")
    lines.append(f"Paths: ({len(paths)} available, " + (f"best #{best_no}" if best_no else "no best path")
                 + f", table {key.split(':', 1)[-1]})")
    if entry.get("multipath_count", 0) > 1:
        lines.append(f"Multipath: eBGP ({entry['multipath_count']} paths share traffic)")
    if not exact and str(query) != prefix:
        lines.append(f"  Longest match for {query}")
    lines.append("  Not advertised to any peer")
    lines.append("  Refresh Epoch 1")
    for p in paths:
        flags = ["valid" if p["valid"] else "not valid", "external"]
        if p["multipath"] and entry.get("multipath_count", 0) > 1:
            flags.append("multipath")
        if p["best"]:
            flags.append("best")
        lines.append(f"  {p['as_path_text'] or 'Local'}")
        lines.append(f"    {p['next_hop'] or '0.0.0.0'} ({p['vif']}) from {p['next_hop'] or '0.0.0.0'} ({p['vif']})")
        lp = "" if p["type"] == core.PUBLIC else f"localpref {p['local_pref']}, "
        lines.append(f"      Origin not reported, metric not reported, {lp}{', '.join(flags)}")
        if p["communities"]:
            lines.append(f"      Community: {' '.join(p['communities'])}")
        if p["type"] != core.PUBLIC:
            lines.append(f"      Local preference: {p['local_pref']} ({core.LP_NAMES.get(p['local_pref'], '?')}), "
                         f"{p['local_pref_source']}")
        lines.append(f"      AS path length {p['as_path_len']}; VIF {vif_label(_vif(bundle, p['vif']))}")
        if p.get("installed"):
            lines.append(f"      Updated {uptime(p['installed'], now)} ago")
        lines.append(f"      Best Path Evaluation: {p['evaluation']}")
    others = [c for c in cover if c != prefix]
    if others:
        lines += ["", f"Less specific prefixes that also cover {query}:"]
        for c in others:
            b = table[c]["best"]
            lines.append(f"  {c:<18} " + (f"best via {b['next_hop']} ({b['vif']})" if b else "no valid path"))
    return lines


def _vif(bundle: dict, vif_id: str) -> dict:
    return next((v for v in bundle.get("vifs") or [] if v["id"] == vif_id), {"id": vif_id})


def bgp_summary(bundle: dict, tables: dict[str, dict], key: str, fam: str | None) -> list[str]:
    vifs = [v for v in bundle.get("vifs") or [] if gateway_of(v) == key]
    counts: dict[str, int] = {}
    for r in bundle.get("routes") or []:
        if r.get("direction") == core.ACCEPTED and (not fam or r.get("family") == fam):
            counts[r["vif"]] = counts.get(r["vif"], 0) + 1
    entries = len(tables.get(key) or {})
    paths = sum(len(e["paths"]) for e in (tables.get(key) or {}).values())
    lines = [table_header(bundle, key),
             f"BGP router identifier {key.split(':', 1)[-1]}, local AS number {local_asn(bundle, key, vifs)}",
             f"{entries} network entries, {paths} paths (message and queue counters are not reported by AWS)",
             "",
             "Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd"]
    shown = []
    for v in vifs:
        peers = [p for p in v.get("peers") or [] if not fam or p.get("family") == fam] or [{}]
        for p in peers:
            nb = core.addr(p.get("customer_address")) or v["id"]
            if v.get("unreadable"):
                state = "NoAccess"
            elif v.get("state") != "available":
                state = "Idle (Admin)" if v.get("state") in ("down", "deleting", "deleted") else (v.get("state") or "Idle")
            elif p.get("status") == "down":
                state = "Active"
            else:
                state = str(counts.get(v["id"], 0))
            lines.append(f"{nb:<15} 4 {str(p.get('asn') or v.get('asn') or '?'):>12} {'-':>7} {'-':>7} {'1':>8} "
                         f"{'0':>4} {'0':>4} {'never':<8} {state}")
            shown.append({"next_hop": core.addr(p.get("customer_address")), "vif": v["id"], "vif_name": v.get("name"),
                          "location": v.get("location"), "region": v.get("region")})
    if not vifs:
        lines.append("% No BGP neighbors in this table")
    return lines + next_hop_legend(shown)


def neighbor_routes(bundle: dict, key: str, which: str, neighbor: str | None, fam: str | None) -> list[str]:
    """'show ip bgp neighbors X received-routes | advertised-routes' for each VIF in the
    table (or the one whose customer address or ID matches)."""
    direction = core.ACCEPTED if which == "received-routes" else core.ADVERTISED
    vifs = [v for v in bundle.get("vifs") or [] if gateway_of(v) == key]
    if neighbor:
        vifs = [v for v in vifs if v["id"] == neighbor or any(core.addr(p.get("customer_address")) == neighbor
                                                               for p in v.get("peers") or [])]
    lines = [table_header(bundle, key)]
    if not vifs:
        return lines + [f"% No such neighbor{' ' + neighbor if neighbor else ''}"]
    for v in vifs:
        peer = core.peer_for(v, fam)
        routes = [r for r in bundle.get("routes") or []
                  if r["vif"] == v["id"] and r.get("direction") == direction and (not fam or r.get("family") == fam)]
        lines += ["", f"Neighbor {core.addr(peer.get('customer_address')) or v['id']}, {vif_label(v)}, {which}:",
                  f"BGP table version is 1, local router ID is {key.split(':', 1)[-1]}", STATUS_LEGEND, TABLE_HEAD]
        nh = core.addr(peer.get("customer_address") if direction == core.ACCEPTED else peer.get("amazon_address"))
        for r in sorted(routes, key=lambda r: (core.net(r["cidr"]).network_address, core.net(r["cidr"]).prefixlen)):
            lines += _row("*", r["cidr"], nh, None, core.as_path_text(r["as_path"]))
        if direction == core.ADVERTISED and core.ADVERTISED not in (bundle.get("directions") or []):
            lines.append("% Advertised routes were not collected for this bundle")
        lines.append(f"\nTotal number of prefixes {len(routes)}")
    return lines


# ---------- show ip route ----------

def route_table(bundle: dict, tables: dict[str, dict], key: str, prefixes: list[str] | None = None) -> list[str]:
    table = tables.get(key) or {}
    now = _now(bundle)
    lines = [table_header(bundle, key), ROUTE_CODES]
    default = next((c for c in table if core.net(c).prefixlen == 0 and table[c]["best"]), None)
    if default:
        b = table[default]["best"]
        lines.append(f"Gateway of last resort is {b['next_hop'] or b['vif']} to network {default}\n")
    else:
        lines.append("Gateway of last resort is not set\n")
    count = 0
    for c in core.sort_prefixes(table) if prefixes is None else prefixes:
        active = [p for p in table[c]["paths"] if p["multipath"]]
        for i, p in enumerate(active):
            hop = p["next_hop"] or p["vif"]
            lead = f"B        {c} " if i == 0 else " " * (len(c) + 10)
            lines.append(f"{lead}[20/0] via {hop}, {uptime(p.get('installed'), now)}, {p['vif']}")
        count += bool(active)
    if not count:
        lines.append("% No routes in this table")
    return lines


def route_entry(bundle: dict, tables: dict[str, dict], key: str, query: ipaddress._BaseNetwork) -> list[str]:
    table = tables.get(key) or {}
    prefix = core.longest_match(table, query)
    lines = [table_header(bundle, key)]
    if not prefix:
        return lines + ["% Network not in table"]
    entry = table[prefix]
    active = [p for p in entry["paths"] if p["multipath"]]
    best = entry["best"]
    vifs = [v for v in bundle.get("vifs") or [] if gateway_of(v) == key]
    now = _now(bundle)
    first_as = next((a for s in best["as_path"] for a in s["path"]), None)
    skipped = [c for c in core.covering(table, query) if core.net(c).prefixlen > core.net(prefix).prefixlen]
    for c in skipped:
        lines.append(f"  {c} is in the BGP table but has no valid path "
                     f"({'; '.join(sorted({p['invalid_reason'] for p in table[c]['paths']}))})")
    lines.append(f"Routing entry for {prefix}" + (f" (longest match for {query})" if str(query) != prefix else ""))
    lines.append(f'  Known via "bgp {local_asn(bundle, key, vifs)}", distance 20, metric 0')
    if first_as is not None:
        lines.append(f"  Tag {first_as}, type external")
    hop = best["next_hop"] or best["vif"]
    lines.append(f"  Last update from {hop} {uptime(best.get('installed'), now)} ago")
    lines.append("  Routing Descriptor Blocks:")
    for i, p in enumerate(active):
        h = p["next_hop"] or p["vif"]
        lines.append(f"  {'*' if i == 0 else ' '} {h}, from {h}, {uptime(p.get('installed'), now)} ago, via {p['vif']}")
        lines.append("      Route metric is 0, traffic share count is 1")
        lines.append(f"      AS Hops {p['as_path_len']}")
        if first_as is not None:
            lines.append(f"      Route tag {next((a for s in p['as_path'] for a in s['path']), first_as)}")
    return lines


# ---------- dispatch ----------

def render(bundle: dict, cmd: dict) -> str:
    """Text for one parsed command (see dx_route.parse_command) across every table."""
    direction = core.ACCEPTED
    tables = core.select(bundle, direction)
    fam = "ipv6" if cmd["afi"] == "ipv6" else "ipv4"
    keys = sorted({gateway_of(v) for v in bundle.get("vifs") or []} | set(tables))
    if cmd.get("table"):
        keys = [k for k in keys if k == cmd["table"] or k.split(":", 1)[-1] == cmd["table"]]
    if cmd["kind"] == "neighbors" and cmd.get("neighbor"):
        nb = cmd["neighbor"]
        keys = [k for k in keys if any(gateway_of(v) == k and (v["id"] == nb or any(
            core.addr(p.get("customer_address")) == nb for p in v.get("peers") or [])) for v in bundle.get("vifs") or [])]
        if not keys:
            return f"% No such neighbor {nb}\n"
    query = cmd.get("prefix")
    out: list[str] = []
    for key in keys:
        if out:
            out.append("")
        fam_tables = {k: {c: e for c, e in t.items() if core.net(c).version == (6 if fam == "ipv6" else 4)}
                      for k, t in tables.items()}
        if cmd["kind"] == "bgp":
            if query and cmd.get("longer"):
                out += bgp_table(bundle, fam_tables, key, core.longer_prefixes(fam_tables.get(key) or {}, query))
            elif query:
                out += bgp_entry(bundle, fam_tables, key, query)
            else:
                out += bgp_table(bundle, fam_tables, key)
        elif cmd["kind"] == "summary":
            out += bgp_summary(bundle, fam_tables, key, fam)
        elif cmd["kind"] == "neighbors":
            out += neighbor_routes(bundle, key, cmd["which"], cmd.get("neighbor"), fam)
        elif cmd["kind"] == "route":
            if query and cmd.get("longer"):
                out += route_table(bundle, fam_tables, key, core.longer_prefixes(fam_tables.get(key) or {}, query))
            elif query:
                out += route_entry(bundle, fam_tables, key, query)
            else:
                out += route_table(bundle, fam_tables, key)
    if not keys:
        out.append("% No Direct Connect virtual interfaces in scope")
    return "\n".join(out).rstrip() + "\n"
