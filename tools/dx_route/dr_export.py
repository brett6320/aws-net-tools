"""Self-contained HTML report for dx_route.

One page per command: the answer (best path and why), the Cisco-style output as it
appears in the terminal, the path-selection table for the longest-match prefix in
each routing table, the VIFs in scope, warnings and notes on the method, and the raw
bundle. Every value from AWS is HTML-escaped.
"""
from __future__ import annotations

import datetime as dt
import html
import json

import dr_cisco as cisco
import dr_core as core
from dr_theme import CSS, THEME_JS

THEMES = ("dark", "light", "auto")


def _e(v) -> str:
    return html.escape("" if v is None else str(v), quote=True)


def _table(headers: list[str], rows: list[list[str]], empty: str = "None") -> str:
    if not rows:
        return f'<p class="muted">{_e(empty)}</p>'
    head = "".join(f"<th>{_e(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f'<div class="tw"><table class="grid"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def _code(v) -> str:
    return f"<code>{_e(v)}</code>" if v not in (None, "") else '<span class="nm">—</span>'


def _state(p: dict) -> str:
    if p["best"]:
        return '<span class="badge ok">best</span>'
    if p["multipath"]:
        return '<span class="badge ok">multipath</span>'
    if not p["valid"]:
        return '<span class="badge bad">not valid</span>'
    return '<span class="badge">inactive</span>'


def _vif_cell(p: dict) -> str:
    v = {"location": p.get("location"), "location_name": p.get("location_name")}
    bits = [b for b in (p.get("vif_name"), core.location_text(v), p.get("region")) if b]
    conn = core.connection_text(p.get("connection"))
    return (f"{_code(p['vif'])}<div class='td muted'>{_e(' · '.join(bits))}</div>"
            + (f"<div class='td muted'>{_e(conn)}</div>" if conn else ""))


def selection_card(bundle: dict, tables: dict, key: str, query) -> str:
    """Paths for the longest-match prefix (or the exact prefix) in one routing table."""
    table = tables.get(key) or {}
    prefix = (str(query) if str(query) in table else core.longest_match(table, query)) if query else None
    if not prefix:
        return ""
    entry = table[prefix]
    rows = []
    for p in entry["paths"]:
        lp = "n/a (public VIF)" if p["type"] == core.PUBLIC else \
            f"{p['local_pref']} ({core.LP_NAMES.get(p['local_pref'], '?')})<div class='td muted'>{_e(p['local_pref_source'])}</div>"
        rows.append([_state(p), _vif_cell(p), _code(p["next_hop"]), lp,
                     f"{_code(p['as_path_text'] or '(empty)')}<div class='td muted'>length {p['as_path_len']}</div>",
                     " ".join(_code(c) for c in p["communities"]) or '<span class="nm">—</span>',
                     _e(p["evaluation"])])
    title = f"{prefix}" + (f" (longest match for {query})" if str(query) != prefix else "")
    return (f'<div class="card"><h3>Path selection · {_e(cisco.table_header(bundle, key)[len("Routing Table: "):])}</h3>'
            f'<p><code class="big">{_e(title)}</code></p>'
            + _table(["State", "VIF", "Next hop", "Local pref", "AS path", "Communities", "Best path evaluation"], rows)
            + "</div>")


def answer_card(bundle: dict, tables: dict, cmd: dict) -> str:
    query = cmd.get("prefix")
    rows = [["Command", _code(cmd["text"])],
            ["Scope", _e(f"Direct Connect gateway {bundle['dx_gateway']}" if bundle.get("dx_gateway")
                         else "Regions " + ", ".join(bundle.get("regions") or []))],
            ["Traffic from", _e(bundle.get("from_region"))],
            ["VIFs", _e(len(bundle.get("vifs") or []))],
            ["Routes collected", _e(len(bundle.get("routes") or []))]]
    badges = []
    if query and cmd["kind"] in ("bgp", "route") and not cmd.get("longer"):
        for key, table in sorted(tables.items()):
            prefix = core.longest_match(table, query)
            if prefix:
                b = table[prefix]["best"]
                n = table[prefix]["multipath_count"]
                via = f"{b['vif']}" + (f" + {n - 1} more (ECMP)" if n > 1 else "")
                gw = next((g for g in bundle.get("gateways") or [] if g["id"] == key), {})
                label = gw.get("name") or key.split(":", 1)[-1]
                badges.append(f'<span class="badge ok">{_e(label)}: {_e(prefix)} via {_e(via)}</span>')
        if not badges:
            badges.append(f'<span class="badge bad">No route to {_e(query)}</span>')
    head = "<div>" + " ".join(badges) + "</div>" if badges else ""
    kv = "".join(f"<tr><th>{_e(k)}</th><td>{v}</td></tr>" for k, v in rows)
    return f'<div class="card answer">{head}<table class="kv">{kv}</table></div>'


def vifs_card(bundle: dict) -> str:
    rows = []
    for v in bundle.get("vifs") or []:
        peers = "<br>".join(_e(f"{p.get('family')}: {core.addr(p.get('customer_address')) or '?'} AS {p.get('asn') or '?'}"
                               f" · {p.get('status') or p.get('state') or '?'}") for p in v.get("peers") or [])
        c = v.get("connection_detail") or {}
        if c and not c.get("visible", True):
            conn, bw, ctype = _code(c["id"]) + f"<div class='td muted'>{_e(c.get('note'))}</div>", "—", "—"
        elif c:
            conn = _code(c["id"]) + (f"<div class='td muted'>{_e(c['name'])}</div>" if c.get("name") else "")
            bw = _e(c.get("bandwidth") or "—")
            ctype = _e(f"hosted by {c['partner']}" if c.get("type") == "hosted" and c.get("partner") else c.get("type"))
            if c.get("type") == "dedicated" and c.get("lag"):
                ctype += f"<div class='td muted'>member of {_e(c['lag'])}</div>"
        else:
            conn = bw = ctype = '<span class="nm">—</span>'
        loc = (f"{_e(v['location_name'])}<div class='td muted'>{_e(v.get('location'))}</div>"
               if v.get("location_name") else _e(v.get("location")))
        rows.append([_code(v["id"]), _e(v.get("name")), _e(v.get("type")), _e(v.get("state")), loc,
                     _e(v.get("region")), conn, bw, ctype, _code(core.gateway_key(v).split(":", 1)[-1]),
                     _e(v.get("owner")), peers or '<span class="nm">—</span>'])
    return ('<div class="card"><h3>Virtual interfaces</h3>'
            + _table(["VIF", "Name", "Type", "State", "Location", "Region", "Connection", "Bandwidth",
                      "Connection type", "Table", "Owner", "BGP peers"], rows, "No VIFs in scope") + "</div>")


NOTES = """<ul class="plain">
<li>Routes come from <code>ListVirtualInterfaceRoutes</code>, which has no best-path flag. The selection is a
simulation of the order AWS documents for traffic toward on-premises: longest prefix, then local preference
(<code>7224:7300</code>/<code>7200</code>/<code>7100</code>; untagged routes get medium from locations associated
with the sending Region and a lower value otherwise), then AS_PATH length, then MED, then ECMP.</li>
<li>MED and origin aren't returned by the API, so paths still tied after AS_PATH are shown as equal-cost.</li>
<li>Paths compete only inside one Direct Connect gateway, virtual private gateway, or a Region's public VIFs.
A transit gateway behind a Direct Connect gateway then compares this route with its other routes (static,
VPC, VPN, Connect); that step isn't shown.</li>
</ul>"""


def render_html(bundle: dict, cmd: dict, output: str, title: str | None = None, theme: str = "dark") -> str:
    if theme not in THEMES:
        raise ValueError(f"theme must be one of {THEMES}")
    tables = core.select(bundle)
    fam_v = 6 if cmd["afi"] == "ipv6" else 4
    tables = {k: {c: e for c, e in t.items() if core.net(c).version == fam_v} for k, t in tables.items()}
    query = cmd.get("prefix")
    sel = "".join(selection_card(bundle, tables, k, query) for k in sorted(tables)) \
        if query and cmd["kind"] in ("bgp", "route") and not cmd.get("longer") else ""
    warns = "".join(f"<li class='warnmsg'>{_e(w)}</li>" for w in bundle.get("warnings") or [])
    warn_card = f'<div class="card"><h3>Warnings</h3><ul class="plain">{warns}</ul></div>' if warns else ""
    raw = json.dumps(bundle, indent=2, default=str)
    page_title = title or f"dx_route · {cmd['text']}"
    generated = bundle.get("generated") or dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    return f"""<!doctype html>
<html lang="en" data-theme="{theme}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(page_title)}</title><style>{CSS}</style></head>
<body><main>
<div class="top"><div><h1>{_e(page_title)}</h1>
<div class="muted">AWS Direct Connect · collected {_e(generated)}</div></div>
<button class="themebtn" type="button" title="Toggle light/dark">◐ Theme</button></div>
{answer_card(bundle, tables, cmd)}
<div class="card"><h3>Router output</h3><pre class="term">Router# {_e(cmd['text'])}
{_e(output)}</pre></div>
{sel}{vifs_card(bundle)}{warn_card}
<div class="card"><h3>How the path is chosen</h3>{NOTES}</div>
<div class="card"><details class="raw"><summary>Raw bundle (JSON)</summary><pre>{_e(raw)}</pre></details></div>
<footer>Generated from the AWS Direct Connect API (BGP route visibility). A simulation of AWS's documented path
selection, not AWS's forwarding table.</footer>
</main><script>{THEME_JS}</script></body></html>
"""
