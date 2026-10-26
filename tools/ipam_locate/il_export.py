"""Self-contained HTML report for ipam_locate bundles.

Layout per query:
  header + status badge (resource / network / pool only / not found)
  Answer card: one row per candidate owner (account, Region, VPC, subnet, resource,
               instance), or the most specific parent CIDR with an IPAM link
  Hierarchy card: IPAM -> scope -> pools -> allocation -> VPC -> subnet -> ENI/EIP
               -> instance, with the query marked at the leaf
  detail tables: pool CIDRs, discovered resource CIDRs, resources inside a CIDR query,
               public addresses, address history; search coverage and warnings; raw JSON

Inline CSS and SVG only; no external resources. Dark by default with an in-page toggle.
"""
from __future__ import annotations

import datetime as dt
import html
import ipaddress
import json

from il_core import CONTAINS, best_cidr, console_url, locate, partition_of, resource_kind, _tag

THEMES = ("dark", "light", "auto")

# label, color per kind (AWS-ish category colors)
_ICONS = {
    "ipam": ("IPAM", "#8c4fff"), "scope": ("SCP", "#8c4fff"), "pool": ("POOL", "#8c4fff"),
    "allocation": ("ALLOC", "#7d8998"), "vpc": ("VPC", "#8c4fff"), "subnet": ("SN", "#8c4fff"),
    "eni": ("ENI", "#ed7100"), "instance": ("EC2", "#ed7100"), "eip": ("EIP", "#ed7100"),
    "public-ip": ("IP", "#ed7100"), "service": ("SVC", "#dd344c"), "query": ("◎", "#58a6ff"),
    "public-ipv4-pool": ("PUB", "#8c4fff"), "ipv6-pool": ("V6", "#8c4fff"), "unpooled": ("—", "#7d8998"),
    "anycast-ip-list": ("ANY", "#8c4fff"),
}


def _e(v) -> str:
    return html.escape("" if v is None else str(v), quote=True)


def icon(kind: str) -> str:
    label, color = _ICONS.get(kind, (kind[:4].upper(), "#7d8998"))
    w = max(28, 8 + 7 * len(label))
    return (f'<svg class="ico" width="{w}" height="20" viewBox="0 0 {w} 20" aria-hidden="true">'
            f'<rect width="{w}" height="20" rx="4" fill="{color}"/>'
            f'<text x="{w / 2}" y="14" text-anchor="middle" font-size="10.5" font-weight="700" '
            f'font-family="-apple-system,Segoe UI,Arial,sans-serif" fill="#fff">{_e(label)}</text></svg>')


def _link(text: str, url: str | None) -> str:
    return f'<a href="{_e(url)}" target="_blank" rel="noopener">{text}</a>' if url else text


def chip(kind: str, rid: str | None, region: str | None = None, name: str | None = None,
         partition: str = "aws", link_kind: str | None = None) -> str:
    if not rid:
        return '<span class="muted">—</span>'
    body = f"<code>{_e(rid)}</code>" + (f' <span class="nm">{_e(name)}</span>' if name else "")
    return f'<span class="chip">{icon(kind)}{_link(body, console_url(link_kind or kind, rid, region, partition))}</span>'


def _fmt(v) -> str:
    if v is None or v == "" or v == []:
        return '<span class="muted">—</span>'
    if isinstance(v, (list, dict)):
        return f"<code>{_e(json.dumps(v, default=str))}</code>"
    return _e(v)


def _table(headers: list[str], rows: list[list[str]], empty: str = "None") -> str:
    if not rows:
        return f'<p class="muted">{_e(empty)}</p>'
    head = "".join(f"<th>{_e(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f'<div class="tw"><table class="grid"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def _status_badge(status: str, n: int) -> str:
    return {
        "resource": f'<span class="badge ok">● Resource found{f" ({n} owners)" if n > 1 else ""}</span>',
        "network": f'<span class="badge ok">● Network found{f" ({n} owners)" if n > 1 else ""}</span>',
        "pool": '<span class="badge warn">● Pool only: no discovered resource</span>',
        "none": '<span class="badge bad">● Not found in IPAM</span>',
    }[status]


# ---------- answer ----------

def _cand_row(c: dict, part: str) -> list[str]:
    reg = c["region"]
    vpc, sub, res, inst, pub = c["vpc"] or {}, c["subnet"] or {}, c["resource"] or {}, c["instance"] or {}, c["public"]
    if res:
        kind = resource_kind(res.get("ResourceType"))
        rcell = chip(kind, res.get("ResourceId"), reg, _tag(res.get("ResourceTags")), part)
        if res.get("NetworkInterfaceAttachmentStatus"):
            rcell += f' <span class="pill">{_e(res["NetworkInterfaceAttachmentStatus"])}</span>'
    elif c["eni_id"]:
        rcell = chip("eni", c["eni_id"], reg, None, part)
    else:
        rcell = '<span class="muted">—</span>'
    if pub:
        svc = pub.get("Service")
        extra = []
        if svc and svc != "other":
            extra.append(f'<span class="pill">{_e(svc)}</span> <code>{_e(pub.get("ServiceResource"))}</code>'
                         if pub.get("ServiceResource") else f'<span class="pill">{_e(svc)}</span>')
        extra.append(f'<span class="muted">{_e(pub.get("AddressType"))}</span>')
        if pub.get("AddressAllocationId") and pub["AddressAllocationId"] != res.get("ResourceId"):
            extra.append(chip("eip", pub["AddressAllocationId"], reg, None, part))
        if c["eni_id"] and c["eni_id"] != res.get("ResourceId"):
            extra.append(chip("eni", c["eni_id"], reg, None, part))
        rcell += "<br>" + " ".join(extra)
    return [
        f"<code>{_e(c['account'])}</code>",
        f"<code>{_e(reg)}</code>",
        chip("vpc", vpc.get("ResourceId"), reg, _tag(vpc.get("ResourceTags")), part),
        chip("subnet", sub.get("ResourceId"), reg, _tag(sub.get("ResourceTags")), part),
        rcell,
        chip("instance", inst.get("ResourceId"), reg, inst.get("ResourceName"), part),
        f"<code>{_e(c['cidr'])}</code>",
    ]


def render_answer(b: dict, loc: dict, part: str) -> str:
    ipam = b.get("ipam") or {}
    home = ipam.get("IpamRegion")
    out = ['<div class="card answer"><h3>Answer</h3>']
    if loc["candidates"]:
        n = len(loc["candidates"])
        if n > 1:
            out.append(f'<p class="warnmsg">{n} owners match. Private ranges are often reused across accounts '
                       f'and VPCs; the most specific match is listed first.</p>')
        out.append(_table(["Account", "Region", "VPC", "Subnet", "Resource", "Instance", "Matched CIDR"],
                          [_cand_row(c, part) for c in loc["candidates"]]))
    ms = loc["most_specific"]
    pool = loc["deepest_pool"]
    rows = []
    if ms:
        rows.append(("Most specific parent CIDR", f'<code class="big">{_e(ms["cidr"])}</code> '
                     f'<span class="muted">from {_e(ms["source"])}</span>'))
    if pool:
        rows.append(("Most specific IPAM pool", chip("pool", pool["IpamPoolId"], home, _tag(pool.get("Tags")),
                                                     part) + f' <code>{_e(best_cidr(pool))}</code>'
                     + (f' <span class="muted">locale {_e(pool.get("Locale"))}</span>'
                        if pool.get("Locale") not in (None, "None") else "")))
    alloc = loc["allocation"]
    if alloc:
        kind = {"vpc": "vpc", "subnet": "subnet", "eip": "eip"}.get(alloc.get("ResourceType") or "", "allocation")
        rows.append(("Pool allocation", f'<code>{_e(alloc.get("Cidr"))}</code> → '
                     + (chip(kind, alloc.get("ResourceId"), alloc.get("ResourceRegion"), None, part)
                        if alloc.get("ResourceId") else _e(alloc.get("Description") or alloc.get("ResourceType")))
                     + f' <span class="muted">account</span> <code>{_e(alloc.get("ResourceOwner"))}</code>'
                     + f' <span class="muted">Region</span> <code>{_e(alloc.get("ResourceRegion"))}</code>'))
    if not loc["candidates"]:
        if pool:
            out.append('<p class="warnmsg">No discovered resource contains this address. The most specific IPAM '
                       'pool is below; open it in the IPAM console to review allocations and history.</p>')
        else:
            out.append('<p class="warnmsg">Nothing in this IPAM contains this address: no pool CIDR and no '
                       'discovered resource. Check the scope, the IPAM operating Regions, or another IPAM.</p>')
    if rows:
        out.append('<table class="kv">' + "".join(f"<tr><th>{_e(k)}</th><td>{v}</td></tr>" for k, v in rows)
                   + "</table>")
    out.append("</div>")
    return "".join(out)


# ---------- hierarchy ----------

def _node(kind: str, label: str, detail: str = "", hit: bool = False, children: list[str] | None = None) -> str:
    kids = f'<ul>{"".join(children)}</ul>' if children else ""
    # Chips already carry their own icon; only plain labels get the node icon.
    ico = "" if label.startswith('<span class="chip">') else icon(kind)
    return (f'<li><div class="tn{" hit" if hit else ""}">{ico}<span class="tl">{label}</span>'
            f'{f"<span class=td>{detail}</span>" if detail else ""}</div>{kids}</li>')


def _cand_branch(c: dict, query: str, part: str) -> str:
    """VPC -> subnet -> resource -> instance -> query, for one candidate."""
    reg = c["region"]
    by_type = {resource_kind(r.get("ResourceType")): r for r in c["records"]}
    leaf = [_node("query", f"<code>{_e(query)}</code>", "query", hit=True)]
    if c["instance"]:
        i = c["instance"]
        leaf = [_node("instance", chip("instance", i.get("ResourceId"), reg, i.get("ResourceName"), part),
                      "", children=leaf)]
    res = c["resource"]
    if res and resource_kind(res.get("ResourceType")) not in ("vpc", "subnet"):
        k = resource_kind(res.get("ResourceType"))
        leaf = [_node(k, chip(k, res.get("ResourceId"), reg, _tag(res.get("ResourceTags")), part),
                      f'<code>{_e(res.get("ResourceCidr"))}</code>', children=leaf)]
    elif c["eni_id"]:
        leaf = [_node("eni", chip("eni", c["eni_id"], reg, None, part), "", children=leaf)]
    if c["public"] and not res:
        p = c["public"]
        leaf = [_node("public-ip", f'<code>{_e(p.get("Address"))}</code>',
                      _e(" · ".join(x for x in (p.get("AddressType"), p.get("Service")) if x)), children=leaf)]
    for k in ("subnet", "vpc"):
        r = by_type.get(k) or c[k]
        if r:
            leaf = [_node(k, chip(k, r.get("ResourceId"), reg, _tag(r.get("ResourceTags")), part),
                          f'<code>{_e(r.get("ResourceCidr"))}</code>' if r.get("ResourceCidr") else "",
                          children=leaf)]
    acct = f'<span class="muted">account</span> <code>{_e(c["account"])}</code> · <code>{_e(reg)}</code>'
    return f'<li><div class="tn acct">{acct}</div><ul>{"".join(leaf)}</ul></li>'


def _within(cidr: str | None, parent: str | None) -> bool:
    try:
        a, p = ipaddress.ip_network(cidr, strict=False), ipaddress.ip_network(parent, strict=False)
        return a.version == p.version and a.subnet_of(p)
    except (TypeError, ValueError):
        return False


def render_hierarchy(b: dict, loc: dict, part: str) -> str:
    ipam = b.get("ipam") or {}
    home = ipam.get("IpamRegion")
    query = b["query"]
    scopes = {s.get("IpamScopeArn"): s for s in b.get("scopes") or []}
    placed: set[int] = set()

    def cands_under(cidr: str | None) -> list[str]:
        out = []
        for i, c in enumerate(loc["candidates"]):
            vpc_cidr = next((r.get("ResourceCidr") for r in c["records"] if r.get("ResourceType") == "vpc"),
                            c["cidr"])
            if i not in placed and _within(vpc_cidr, cidr):
                placed.add(i)
                out.append(_cand_branch(c, query, part))
        return out

    scope_nodes: dict[str, list[str]] = {}
    for chain in loc["pool_chains"]:
        deepest = chain[-1]
        alloc = loc["allocation"] if deepest is loc["deepest_pool"] else None
        kids = cands_under(best_cidr(deepest))
        if alloc:
            kind = {"vpc": "vpc", "subnet": "subnet", "eip": "eip"}.get(alloc.get("ResourceType") or "", "allocation")
            label = (chip(kind, alloc.get("ResourceId"), alloc.get("ResourceRegion"), None, part)
                     if alloc.get("ResourceId") else _e(alloc.get("Description") or alloc.get("ResourceType")))
            detail = (f'<code>{_e(alloc.get("Cidr"))}</code> <span class="muted">allocation · account</span> '
                      f'<code>{_e(alloc.get("ResourceOwner"))}</code> · <code>{_e(alloc.get("ResourceRegion"))}</code>')
            kids = [_node("allocation", label, detail, children=kids
                          or [_node("query", f"<code>{_e(query)}</code>", "query", hit=True)])]
        if not kids:
            kids = [_node("query", f"<code>{_e(query)}</code>", "query (no discovered resource)", hit=True)]
        node = kids
        for pool in reversed(chain):
            locale = pool.get("Locale")
            detail = f'<code>{_e(best_cidr(pool))}</code>' + (
                f' <span class="muted">locale {_e(locale)}</span>' if locale not in (None, "None") else "")
            node = [_node("pool", chip("pool", pool["IpamPoolId"], home, _tag(pool.get("Tags")) or
                                       pool.get("Description"), part), detail, children=node)]
        scope_nodes.setdefault(chain[0].get("IpamScopeArn"), []).extend(node)

    tree = []
    for arn, nodes in scope_nodes.items():
        s = scopes.get(arn) or {}
        sid = s.get("IpamScopeId")
        label = chip("scope", sid, home, None, part) if sid else f"<code>{_e(arn)}</code>"
        tree.append(_node("scope", label,
                          _e(f'{s.get("IpamScopeType", "")} scope'), children=nodes))
    rest = [_cand_branch(c, query, part) for i, c in enumerate(loc["candidates"]) if i not in placed]
    if rest:
        tree.append(_node("unpooled", "Not in an IPAM pool", "discovered by IPAM, not allocated from a pool",
                          children=rest))
    if not tree:
        tree.append(_node("query", f"<code>{_e(query)}</code>", "not found", hit=True))
    root = _node("ipam", chip("ipam", ipam.get("IpamId"), home, None, part),
                 f'<span class="muted">home</span> <code>{_e(home)}</code> <span class="muted">owner</span> '
                 f'<code>{_e(ipam.get("OwnerId"))}</code> <span class="muted">{_e(ipam.get("Tier"))} tier</span>',
                 children=tree)
    return f'<div class="card"><h3>Hierarchy</h3><ul class="tree">{root}</ul></div>'


# ---------- detail tables ----------

def render_details(b: dict, loc: dict, part: str) -> str:
    home = (b.get("ipam") or {}).get("IpamRegion")
    out = []
    pool_rows = [[chip("pool", p["IpamPoolId"], home, _tag(p.get("Tags")), part), f'<code>{_e(c.get("Cidr"))}</code>',
                  _e(c.get("Relation")), _e(p.get("PoolDepth")), _e(p.get("Locale")), _e(c.get("State")),
                  _e(p.get("IpamScopeType"))]
                 for p in sorted(b.get("pools") or [], key=lambda p: p.get("PoolDepth") or 0)
                 for c in p.get("MatchedCidrs", [])]
    out.append('<div class="card"><h3>Pool CIDRs touching the query</h3>'
               + _table(["Pool", "CIDR", "Relation", "Depth", "Locale", "State", "Scope"], pool_rows) + "</div>")

    def res_rows(rows):
        return [[_e(r.get("ResourceType")), chip(resource_kind(r.get("ResourceType")), r.get("ResourceId"),
                                                 r.get("ResourceRegion"), _tag(r.get("ResourceTags")), part),
                 f'<code>{_e(r.get("ResourceCidr"))}</code>', f'<code>{_e(r.get("ResourceOwnerId"))}</code>',
                 f'<code>{_e(r.get("ResourceRegion"))}</code>', _fmt(r.get("VpcId")), _fmt(r.get("SubnetId")),
                 _fmt(r.get("IpSource")), _fmt(r.get("NetworkInterfaceAttachmentStatus")),
                 _fmt(r.get("SampleTime"))] for r in rows]

    heads = ["Type", "Resource", "CIDR", "Account", "Region", "VPC", "Subnet", "IP source", "ENI status", "Sampled"]
    out.append('<div class="card"><h3>Discovered resources containing the query</h3>'
               + _table(heads, res_rows([r for r in b.get("resources") or [] if r.get("Relation") == CONTAINS]))
               + "</div>")
    if not loc["single"]:
        out.append(f'<div class="card"><h3>Discovered resources inside {_e(b["query"])} '
                   f'<span class="muted">({len(loc["within"])})</span></h3>'
                   + _table(heads, res_rows(loc["within"])) + "</div>")
    if b.get("public_addresses"):
        rows = [[f'<code>{_e(a.get("Address"))}</code>', f'<code>{_e(a.get("AddressOwnerId"))}</code>',
                 f'<code>{_e(a.get("AddressRegion"))}</code>', _fmt(a.get("AddressType")), _fmt(a.get("Service")),
                 _fmt(a.get("ServiceResource")), chip("eni", a.get("NetworkInterfaceId"), a.get("AddressRegion"),
                                                      None, part),
                 chip("instance", a.get("InstanceId"), a.get("AddressRegion"), None, part),
                 _fmt(a.get("AssociationStatus")), _fmt(a.get("SampleTime"))] for a in b["public_addresses"]]
        out.append('<div class="card"><h3>Public addresses</h3>' + _table(
            ["Address", "Account", "Region", "Type", "Service", "Service resource", "ENI", "Instance", "Association",
             "Sampled"], rows) + "</div>")
    if loc["single"]:
        rows = [[_e(h.get("ResourceType")), chip(resource_kind(h.get("ResourceType")), h.get("ResourceId"),
                                                 h.get("ResourceRegion"), h.get("ResourceName"), part),
                 f'<code>{_e(h.get("ResourceCidr"))}</code>', f'<code>{_e(h.get("ResourceOwnerId"))}</code>',
                 f'<code>{_e(h.get("ResourceRegion"))}</code>', _fmt(h.get("VpcId")),
                 _fmt(h.get("ResourceComplianceStatus")), _fmt(h.get("ResourceOverlapStatus")),
                 _fmt(h.get("SampledStartTime"))] for h in b.get("history") or []]
        out.append('<div class="card"><h3>Address history (current)</h3>' + _table(
            ["Type", "Resource", "CIDR", "Account", "Region", "VPC", "Compliance", "Overlap", "Since"], rows) + "</div>")

    disc = "".join(f'<li><code>{_e(d["IpamResourceDiscoveryId"])}</code> '
                   f'<span class="muted">owner</span> <code>{_e(d.get("OwnerId"))}</code> · '
                   f'{" ".join(f"<code>{_e(r)}</code>" for r in d.get("Regions") or []) or "no Regions"}</li>'
                   for d in b.get("discoveries") or [])
    warn = "".join(f'<li class="warnmsg">{_e(w)}</li>' for w in b.get("warnings") or [])
    out.append(f'<div class="card"><h3>Search coverage</h3><ul class="plain">{disc}</ul>'
               + (f'<h5>Warnings</h5><ul class="plain">{warn}</ul>' if warn else "") + "</div>")
    raw = json.dumps(b, indent=2, default=str)
    out.append(f'<details class="card raw"><summary>Raw API data (JSON)</summary><pre>{_e(raw)}</pre></details>')
    return "".join(out)


def render_query(b: dict) -> str:
    loc = locate(b)
    part = partition_of((b.get("ipam") or {}).get("IpamArn"))
    q = b["query"]
    kind = "address" if loc["single"] else "CIDR"
    return (f'<section class="query" id="{_e(q)}"><div class="ahead"><div><h2>{_e(q)}</h2>'
            f'<div class="muted">{_e(b.get("family"))} {kind} · IPAM <code>{_e((b.get("ipam") or {}).get("IpamId"))}'
            f'</code> · collected {_e(b.get("generated"))}</div></div>'
            f'<div class="badges">{_status_badge(loc["status"], len(loc["candidates"]))}</div></div>'
            + render_answer(b, loc, part) + render_hierarchy(b, loc, part) + render_details(b, loc, part)
            + "</section>")


_THEME_JS = (
    "document.querySelector('.themebtn').addEventListener('click',function(){"
    "var r=document.documentElement,c=r.getAttribute('data-theme');"
    "if(c==='auto')c=matchMedia('(prefers-color-scheme: light)').matches?'light':'dark';"
    "r.setAttribute('data-theme',c==='light'?'dark':'light');});"
)

_LIGHT = ("--bg:#f4f5f7;--card:#fff;--fg:#16191f;--muted:#5f6b7a;--line:#d5dbdb;--code:#eef1f4;--ok:#037f0c;"
          "--okbg:#e9f7ea;--bad:#d1321e;--badbg:#fdecea;--warn:#8d6605;--warnbg:#fff6dd;--accent:#0972d3;"
          "--hit:#e8f1fc;color-scheme:light")

CSS = """
/* Dark is the default; data-theme="light" or "auto" (follow the OS) override it. */
:root{--bg:#0f1419;--card:#192029;--fg:#e6e9ee;--muted:#9aa5b1;--line:#2e3a47;--code:#232d38;--ok:#5fd16a;--okbg:#14301a;--bad:#ff7b6b;--badbg:#3a1714;--warn:#f2c94c;--warnbg:#3a2f0c;--accent:#58a6ff;--hit:#16283d;color-scheme:dark}
:root[data-theme="light"]{LIGHT}
@media (prefers-color-scheme:light){:root[data-theme="auto"]{LIGHT}}
@media print{:root,:root[data-theme]{LIGHT}.themebtn{display:none}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:1280px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:19px;margin:0}h3{font-size:15px;margin:0 0 12px}
h5{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:12px 0 6px}
code{font:12.5px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--code);padding:1px 5px;border-radius:4px;word-break:break-all}
code.big{font-size:15px;font-weight:600}
a{color:var(--accent)}
.muted{color:var(--muted);font-weight:400}.nm{color:var(--muted)}.warnmsg{color:var(--warn)}
.top{display:flex;justify-content:space-between;align-items:flex-end;gap:12px;flex-wrap:wrap;margin-bottom:16px}
nav.toc{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 20px}
nav.toc a{background:var(--card);border:1px solid var(--line);border-radius:999px;padding:4px 12px;text-decoration:none;color:var(--fg)}
.query{margin-bottom:40px}
.ahead{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:16px;min-width:0}
.answer{border-left:4px solid var(--accent)}
.badge{display:inline-block;padding:6px 14px;border-radius:999px;font-weight:600;background:var(--code)}
.badge.ok{color:var(--ok);background:var(--okbg)}.badge.bad{color:var(--bad);background:var(--badbg)}
.badge.warn{color:var(--warn);background:var(--warnbg)}
.pill{display:inline-block;padding:0 8px;border-radius:4px;font-weight:600;font-size:12px;background:var(--code)}
.chip{display:inline-flex;align-items:center;gap:6px;margin:1px 6px 1px 0;vertical-align:middle}
.ico{flex:none}
table.kv{border-collapse:collapse;width:100%;margin-top:8px}
table.kv th{text-align:left;vertical-align:top;color:var(--muted);font-weight:500;padding:5px 12px 5px 0;width:24%;white-space:nowrap}
table.kv td{padding:5px 0;vertical-align:top}
.tw{overflow-x:auto}
table.grid{border-collapse:collapse;width:100%;font-size:13px}
table.grid th{text-align:left;color:var(--muted);font-weight:500;border-bottom:1px solid var(--line);padding:6px 10px 6px 0;white-space:nowrap}
table.grid td{border-bottom:1px solid var(--line);padding:6px 10px 6px 0;vertical-align:top}
ul.plain{list-style:none;margin:0;padding:0}ul.plain li{padding:2px 0}
ul.tree,ul.tree ul{list-style:none;margin:0;padding:0}
ul.tree ul{margin-left:14px;padding-left:16px;border-left:1px dashed var(--line)}
ul.tree li{position:relative;padding:3px 0}
ul.tree ul>li::before{content:"";position:absolute;left:-16px;top:16px;width:12px;border-top:1px dashed var(--line)}
.tn{display:inline-flex;align-items:center;flex-wrap:wrap;gap:8px;padding:4px 8px;border:1px solid var(--line);border-radius:8px;background:var(--bg)}
.tn.acct{border-style:dashed}
.tn.hit{border-color:var(--accent);background:var(--hit);font-weight:600}
.tl{display:inline-flex;align-items:center}.td{font-size:12.5px}
details.raw summary{cursor:pointer;font-weight:600}
details.raw pre{max-height:480px;overflow:auto;background:var(--code);padding:12px;border-radius:6px;font-size:12px}
.themebtn{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:999px;padding:5px 12px;cursor:pointer;font:inherit}
footer{color:var(--muted);font-size:12px;margin-top:24px}
""".replace("LIGHT", _LIGHT)


def render_html(bundles: list[dict], title: str | None = None, theme: str = "dark") -> str:
    if theme not in THEMES:
        raise ValueError(f"theme must be one of {THEMES}")
    generated = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    page_title = title or "IPAM Locate"
    toc = ('<nav class="toc">' + "".join(f'<a href="#{_e(b["query"])}">{_e(b["query"])}</a>' for b in bundles)
           + "</nav>") if len(bundles) > 1 else ""
    body = "".join(render_query(b) for b in bundles)
    return f"""<!doctype html>
<html lang="en" data-theme="{theme}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(page_title)}</title><style>{CSS}</style></head>
<body><main>
<div class="top"><div><h1>{_e(page_title)}</h1>
<div class="muted">AWS VPC IPAM · exported {generated}</div></div>
<button class="themebtn" type="button" title="Toggle light/dark">◐ Theme</button></div>
{toc}{body}
<footer>Generated from the Amazon VPC IPAM API. Discovered data reflects IPAM's last sample time.
Console links open in the account you're signed in to.</footer>
</main><script>{_THEME_JS}</script></body></html>
"""
