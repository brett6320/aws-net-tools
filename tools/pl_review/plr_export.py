"""Self-contained HTML report for pl_review.

Renders PrefixListReport.to_dict() (the same data as the JSON report), so a saved
JSON report renders the same way. Layout:

  header + verdict badge (at risk / ok / partly evaluated)
  summary cards: prefix list size now -> proposed, limit, groups, accounts
  security groups: one row per group and direction, at-risk first, with a weight bar
               (current weight, growth from the proposed length, the limit) and the
               prefix lists that make up the weight; search and "at risk only" filter
  Firewall Manager policies (when any replicas were found), coverage, raw JSON

Inline CSS and JS only; no external resources. Dark by default with an in-page toggle.
"""
from __future__ import annotations

import html
import json
from typing import Any

THEMES = ("dark", "light", "auto")


def _e(v: Any) -> str:
    return html.escape("" if v is None else str(v), quote=True)


def _status(u: dict) -> str:
    return "EXCEEDS" if u.get("exceeds_proposed") else ("OVER NOW" if u.get("exceeds_now") else "ok")


_PILL = {"EXCEEDS": "bad", "OVER NOW": "warn", "ok": "ok", "ERROR": "warn"}


def _pill(status: str) -> str:
    return f'<span class="pill {_PILL.get(status, "")}">{_e(status)}</span>'


def _verdict(d: dict) -> str:
    n = d.get("at_risk_count") or 0
    errors = d.get("error_count") or 0
    if n:
        return f'<span class="badge bad">{n} security group{"s" if n != 1 else ""} would exceed the limit</span>'
    if errors:
        return f'<span class="badge warn">No group at risk · {errors} not evaluated</span>'
    return '<span class="badge ok">No security group at risk</span>'


def _bar(u: dict, limit: int) -> str:
    """Current weight, growth to the proposed weight, and the limit, on one scale."""
    now, prop = u.get("current_weight") or 0, u.get("proposed_weight") or 0
    scale = max(limit, prop, now, 1) * 1.05
    lo, hi = sorted((now, prop))
    cls = "bad" if prop > limit else ("warn" if now > limit else "")
    grow = "grow" if prop >= now else "shrink"
    return (f'<div class="bar {cls}" title="now {now}, proposed {prop}, limit {limit}">'
            f'<i class="now" style="width:{lo / scale:.1%}"></i>'
            f'<i class="{grow}" style="left:{lo / scale:.1%};width:{(hi - lo) / scale:.1%}"></i>'
            f'<b style="left:{limit / scale:.1%}"></b></div>')


def _pl_cell(u: dict, target: str, proposed: int) -> str:
    """Prefix lists behind the weight: id x refs = weight (the target at its proposed length)."""
    refs, weights = u.get("prefix_lists") or {}, u.get("pl_weights") or {}
    if not refs:
        return '<span class="muted">—</span>'
    items = []
    for pid, n in sorted(refs.items(), key=lambda kv: (kv[0] != target, kv[0])):
        if pid == target:
            items.append(f'<li class="tgt"><code>{_e(pid)}</code> ×{n} = {n * proposed}'
                         f' <span class="muted">(now {n * weights.get(pid, 0)})</span></li>')
        elif pid in weights:
            items.append(f'<li><code>{_e(pid)}</code> ×{n} = {n * weights[pid]}</li>')
        else:
            items.append(f'<li><code>{_e(pid)}</code> ×{n}</li>')
    return f'<ul class="plain">{"".join(items)}</ul>'


def _sg_rows(d: dict) -> str:
    target, proposed, limit = d["prefix_list_id"], d.get("proposed_length") or 0, d.get("limit") or 0
    out = []
    for sg in d.get("security_groups") or []:
        name = _e(sg.get("group_name") or "?")
        if sg.get("fm_managed"):
            name = (f'<span class="pill fm" title="Firewall Manager policy {_e(sg.get("fm_policy_id"))}">FM</span> '
                    + name)
        vpc = f'<div class="muted">{_e(sg["vpc_id"])}</div>' if sg.get("vpc_id") else ""
        ident = (f'<td><code>{_e(sg.get("account_id") or "?")}</code></td>'
                 f'<td><code>{_e(sg.get("group_id") or "?")}</code><div>{name}</div>{vpc}</td>')
        search = " ".join(_e(x) for x in (sg.get("account_id"), sg.get("group_id"), sg.get("group_name"),
                                         sg.get("vpc_id"), sg.get("fm_policy_id"), sg.get("profile")) if x)
        if sg.get("error"):
            out.append(f'<tr class="err" data-risk="0" data-s="{search}">{ident}<td>—</td>'
                       f'<td colspan="6" class="warnmsg">Not evaluated: {_e(sg["error"])}</td>'
                       f'<td>{_pill("ERROR")}</td></tr>')
            continue
        dirs = [sg["ingress"], sg["egress"]]
        for i, u in enumerate(dirs):
            status = _status(u)
            first = (ident.replace("<td>", '<td rowspan="2">') if i == 0 else "")
            out.append(
                f'<tr class="{"first" if i == 0 else "second"}" data-risk="{int(bool(sg.get("at_risk")))}" '
                f'data-s="{search}">{first}<td>{_e(u.get("direction"))}</td>'
                f'<td class="n">{u.get("rule_count", 0)}</td><td class="n">{u.get("current_weight", 0)}</td>'
                f'<td class="n"><b>{u.get("proposed_weight", 0)}</b></td>'
                f'<td class="n {"neg" if (u.get("headroom_proposed") or 0) < 0 else ""}">'
                f'{u.get("headroom_proposed", 0)}</td>'
                f'<td class="barcell">{_bar(u, limit)}</td><td>{_pl_cell(u, target, proposed)}</td>'
                f'<td>{_pill(status)}</td></tr>')
    return "".join(out)


def _fm_table(d: dict) -> str:
    pols = d.get("fm_policies") or {}
    if not pols:
        return ""
    rows = "".join(
        f'<tr><td><code>{_e(pid)}</code></td><td class="n">{r.get("replicas", 0)}</td>'
        f'<td class="n">{r.get("account_count", len(r.get("accounts") or []))}</td>'
        f'<td class="n">{r.get("at_risk", 0)}</td><td class="n">{r.get("errors", 0)}</td>'
        f'<td class="n">{r.get("max_proposed_ingress", 0)}</td><td class="n">{r.get("max_proposed_egress", 0)}</td></tr>'
        for pid, r in sorted(pols.items()))
    return ('<div class="card"><h3>Firewall Manager policies</h3><p class="muted">Replicas of one policy share '
            'the same rules, so one replica at risk usually means the policy needs its rules trimmed.</p>'
            '<div class="tw"><table class="grid"><thead><tr><th>Policy</th><th class="n">Replicas</th>'
            '<th class="n">Accounts</th><th class="n">At risk</th><th class="n">Not evaluated</th>'
            '<th class="n">Max proposed ingress</th><th class="n">Max proposed egress</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div></div>')


def _cards(d: dict) -> str:
    sgs = d.get("security_groups") or []
    accounts = {s.get("account_id") for s in sgs if s.get("account_id")}
    over_now = sum(1 for s in sgs if not s.get("error") and (s["ingress"].get("exceeds_now") or s["egress"].get("exceeds_now")))
    cur, prop = d.get("current_max_entries") or 0, d.get("proposed_length") or 0
    delta = prop - cur
    cards = [
        (f'{cur} → {prop}', f'MaxEntries ({"+" if delta >= 0 else ""}{delta})', ""),
        (d.get("current_entry_count", 0), "entries in use", ""),
        (d.get("limit", 0), "rule limit per direction", ""),
        (len(sgs), "security groups", ""),
        (len(accounts), "accounts", ""),
        (d.get("at_risk_count", 0), "would exceed", "bad" if d.get("at_risk_count") else ""),
        (over_now, "over the limit now", "warn" if over_now else ""),
        (d.get("error_count", 0), "not evaluated", "warn" if d.get("error_count") else ""),
    ]
    return '<div class="cards">' + "".join(
        f'<div class="stat {cls}"><b>{_e(v)}</b><span>{_e(label)}</span></div>' for v, label, cls in cards) + "</div>"


def _coverage(d: dict) -> str:
    missing = d.get("accounts_without_profile") or []
    scanned = d.get("profiles_scanned") or []
    rows = [("Owner account", f'<code>{_e(d.get("owner_account"))}</code> via <code>{_e(d.get("owner_profile"))}</code>'),
            ("Profiles scanned", ", ".join(f"<code>{_e(p)}</code>" for p in scanned) or "—")]
    if missing:
        rows.append(("Accounts without a profile", '<span class="warnmsg">'
                     + ", ".join(f"<code>{_e(a)}</code>" for a in missing)
                     + "</span> (their groups are listed as not evaluated)"))
    return ('<div class="card"><h3>Coverage</h3><table class="kv">'
            + "".join(f"<tr><th>{k}</th><td>{v}</td></tr>" for k, v in rows) + "</table></div>")


_JS = (
    "document.querySelector('.themebtn').addEventListener('click',function(){"
    "var r=document.documentElement,c=r.getAttribute('data-theme');"
    "if(c==='auto')c=matchMedia('(prefers-color-scheme: light)').matches?'light':'dark';"
    "r.setAttribute('data-theme',c==='light'?'dark':'light');});"
    "(function(){var q=document.getElementById('q'),k=document.getElementById('risk'),"
    "rows=[].slice.call(document.querySelectorAll('#sgs tbody tr')),cnt=document.getElementById('cnt');"
    "function f(){var t=q.value.toLowerCase(),n=0,seen={};rows.forEach(function(r){"
    "var ok=(!k.checked||r.dataset.risk==='1')&&(!t||r.dataset.s.toLowerCase().indexOf(t)>=0);"
    "r.style.display=ok?'':'none';if(ok&&!r.classList.contains('second'))n++;});"
    "cnt.textContent=n+' of '+rows.filter(function(r){return !r.classList.contains('second')}).length;}"
    "q.addEventListener('input',f);k.addEventListener('change',f);f();})();"
)

_LIGHT = ("--bg:#f4f5f7;--card:#fff;--fg:#16191f;--muted:#5f6b7a;--line:#d5dbdb;--code:#eef1f4;--ok:#037f0c;"
          "--okbg:#e9f7ea;--bad:#d1321e;--badbg:#fdecea;--warn:#8d6605;--warnbg:#fff6dd;--accent:#0972d3;"
          "--fm:#7b3fe4;--fmbg:#f1eafd;color-scheme:light")

CSS = """
/* Dark is the default; data-theme="light" or "auto" (follow the OS) override it. */
:root{--bg:#0f1419;--card:#192029;--fg:#e6e9ee;--muted:#9aa5b1;--line:#2e3a47;--code:#232d38;--ok:#5fd16a;--okbg:#14301a;--bad:#ff7b6b;--badbg:#3a1714;--warn:#f2c94c;--warnbg:#3a2f0c;--accent:#58a6ff;--fm:#b59bff;--fmbg:#2a2140;color-scheme:dark}
:root[data-theme="light"]{LIGHT}
@media (prefers-color-scheme:light){:root[data-theme="auto"]{LIGHT}}
@media print{:root,:root[data-theme]{LIGHT}.themebtn,.filters{display:none}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:1280px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:19px;margin:0}h3{font-size:15px;margin:0 0 12px}
code{font:12.5px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--code);padding:1px 5px;border-radius:4px;word-break:break-all}
.muted{color:var(--muted);font-weight:400}.warnmsg{color:var(--warn)}
p.muted{margin:-6px 0 12px}
.top{display:flex;justify-content:space-between;align-items:flex-end;gap:12px;flex-wrap:wrap;margin-bottom:16px}
.ahead{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:16px;min-width:0}
.badge{display:inline-block;padding:6px 14px;border-radius:999px;font-weight:600;background:var(--code)}
.badge.ok{color:var(--ok);background:var(--okbg)}.badge.bad{color:var(--bad);background:var(--badbg)}
.badge.warn{color:var(--warn);background:var(--warnbg)}
.pill{display:inline-block;padding:0 8px;border-radius:4px;font-weight:600;font-size:12px;background:var(--code);white-space:nowrap}
.pill.ok{color:var(--ok);background:var(--okbg)}.pill.bad{color:var(--bad);background:var(--badbg)}
.pill.warn{color:var(--warn);background:var(--warnbg)}.pill.fm{color:var(--fm);background:var(--fmbg)}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px;margin-bottom:16px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 14px}
.stat b{display:block;font-size:20px}.stat span{color:var(--muted);font-size:12px}
.stat.bad{border-color:var(--bad)}.stat.bad b{color:var(--bad)}.stat.warn b{color:var(--warn)}
.filters{display:flex;gap:16px;align-items:center;flex-wrap:wrap;margin-bottom:10px}
.filters input[type=search]{background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:5px 10px;font:inherit;min-width:240px}
.tw{overflow-x:auto}
table.grid{border-collapse:collapse;width:100%;font-size:13px}
table.grid th{text-align:left;color:var(--muted);font-weight:500;border-bottom:1px solid var(--line);padding:6px 10px 6px 0;white-space:nowrap}
table.grid td{padding:6px 10px 6px 0;vertical-align:top}
table.grid code{white-space:nowrap;word-break:normal}
table.grid tr.second td,table.grid tr.err td{border-bottom:1px solid var(--line)}
table.grid tr.first td[rowspan]{border-bottom:1px solid var(--line)}
table.grid .n{text-align:right;font-variant-numeric:tabular-nums}
td.neg{color:var(--bad);font-weight:600}
td.barcell{width:180px;padding-top:9px}
.bar{position:relative;height:10px;background:var(--code);border-radius:5px;overflow:visible}
.bar i{position:absolute;top:0;height:10px;border-radius:5px}
.bar i.now{left:0;background:var(--accent)}
.bar i.grow{background:repeating-linear-gradient(45deg,var(--accent) 0 3px,transparent 3px 6px);opacity:.8}
.bar i.shrink{background:var(--muted);opacity:.4}
.bar.bad i.now,.bar.bad i.grow{background-color:transparent}
.bar.bad i.now{background:var(--bad)}.bar.bad i.grow{background:repeating-linear-gradient(45deg,var(--bad) 0 3px,transparent 3px 6px)}
.bar.warn i.now{background:var(--warn)}
.bar b{position:absolute;top:-3px;width:2px;height:16px;background:var(--fg);opacity:.7}
.legend{display:flex;gap:16px;flex-wrap:wrap;font-size:12px;color:var(--muted);margin-top:10px}
.legend i{display:inline-block;width:18px;height:10px;border-radius:5px;vertical-align:middle;margin-right:5px}
ul.plain{list-style:none;margin:0;padding:0}ul.plain li{padding:1px 0;white-space:nowrap}
li.tgt{font-weight:600}
table.kv{border-collapse:collapse;width:100%}
table.kv th{text-align:left;vertical-align:top;color:var(--muted);font-weight:500;padding:5px 12px 5px 0;width:24%;white-space:nowrap}
table.kv td{padding:5px 0;vertical-align:top}
details.raw summary{cursor:pointer;font-weight:600}
details.raw pre{max-height:480px;overflow:auto;background:var(--code);padding:12px;border-radius:6px;font-size:12px}
.themebtn{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:999px;padding:5px 12px;cursor:pointer;font:inherit}
footer{color:var(--muted);font-size:12px;margin-top:24px}
""".replace("LIGHT", _LIGHT)


def render_html(d: dict, title: str | None = None, theme: str = "dark") -> str:
    """HTML for one report dict (PrefixListReport.to_dict() or a saved JSON report)."""
    if theme not in THEMES:
        raise ValueError(f"theme must be one of {THEMES}")
    page_title = title or "Prefix List Review"
    pl = d["prefix_list_id"]
    name = d.get("prefix_list_name")
    raw = json.dumps(d, indent=2, default=str)
    return f"""<!doctype html>
<html lang="en" data-theme="{theme}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(page_title)}: {_e(pl)}</title><style>{CSS}</style></head>
<body><main>
<div class="top"><div><h1>{_e(page_title)}</h1>
<div class="muted">Security groups referencing a managed prefix list · generated {_e(d.get("generated_at"))}</div></div>
<button class="themebtn" type="button" title="Toggle light/dark">◐ Theme</button></div>
<div class="ahead"><div><h2><code>{_e(pl)}</code> {_e(name) if name else '<span class="muted">unnamed</span>'}</h2>
<div class="muted">owner <code>{_e(d.get("owner_account"))}</code> · {_e(d.get("region"))} ·
growing MaxEntries from {_e(d.get("current_max_entries"))} to {_e(d.get("proposed_length"))}</div></div>
<div>{_verdict(d)}</div></div>
{_cards(d)}
<div class="card"><h3>Security groups</h3>
<p class="muted">Weight = rules with each referenced prefix list counted as its MaxEntries (CIDR and group
references count 1). {_e(pl)} is counted at the proposed length. At-risk groups are listed first.</p>
<div class="filters"><input type="search" id="q" placeholder="Filter: account, group, name, VPC, policy">
<label><input type="checkbox" id="risk"> At risk only</label><span class="muted">Showing <span id="cnt"></span> groups</span></div>
<div class="tw"><table class="grid" id="sgs"><thead><tr><th>Account</th><th>Security group / VPC</th>
<th>Direction</th><th class="n">Rules</th><th class="n">Now</th><th class="n">Proposed</th><th class="n">Headroom</th>
<th>Weight vs limit</th><th>Prefix lists (refs = weight)</th><th>Status</th></tr></thead>
<tbody>{_sg_rows(d)}</tbody></table></div>
<div class="legend"><span><i style="background:var(--accent)"></i>current weight</span>
<span><i style="background:repeating-linear-gradient(45deg,var(--accent) 0 3px,transparent 3px 6px)"></i>added by the proposed length</span>
<span><i style="width:2px;background:var(--fg)"></i>limit ({_e(d.get("limit"))})</span></div></div>
{_fm_table(d)}
{_coverage(d)}
<div class="card"><details class="raw"><summary>Raw report JSON</summary><pre>{_e(raw)}</pre></details></div>
<footer>Read-only review. AWS counts a prefix list reference in a security group rule as the list's MaxEntries,
not its current entry count. AWS-managed lists use their documented weight.</footer>
</main><script>{_JS}</script></body></html>
"""
