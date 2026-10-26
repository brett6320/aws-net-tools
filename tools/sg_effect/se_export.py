"""Self-contained HTML report for sg_effect.

The answer (resources, what a removal would cost), the target group's rules with where
each one is the only rule allowing its traffic, one card per resource with its
effective inbound and outbound access and both removal scenarios, the groups that
reference the target, warnings, and the raw bundle. Every value from AWS is escaped.
"""
from __future__ import annotations

import datetime as dt
import html
import json

from se_text import group_label, resource_label
from se_theme import CSS, THEME_JS

THEMES = ("dark", "light", "auto")
IN, OUT = "inbound", "outbound"


def _e(v) -> str:
    return html.escape("" if v is None else str(v), quote=True)


def _code(v) -> str:
    return f"<code>{_e(v)}</code>" if v not in (None, "") else '<span class="nm">—</span>'


def _table(headers: list[str], rows: list[list[str]], empty: str = "None") -> str:
    if not rows:
        return f'<p class="muted">{_e(empty)}</p>'
    head = "".join(f"<th>{_e(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f'<div class="tw"><table class="grid"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def _badge(text: str, cls: str = "") -> str:
    return f'<span class="badge {cls}">{_e(text)}</span>'


def _lost_count(result: dict, key: str) -> int:
    return sum(1 for r in result["resources"]
               if any(i["lost"] for d in (IN, OUT) for i in (r.get(key) or {}).get(d, []))
               or (key == "remove_sg" and (r.get(key) or {}).get("as_peer")))


def answer_card(result: dict, names: dict[str, str]) -> str:
    t = result["target"]
    n = len(result["resources"])
    safe = [s for s in result["rule_summary"] if not s["unique_on"]] if n else []
    badges = [_badge(f"{n} resource{'s' if n != 1 else ''}", "ok" if n else "warn"),
              _badge(f"{len(result['referencing'])} referencing group{'s' if len(result['referencing']) != 1 else ''}")]
    if n:
        badges.append(_badge(f"{len(safe)} of {len(t['rules'])} rules redundant everywhere", "ok" if safe else ""))
    if result["removing"]:
        lose = _lost_count(result, "remove_rules")
        badges.append(_badge(f"Removing {len(result['removing'])} rule{'s' if len(result['removing']) != 1 else ''}: "
                             + (f"{lose} resource{'s' if lose != 1 else ''} lose access" if lose
                                else "no resource loses access"), "bad" if lose else "ok"))
    rows = [["Security group", _e(group_label(t["id"], names))], ["Description", _e(t.get("description"))],
            ["VPC", _code(t.get("vpc"))], ["Account / Region", _e(f"{result.get('account')} · {result.get('region')}")]]
    if result["removing"]:
        rows.append(["Scenario", "<br>".join(f"remove {_code(r['id'])} {_e(r['text'])}" for r in result["removing"])])
    kv = "".join(f"<tr><th>{_e(k)}</th><td>{v}</td></tr>" for k, v in rows)
    return f'<div class="card answer"><div>{" ".join(badges)}</div><table class="kv">{kv}</table></div>'


def rules_card(result: dict) -> str:
    n = len(result["resources"])
    rows = []
    for s in result["rule_summary"]:
        u, r = s["unique_on"], s["redundant_on"]
        verdict = (_badge("redundant everywhere", "ok") if n and not u else
                   _badge(f"only rule on {len(u)} of {n}", "warn") if n else '<span class="nm">—</span>')
        rows.append([_code(s["rule"]), _e(s["text"]), _e(s.get("description")), verdict,
                     "<br>".join(_e(x) for x in u) or '<span class="nm">—</span>'])
    safe = sum(1 for x in result["rule_summary"] if n and not x["unique_on"])
    return (f'<div class="card"><details class="access"><summary>Rules of the target group: '
            f'{len(rows)} rule{"s" if len(rows) != 1 else ""}, {safe} redundant everywhere</summary>'
            + _table(["Rule", "Allows", "Description", "Where it matters", "Only rule allowing it on"], rows,
                     "The group has no rules") + "</details></div>")


def _access_table(entries: list[dict], target: str, names: dict[str, str]) -> str:
    rows = []
    for e in entries:
        grants = "<br>".join(f"{_e(group_label(g['group'], names))} {_code(g['rule'])}" for g in e["grants"])
        note = []
        if e["only_target"]:
            note.append(_badge("target only", "warn"))
        elif e["from_target"]:
            note.append(_badge("target + other"))
        if e["open_to_world"]:
            note.append(_badge("anywhere", "bad"))
        if e["covered_by"]:
            note.append(f"<div class='td muted'>covered by {_e(e['covered_by'][0]['text'])}</div>")
        rows.append([_e(e["traffic"]), _code(e["peer"]), grants, " ".join(note)])
    return _table(["Traffic", "Peer", "Allowed by", "Note"], rows, "Nothing allowed")


def _scenario(block: dict, names: dict[str, str]) -> str:
    items = []
    for d in (IN, OUT):
        for i in block.get(d) or []:
            if i["lost"]:
                word = "partly loses" if i.get("partly") else "loses"
                items += [f"<li>{_badge(word, 'bad')} {_e(d)} {_e(x)} {_code(i['rule'])}</li>" for x in i["lost"]]
            else:
                by = "; ".join(k["text"] + (f" ({group_label(k['group'], names)})" if k.get("group") else "")
                               for k in i["kept_by"])
                items.append(f"<li>{_badge('keeps', 'ok')} {_e(i['text'])} "
                             f"<span class='muted'>still allowed by {_e(by)}</span></li>")
    items += [f"<li>{_badge('as a peer', 'warn')} {_e(i['text'])} {_code(i['rule'])}</li>"
              for i in block.get("as_peer") or []]
    return f'<ul class="plain">{"".join(items) or "<li class=muted>No change</li>"}</ul>'


def resource_card(res: dict, result: dict, names: dict[str, str]) -> str:
    t = result["target"]["id"]
    enis = "<br>".join(f"{_code(e['id'])} {_e(', '.join(e.get('private_ips') or []))}"
                       + (f" · public {_e(e['public_ip'])}" if e.get("public_ip") else "")
                       + f" <span class='muted'>{_e(e.get('subnet'))}</span>" for e in res["enis"])
    groups = " ".join(_badge(group_label(g, names), "warn" if g == t else "") for g in res["groups"])
    body = [f"<h3>{_e(resource_label(res))}</h3>",
            f'<table class="kv"><tr><th>Network interfaces</th><td>{enis}</td></tr>'
            f"<tr><th>Security groups</th><td>{groups}</td></tr></table>",
            f"<h4>If {_e(t)} is removed from it</h4>{_scenario(res['remove_sg'], names)}"]
    if "remove_rules" in res:
        body.append(f"<h4>If the selected rules are removed</h4>{_scenario(res['remove_rules'], names)}")
    n_in, n_out = len(res["effective"][IN]), len(res["effective"][OUT])
    body.append(f'<details class="access"><summary>Effective access: {n_in} inbound, {n_out} outbound</summary>'
                f"<h4>Inbound</h4>{_access_table(res['effective'][IN], t, names)}"
                f"<h4>Outbound</h4>{_access_table(res['effective'][OUT], t, names)}</details>")
    return f'<div class="card">{"".join(body)}</div>'


def referencing_card(result: dict) -> str:
    rows = []
    for g in result["referencing"]:
        used = "<br>".join(_e(resource_label(r)) for r in g["resources"]) or '<span class="nm">no resources</span>'
        rows.append([_e(group_label(g["group"], {g["group"]: g["name"]})), "<br>".join(_e(r) for r in g["rules"]), used])
    return (f'<div class="card"><h3>Groups that reference {_e(result["target"]["id"])}</h3>'
            '<p class="muted">Their rules allow traffic to or from members of the target group.</p>'
            + _table(["Group", "Rules", "Used by"], rows, "No other group references it") + "</div>")


def render_html(result: dict, bundle: dict, title: str | None = None, theme: str = "dark") -> str:
    if theme not in THEMES:
        raise ValueError(f"theme must be one of {THEMES}")
    t = result["target"]
    names = {t["id"]: t.get("name") or ""}
    for r in result["resources"]:
        names.update(r.get("group_names") or {})
    warns = "".join(f"<li class='warnmsg'>{_e(w)}</li>" for w in result["warnings"])
    warn_card = f'<div class="card"><h3>Warnings</h3><ul class="plain">{warns}</ul></div>' if warns else ""
    page_title = title or f"sg_effect · {group_label(t['id'], names)}"
    generated = result.get("generated") or dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    cards = "".join(resource_card(r, result, names) for r in result["resources"]) or \
        '<div class="card"><p class="muted">No network interface uses this group.</p></div>'
    raw = json.dumps(bundle, indent=2, default=str)
    return f"""<!doctype html>
<html lang="en" data-theme="{theme}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(page_title)}</title><style>{CSS}
h4{{font-size:13px;margin:16px 0 6px;color:var(--muted)}}
ul.plain li{{margin:4px 0}}
details.access{{margin-top:14px}}details.access summary{{cursor:pointer;color:var(--muted);font-weight:600}}</style></head>
<body><main>
<div class="top"><div><h1>{_e(page_title)}</h1>
<div class="muted">Security group effect · collected {_e(generated)}</div></div>
<button class="themebtn" type="button" title="Toggle light/dark">◐ Theme</button></div>
{answer_card(result, names)}{rules_card(result)}{cards}{referencing_card(result)}{warn_card}
<div class="card"><details class="raw"><summary>Raw bundle (JSON)</summary><pre>{_e(raw)}</pre></details></div>
<footer>Security groups only allow, so a resource's access is the union of every rule of every group on it.
Network ACLs, route tables and the resources' own firewalls aren't considered.</footer>
</main><script>{THEME_JS}</script></body></html>
"""
