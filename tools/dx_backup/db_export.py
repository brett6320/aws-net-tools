"""Self-contained HTML report for a dx_backup diff (and, optionally, the restore plan).

One card per changed object with a Field / Before / After table, plus the two
snapshots being compared and any warnings. Auth keys appear only as "changed".
Every value from AWS is HTML-escaped.
"""
from __future__ import annotations

import datetime as dt
import html

import db_core as core
import db_diff
from db_theme import CSS, THEME_JS

THEMES = ("dark", "light", "auto")
OPS = {"+": ("added", "ok"), "-": ("removed", "bad"), "~": ("changed", "warn")}


def _e(v) -> str:
    return html.escape("" if v is None else str(v), quote=True)


def _cell(value, other) -> str:
    if value is None:
        return '<span class="nm">—</span>'
    if value is True:
        return "present"
    if core.is_fingerprint(value):
        return "auth key set" if other is None else ("auth key (changed)" if value != other else "auth key")
    return f"<code class='wrap'>{_e(db_diff.show(value))}</code>"


def change_card(c: dict) -> str:
    word, cls = OPS[c["op"]]
    title = _e(db_diff.heading(c)[2:])
    head = f'<h3><span class="badge {cls}">{word}</span> {title}</h3>'
    if not c["fields"]:
        return f'<div class="card">{head}</div>'
    rows = "".join(f"<tr><td><code class='wrap'>{_e(p)}</code></td><td>{_cell(a, b)}</td><td>{_cell(b, a)}</td></tr>"
                   for p, a, b in c["fields"])
    return (f'<div class="card">{head}<div class="tw"><table class="grid diff"><colgroup><col style="width:30%">'
            f'<col style="width:35%"><col style="width:35%"></colgroup><thead><tr><th>Field</th><th>Before</th>'
            f'<th>After</th></tr></thead><tbody>{rows}</tbody></table></div></div>')


def render_html(changes: list[dict], old: dict, new: dict, plan_text: str | None = None, title: str | None = None,
                theme: str = "dark", state: bool = False) -> str:
    if theme not in THEMES:
        raise ValueError(f"theme must be one of {THEMES}")
    s = db_diff.summary(changes)
    badges = (" ".join(f'<span class="badge {OPS[op][1]}">{s[op]} {OPS[op][0]}</span>' for op in "+-~")
              if changes else '<span class="badge ok">No configuration changes</span>')
    kv = "".join(f"<tr><th>{_e(k)}</th><td>{_e(v)}</td></tr>" for k, v in (
        ("Old", db_diff.describe(old["manifest"])), ("New", db_diff.describe(new["manifest"])),
        ("Compared", "configuration and state" if state else "configuration (state fields left out)")))
    warns = [*(old["manifest"].get("warnings") or []), *(new["manifest"].get("warnings") or [])]
    warn_card = ('<div class="card"><h3>Warnings</h3><ul class="plain">'
                 + "".join(f"<li class='warnmsg'>{_e(w)}</li>" for w in warns) + "</ul></div>") if warns else ""
    plan_card = (f'<div class="card"><h3>Restore plan</h3><pre class="term">{_e(plan_text)}</pre></div>'
                 if plan_text else "")
    page_title = title or "dx_backup · diff"
    generated = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    return f"""<!doctype html>
<html lang="en" data-theme="{theme}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(page_title)}</title><style>{CSS}</style></head>
<body><main>
<div class="top"><div><h1>{_e(page_title)}</h1>
<div class="muted">AWS Direct Connect configuration · generated {_e(generated)}</div></div>
<button class="themebtn" type="button" title="Toggle light/dark">◐ Theme</button></div>
<div class="card answer"><div>{badges}</div><table class="kv">{kv}</table></div>
{"".join(change_card(c) for c in changes)}{plan_card}{warn_card}
<footer>Generated from dx_backup snapshots. BGP auth keys are stored only as salted fingerprints.</footer>
</main><script>{THEME_JS}</script></body></html>
"""
