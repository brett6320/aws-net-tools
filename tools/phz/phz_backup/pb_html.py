"""Self-contained HTML report of a phz_backup backup.

Layout:
  header and summary cards
  Zones: one row per backed-up PHZ, linking to its section
  Per zone: tags, VPC associations (owner account, cross-account / unknown owner), pending
            authorizations, every record set (searchable), and the zone's restore script with
            copy and download buttons. The script is never run from the page.

Inline CSS and JS only; styles and theme toggle shared with the phz_review report.
"""
from __future__ import annotations

import html
import json
import sys
from pathlib import Path
from typing import Any, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "phz_review"))

from phz_html import CSS  # noqa: E402

EXTRA_CSS = """
.zone h3{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.zone details{margin-top:12px}.zone summary{cursor:pointer;font-weight:600}
.btns{display:flex;gap:8px;margin:8px 0}
td.v{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px;word-break:break-all}
"""

JS = r"""
document.querySelectorAll("input.rfilter").forEach(function (inp) {
  inp.addEventListener("input", function () {
    var q = inp.value.toLowerCase(), rows = document.querySelectorAll("#" + inp.dataset.table + " tbody tr"), n = 0;
    rows.forEach(function (r) { var hit = !q || r.textContent.toLowerCase().indexOf(q) >= 0; r.style.display = hit ? "" : "none"; if (hit) n++; });
    document.getElementById(inp.dataset.table + "-n").textContent = q ? n + " of " + rows.length : "";
  });
});
document.querySelectorAll("button.copy").forEach(function (b) {
  b.addEventListener("click", function () {
    var t = document.getElementById(b.dataset.src).textContent;
    navigator.clipboard.writeText(t).then(function () { b.textContent = "Copied"; setTimeout(function () { b.textContent = "Copy"; }, 1500); });
  });
});
document.querySelectorAll("button.dl").forEach(function (b) {
  b.addEventListener("click", function () {
    var blob = new Blob([document.getElementById(b.dataset.src).textContent], {type: "text/x-shellscript"});
    var a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = b.dataset.name;
    document.body.appendChild(a); a.click(); a.remove();
  });
});
document.querySelector(".themebtn").addEventListener("click", function () {
  var r = document.documentElement;
  r.setAttribute("data-theme", r.getAttribute("data-theme") === "light" ? "dark" : "light");
});
"""


def _e(v: Any) -> str:
    return html.escape("" if v is None else str(v))


def _dns(name: str) -> str:
    """Show the wildcard escape as '*', as the console does."""
    return name.replace("\\052", "*")


def record_value(rr: dict[str, Any]) -> str:
    if "AliasTarget" in rr:
        t = rr["AliasTarget"]
        health = ", evaluate target health" if t.get("EvaluateTargetHealth") else ""
        return f"alias → {_e(_dns(t.get('DNSName', '')))} <span class=\"muted\">({_e(t.get('HostedZoneId'))}{health})</span>"
    if rr.get("TrafficPolicyInstanceId"):
        return f"<span class=\"muted\">traffic policy instance {_e(rr['TrafficPolicyInstanceId'])}</span>"
    return "<br>".join(_e(r.get("Value")) for r in rr.get("ResourceRecords") or [])


def routing(rr: dict[str, Any]) -> str:
    parts = []
    if rr.get("SetIdentifier"):
        parts.append(f"id {rr['SetIdentifier']}")
    for key, label in (("Weight", "weight"), ("Region", "latency"), ("Failover", "failover")):
        if key in rr:
            parts.append(f"{label} {rr[key]}")
    if rr.get("GeoLocation"):
        parts.append("geo " + ",".join(f"{v}" for v in rr["GeoLocation"].values()))
    if rr.get("MultiValueAnswer"):
        parts.append("multivalue")
    if rr.get("HealthCheckId"):
        parts.append(f"health check {rr['HealthCheckId']}")
    return _e("; ".join(parts))


def _owner_pill(v: dict[str, Any], account: str) -> str:
    owner = v.get("owner")
    if not owner:
        return '<span class="pill warn">unknown owner</span>'
    if owner != account:
        return '<span class="pill">cross-account</span>'
    return '<span class="pill ok">same account</span>'


def _stat(n: int, label: str, highlight: bool = False) -> str:
    return f'<div class="stat{" hl" if highlight else ""}"><b>{n}</b><span>{_e(label)}</span></div>'


def zone_section(i: int, b: dict[str, Any], script: str) -> str:
    z, account = b["zone"], b["account"]
    tags = b.get("tags") or {}
    vpcs = b.get("vpcs") or []
    auths = b.get("authorizations") or []
    records = b.get("records") or []
    tid = f"rec{i}"
    out = [f'<section class="card zone" id="zone-{_e(z["id"])}">',
           f'<h3>{_e(z["name"])} <code>{_e(z["id"])}</code></h3>',
           '<div class="kv">',
           f'<span class="muted">Account</span><span>{_e(account)}</span>',
           f'<span class="muted">Comment</span><span>{_e(z.get("comment")) or "<span class=muted>none</span>"}</span>',
           '<span class="muted">Tags</span><span>'
           + (" ".join(f"<code>{_e(k)}={_e(v)}</code>" for k, v in tags.items()) or '<span class="muted">none</span>')
           + "</span>",
           "</div>"]

    out.append(f"<h4>VPC associations ({len(vpcs)})</h4>")
    if vpcs:
        out.append('<div class="tw"><table class="grid"><thead><tr><th class="nosort">VPC</th><th class="nosort">Region</th>'
                   '<th class="nosort">Owner</th><th class="nosort"></th></tr></thead><tbody>')
        for v in vpcs:
            out.append(f'<tr><td class="m">{_e(v["vpc_id"])}</td><td class="m">{_e(v["region"])}</td>'
                       f'<td class="m">{_e(v.get("owner") or "?")}</td><td>{_owner_pill(v, account)}</td></tr>')
        out.append("</tbody></table></div>")
    else:
        out.append('<p class="muted">None.</p>')
    if auths:
        out.append(f"<h4>Pending authorizations ({len(auths)})</h4><ul>"
                   + "".join(f"<li><code>{_e(a['vpc_id'])}</code> ({_e(a['region'])})</li>" for a in auths) + "</ul>")

    out += [f"<h4>Record sets ({len(records)})</h4>",
            f'<div class="controls"><input type="search" class="rfilter" data-table="{tid}" placeholder="Filter name, type, value…">'
            f'<span class="muted" id="{tid}-n"></span></div>',
            f'<div class="tw"><table class="grid" id="{tid}"><thead><tr><th class="nosort">Name</th><th class="nosort">Type</th>'
            '<th class="nosort">TTL</th><th class="nosort">Value</th><th class="nosort">Routing</th></tr></thead><tbody>']
    for rr in records:
        out.append(f'<tr><td class="m">{_e(_dns(rr["Name"]))}</td><td class="m">{_e(rr["Type"])}</td>'
                   f'<td class="m">{_e(rr.get("TTL", ""))}</td><td class="v">{record_value(rr)}</td><td>{routing(rr)}</td></tr>')
    out.append("</tbody></table></div>")

    sid = f"script{i}"
    fname = f"{z['name']}.restore.sh"
    out += ["<details><summary>Restore script</summary>",
            '<p class="muted">Recreates this zone from the backup with the AWS CLI. Review before running; nothing runs from this page. '
            "For a zone that still exists, generate a script with <code>restore-plan --into ZONE_ID</code> instead.</p>",
            f'<div class="btns"><button type="button" class="copy" data-src="{sid}">Copy</button>'
            f'<button type="button" class="dl primary" data-src="{sid}" data-name="{_e(fname)}">Download {_e(fname)}</button></div>',
            f'<pre class="script" id="{sid}">{_e(script)}</pre>',
            "</details></section>"]
    return "\n".join(out)


def render_html(backups: Sequence[dict[str, Any]], scripts: Sequence[str], source: str, generated_at: str, theme: str = "dark") -> str:
    accounts = sorted({b["account"] for b in backups})
    taken = sorted({b.get("taken_at") or "" for b in backups})
    vpcs = [(b["account"], v) for b in backups for v in b.get("vpcs") or []]
    cross = sum(1 for a, v in vpcs if v.get("owner") and v["owner"] != a)
    unknown = sum(1 for _, v in vpcs if not v.get("owner"))
    cards = "".join([
        _stat(len(backups), "zones"),
        _stat(sum(len(b.get("records") or []) for b in backups), "record sets"),
        _stat(len(vpcs), "VPC associations"),
        _stat(cross, "cross-account"),
        _stat(unknown, "unknown VPC owners", highlight=unknown > 0),
        _stat(sum(len(b.get("authorizations") or []) for b in backups), "pending authorizations"),
    ])
    note = ""
    if unknown:
        note = ('<div class="card note">Some VPC owners were unknown when the backup was taken. Their restore commands '
                "need a <code>PROFILE_VPC_&lt;ID&gt;</code> variable set before the script runs. Run <code>ou_vpcs</code> for the "
                "OUs involved and take a new backup to record them.</div>")
    rows = []
    for b in backups:
        z = b["zone"]
        bv = b.get("vpcs") or []
        rows.append(
            f'<tr><td><a href="#zone-{_e(z["id"])}">{_e(z["name"])}</a></td><td class="m">{_e(z["id"])}</td>'
            f'<td>{len(b.get("records") or [])}</td><td>{len(bv)}</td>'
            f'<td>{sum(1 for v in bv if v.get("owner") and v["owner"] != b["account"])}</td>'
            f'<td>{sum(1 for v in bv if not v.get("owner"))}</td><td>{len(b.get("tags") or {})}</td>'
            f'<td>{_e(z.get("comment"))}</td></tr>')
    zones_table = ('<section class="card"><h3>Zones</h3><div class="tw"><table class="grid"><thead><tr>'
                   + "".join(f'<th class="nosort">{h}</th>' for h in
                             ("Name", "Zone ID", "Records", "VPCs", "Cross-account", "Unknown owner", "Tags", "Comment"))
                   + "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></div></section>")
    sections = "\n".join(zone_section(i, b, s) for i, (b, s) in enumerate(zip(backups, scripts)))
    data = json.dumps({"accounts": accounts, "taken_at": taken, "source": source})
    return f"""<!doctype html>
<html lang="en" data-theme="{_e(theme)}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PHZ backup {_e(", ".join(accounts))}</title>
<style>{CSS}{EXTRA_CSS}</style></head><body><main>
<div class="top"><div><h1>PHZ backup &mdash; account {_e(", ".join(accounts))}</h1>
<div class="muted">Taken {_e(", ".join(taken))} &middot; <code>{_e(source)}</code> &middot; report generated {_e(generated_at)}</div></div>
<button class="themebtn" type="button" title="Toggle light/dark">◐ Theme</button></div>
<div class="cards">{cards}</div>
{note}
{zones_table}
{sections}
<footer>phz_backup report. Restore scripts are generated from the backup and never run from this page.</footer>
<script type="application/json" id="meta">{_e(data)}</script>
<script>{JS}</script>
</main></body></html>
"""
