"""Self-contained HTML report for phz_review.

Layout:
  header, summary cards and notes
  Private hosted zones: sortable / filterable, each with its owner account
  Associations: zone <-> VPC rows with both owner accounts, cross-account flag and status
               (associated, authorized-pending, authorized = stale); rows can be selected
  Migration planner: move the selected VPCs to another PHZ. Builds the AWS CLI commands
               grouped by the account that must run them, in order: authorizations (target
               PHZ owner), associations (VPC owner), disassociations from the old PHZs, then
               authorization cleanup. It is never run from the page.

Inline CSS and JS only; no external resources. Dark by default with an in-page toggle.
The planner logic (PLANNER_JS) has no DOM access so it can be tested on its own.
"""
from __future__ import annotations

import html
import json
from typing import Any

_LIGHT = ("--bg:#f4f5f7;--card:#fff;--fg:#16191f;--muted:#5f6b7a;--line:#d5dbdb;--code:#eef1f4;--ok:#037f0c;"
          "--okbg:#e9f7ea;--bad:#d1321e;--badbg:#fdecea;--warn:#8d6605;--warnbg:#fff6dd;--accent:#0972d3;"
          "--hit:#e8f1fc;color-scheme:light")

CSS = """
:root{--bg:#0f1419;--card:#192029;--fg:#e6e9ee;--muted:#9aa5b1;--line:#2e3a47;--code:#232d38;--ok:#5fd16a;--okbg:#14301a;--bad:#ff7b6b;--badbg:#3a1714;--warn:#f2c94c;--warnbg:#3a2f0c;--accent:#58a6ff;--hit:#16283d;color-scheme:dark}
:root[data-theme="light"]{LIGHT}
@media (prefers-color-scheme:light){:root[data-theme="auto"]{LIGHT}}
@media print{:root,:root[data-theme]{LIGHT}.themebtn{display:none}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:1400px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:22px;margin:0 0 4px}h3{font-size:16px;margin:0 0 8px}h4{font-size:13px;margin:14px 0 6px}
code,pre{font:12.5px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
code{background:var(--code);padding:1px 5px;border-radius:4px}
a{color:var(--accent)}
.muted{color:var(--muted)}
.top{display:flex;justify-content:space-between;align-items:flex-end;gap:12px;flex-wrap:wrap;margin-bottom:16px}
.cards{display:flex;flex-wrap:wrap;gap:10px;margin:0 0 16px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:8px 14px;min-width:110px}
.stat b{display:block;font-size:20px}.stat span{color:var(--muted);font-size:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:16px;min-width:0}
.note{border-left:4px solid var(--warn)}
.controls{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:end;margin:4px 0 8px}
.controls label{display:flex;flex-direction:column;font-size:11px;color:var(--muted);gap:2px}
.controls label.check{flex-direction:row;align-items:center;gap:6px;font-size:13px;color:var(--fg)}
select,input,button{font:inherit;font-size:13px;color:var(--fg);background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:4px 6px}
input[type=search]{width:240px}select{max-width:260px}button{cursor:pointer}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
.tw{overflow-x:auto}
table.grid{border-collapse:collapse;width:100%;font-size:13px}
table.grid th{text-align:left;color:var(--muted);font-weight:500;border-bottom:1px solid var(--line);padding:6px 10px 6px 0;white-space:nowrap;cursor:pointer;user-select:none}
table.grid th.nosort{cursor:default}
table.grid th.asc::after{content:" \\25B2"}table.grid th.desc::after{content:" \\25BC"}
table.grid td{border-bottom:1px solid var(--line);padding:5px 10px 5px 0;vertical-align:top}
table.grid td.m{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px;white-space:nowrap}
table.grid tr.sel td{background:var(--hit)}
.pill{display:inline-block;padding:0 8px;border-radius:4px;font-weight:600;font-size:12px;background:var(--code)}
.pill.ok{color:var(--ok);background:var(--okbg)}.pill.bad{color:var(--bad);background:var(--badbg)}.pill.warn{color:var(--warn);background:var(--warnbg)}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px}
.msgs div{padding:6px 10px;border-radius:6px;margin:4px 0}
.msgs .err{color:var(--bad);background:var(--badbg)}.msgs .wrn{color:var(--warn);background:var(--warnbg)}
pre.script{background:var(--code);padding:12px;border-radius:6px;overflow:auto;max-height:560px;white-space:pre}
.kv{display:grid;grid-template-columns:max-content 1fr;gap:6px 10px;align-items:center}
.themebtn{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:999px;padding:5px 12px;cursor:pointer;font:inherit}
footer{color:var(--muted);font-size:12px;margin-top:24px}
""".replace("LIGHT", _LIGHT)

# Pure planning logic: (report data, selected associations, options) -> steps + errors/warnings, and the script text.
PLANNER_JS = r"""
var CREATE_AUTH = "create-vpc-association-authorization", ASSOCIATE = "associate-vpc-with-hosted-zone",
    DELETE_AUTH = "delete-vpc-association-authorization", DISASSOCIATE = "disassociate-vpc-from-hosted-zone";
var PHASES = {1: "Authorize the VPC owner(s)", 2: "Associate with the new PHZ", 3: "Disassociate from the old PHZ(s)",
              4: "Clean up authorizations"};

function isAcct(a) { return /^\d{12}$/.test(a || ""); }
function zname(n) { return String(n || "").toLowerCase().replace(/\.$/, ""); }
function shq(s) { s = String(s); return /^[A-Za-z0-9_.,=\/:@%+-]+$/.test(s) ? s : "'" + s.replace(/'/g, "'\\''") + "'"; }

function planMigration(data, selected, opts) {
  var steps = [], errors = [], warnings = [];
  var t = opts.target || {};
  var tname = zname(t.name);
  if (!t.zone_id) errors.push("Choose a target PHZ.");
  else if (!isAcct(t.owner)) errors.push("Enter the 12-digit account that owns the target PHZ " + t.zone_id + ".");
  if (!selected.length) errors.push("Select at least one association (old PHZ \u2194 VPC) to migrate.");
  if (errors.length) return {steps: steps, errors: errors, warnings: warnings};

  var zones = {};
  data.zones.forEach(function (z) { zones[z.zone_id] = z; });
  var assoc = data.associations;
  function rowsFor(zid, region, vpc) {
    return assoc.filter(function (a) { return a.zone_id === zid && a.vpc_id === vpc && a.vpc_region === region; });
  }
  function has(zid, region, vpc, statuses) {
    return rowsFor(zid, region, vpc).some(function (a) { return statuses.indexOf(a.status) >= 0; });
  }
  function zoneName(zid) {
    if (zid === t.zone_id) return tname;
    if (zones[zid]) return zones[zid].name;
    var a = assoc.filter(function (r) { return r.zone_id === zid; })[0];
    return a ? a.zone_name : "";
  }
  function zoneOwner(zid) {
    if (zones[zid] && isAcct(zones[zid].owner)) return zones[zid].owner;
    var a = assoc.filter(function (r) { return r.zone_id === zid && isAcct(r.zone_owner); })[0];
    return a ? a.zone_owner : "";
  }
  var remaining = {};
  if (data.vpc_counts_complete) data.zones.forEach(function (z) { if (z.vpc_count != null) remaining[z.zone_id] = z.vpc_count; });

  var byVpc = {}, order = [];
  selected.forEach(function (s) {
    var k = s.vpc_region + "/" + s.vpc_id;
    if (!byVpc[k]) { byVpc[k] = {vpc_id: s.vpc_id, vpc_region: s.vpc_region, sources: []}; order.push(k); }
    if (byVpc[k].sources.indexOf(s.zone_id) < 0) byVpc[k].sources.push(s.zone_id);
  });

  var anyCross = false, anyConflict = false, anyPhzSide = false;
  order.forEach(function (k) {
    var v = byVpc[k], vpc = v.vpc_id, region = v.vpc_region;
    var known = assoc.filter(function (a) { return a.vpc_id === vpc && isAcct(a.vpc_owner); })[0];
    var owner = (opts.vpcOwners || {})[vpc] || (known ? known.vpc_owner : "");
    if (!isAcct(owner)) { errors.push("Enter the account that owns " + vpc + " (" + region + ")."); return; }
    function step(phase, account, side, action, zid, note, skipped) {
      steps.push({phase: phase, account: account, side: side, action: action, zone_id: zid, zone_name: zoneName(zid),
                  vpc_id: vpc, vpc_region: region, vpc_owner: owner, note: note || "", skipped: skipped || ""});
    }
    if (v.sources.indexOf(t.zone_id) >= 0) warnings.push(vpc + ": the target PHZ is also selected as an old PHZ; ignored.");
    var srcs = v.sources.filter(function (z) { return z !== t.zone_id; });
    var cross = owner !== t.owner;

    var others = assoc.filter(function (a) {
      return a.vpc_id === vpc && a.vpc_region === region && a.status === "associated" && a.zone_id !== t.zone_id &&
        zname(a.zone_name) === tname && srcs.indexOf(a.zone_id) < 0;
    });
    if (others.length) {
      errors.push(vpc + " is also associated with " + others.map(function (a) { return a.zone_id; }).join(", ") +
        ", which has the same name as the target (" + tname + "). Route 53 refuses a second PHZ with the same name " +
        "(ConflictingDomainExists): select that association too.");
      return;
    }
    var conflicts = srcs.filter(function (z) { return zname(zoneName(z)) === tname; });
    var rest = srcs.filter(function (z) { return conflicts.indexOf(z) < 0; });
    if (conflicts.length && !opts.disassociate) {
      errors.push(vpc + ": the old PHZ has the same name as the target, so it must be disassociated first. " +
        "Tick \u201cdisassociate from the old PHZ\u201d.");
      return;
    }

    function disassociate(zid, phase, note) {
      var side = opts.disassociateAs === "phz" ? "phz" : "vpc";
      var acct = side === "phz" ? zoneOwner(zid) : owner;
      if (!isAcct(acct)) { errors.push("Owner account of the old PHZ " + zid + " is unknown; disassociate as the VPC owner instead."); return false; }
      if (remaining[zid] != null) {
        if (remaining[zid] <= 1) {
          step(phase, acct, side, DISASSOCIATE, zid, "", "last VPC on this PHZ; Route 53 does not allow removing it");
          return false;
        }
        remaining[zid]--;
      }
      anyPhzSide = anyPhzSide || side === "phz";
      step(phase, acct, side, DISASSOCIATE, zid, note);
      return true;
    }

    if (has(t.zone_id, region, vpc, ["associated"])) {
      step(2, owner, "vpc", ASSOCIATE, t.zone_id, "", "already associated with the target");
      if (cross && opts.deleteTargetAuth && has(t.zone_id, region, vpc, ["authorized"]))
        step(4, t.owner, "phz", DELETE_AUTH, t.zone_id, "stale authorization from an earlier association");
    } else {
      anyCross = anyCross || cross;
      if (cross) {
        if (has(t.zone_id, region, vpc, ["authorized", "authorized-pending"]))
          step(1, t.owner, "phz", CREATE_AUTH, t.zone_id, "", "authorization already exists");
        else
          step(1, t.owner, "phz", CREATE_AUTH, t.zone_id, "allow account " + owner + " to associate " + vpc);
      }
      var blocked = false;
      conflicts.forEach(function (z) {
        anyConflict = true;
        if (!disassociate(z, 2, "same name as the target, so it must go first; " + tname +
                          " does not resolve in this VPC until the next command completes")) blocked = true;
      });
      if (blocked) {
        step(2, owner, "vpc", ASSOCIATE, t.zone_id, "", "blocked: the same-name old PHZ can't be disassociated");
        errors.push(vpc + " can't move: the same-name old PHZ must be disassociated first and can't be. " +
          "Associate another VPC with it, or delete it, then re-run.");
      } else {
        step(2, owner, "vpc", ASSOCIATE, t.zone_id, cross ? "cross-account; uses the authorization from step 1" : "same account");
        if (cross && opts.deleteTargetAuth)
          step(4, t.owner, "phz", DELETE_AUTH, t.zone_id, "no longer needed once associated");
      }
    }
    if (opts.disassociate) rest.forEach(function (z) { disassociate(z, 3, "after the new association is in place"); });
    if (opts.cleanupSourceAuth) srcs.forEach(function (z) {
      if (has(z, region, vpc, ["authorized", "authorized-pending"])) {
        var zo = zoneOwner(z);
        if (isAcct(zo)) step(4, zo, "phz", DELETE_AUTH, z, "leftover authorization on the old PHZ; stops the VPC re-associating");
      }
    });
  });

  if (anyCross) warnings.push("Cross-account: the target PHZ owner must create each authorization (step 1) before the VPC owner " +
    "associates. Run the steps in order; if different teams own the accounts, hand each team its step.");
  if (anyConflict) warnings.push("Same-name migration: Route 53 doesn't allow two PHZs with the same name on one VPC, so the old PHZ " +
    "is removed just before the new one is added. Records in that name don't resolve in the VPC between the two commands; " +
    "run them back to back, in a change window.");
  if (opts.disassociate && !data.vpc_counts_complete) warnings.push("This report doesn't hold every VPC on the old PHZs, so " +
    "it can't check whether a disassociation removes a PHZ's last VPC (Route 53 rejects that). Check with phz_review by-zone.");
  if (cross_any_unknown_auth(data, anyCross)) warnings.push("Existing authorizations weren't listed in this report, so step 1 " +
    "may recreate one that exists already.");
  if (anyPhzSide) warnings.push("Disassociating as the PHZ owner works only for PHZs it owns; VPCs shared through RAM are still " +
    "associated by their owner account.");
  steps.sort(function (a, b) { return a.phase - b.phase; });
  return {steps: steps, errors: errors, warnings: warnings};
}

function cross_any_unknown_auth(data, anyCross) { return anyCross && !data.authorizations_listed; }

function cliFor(s, profile) {
  var parts = ["aws", "route53", s.action, "--hosted-zone-id", s.zone_id, "--vpc", "VPCRegion=" + s.vpc_region + ",VPCId=" + s.vpc_id];
  if (profile) parts.push("--profile", profile);
  return parts.map(shq).join(" ");
}

function renderScript(plan, opts, meta) {
  var t = opts.target, profiles = opts.profiles || {};
  var accounts = {};
  plan.steps.forEach(function (s) {
    if (s.skipped) return;
    accounts[s.account] = accounts[s.account] || {};
    accounts[s.account][s.side === "phz" ? (s.zone_id === t.zone_id ? "target PHZ owner" : "old PHZ owner") : "VPC owner"] = 1;
  });
  var L = ["#!/usr/bin/env bash",
           "# PHZ migration plan \u2014 prepared in the phz_review report (" + (meta.generated_at || "") + ")",
           "# Target PHZ: " + t.zone_id + " " + (t.name || "") + " (owner account " + t.owner + ")",
           "# Accounts:"];
  Object.keys(accounts).sort().forEach(function (a) {
    L.push("#   " + a + ": " + Object.keys(accounts[a]).join(", ") + (profiles[a] ? " (profile: " + profiles[a] + ")" : ""));
  });
  L.push("# Review before running. Run each step with credentials for the account in its header.");
  plan.warnings.forEach(function (w) { L.push("# NOTE: " + w); });
  L.push("set -euo pipefail");
  var cur = null, n = 0, active = 0;
  plan.steps.forEach(function (s) {
    var target = s.zone_id + " " + (s.zone_name || "") + " <-> " + s.vpc_id + " (" + s.vpc_region + ", account " + s.vpc_owner + ")";
    if (s.skipped) { L.push("# SKIP " + s.action + " " + target + ": " + s.skipped); return; }
    var head = s.phase + "|" + s.account;
    if (head !== cur) {
      cur = head; n++;
      var who = s.side === "phz" ? "PHZ owner" : "VPC owner";
      L.push("", "# ===== Step " + n + ": " + PHASES[s.phase] + " \u2014 run as " + who + " account " + s.account +
             (profiles[s.account] ? " (profile: " + profiles[s.account] + ")" : "") + " =====");
    }
    active++;
    L.push("# " + target + (s.note ? " \u2014 " + s.note : ""));
    L.push(cliFor(s, profiles[s.account]));
  });
  if (!active) L.push("", "# Nothing to do.");
  return L.join("\n") + "\n";
}
"""

UI_JS = r"""
(function () {
  var D = JSON.parse(document.getElementById("phz-data").textContent);
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
    return {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]; }); }
  function $(id) { return document.getElementById(id); }
  function fmt(v) {
    if (v === true) return "yes"; if (v === false) return "no"; if (v == null) return "";
    if (typeof v === "object") return Object.keys(v).map(function (k) { return k + "=" + v[k]; }).join(", ");
    return String(v);
  }
  function akey(a) { return a.zone_id + "|" + a.vpc_region + "|" + a.vpc_id + "|" + a.status; }

  // ---------------------------------------------------------------- tables
  function Table(cfg) {
    var st = {q: "", f: {}, sort: cfg.sort ? [cfg.sort] : []};
    var root = $(cfg.id), ctl = document.createElement("div"), tw = document.createElement("div");
    ctl.className = "controls"; tw.className = "tw"; root.appendChild(ctl); root.appendChild(tw);
    var q = document.createElement("input"); q.type = "search"; q.placeholder = "Search " + cfg.label;
    var ql = document.createElement("label"); ql.textContent = "Search"; ql.appendChild(q); ctl.appendChild(ql);
    q.addEventListener("input", function () { st.q = q.value.toLowerCase(); draw(); });
    cfg.filters.forEach(function (k) {
      var col = cfg.columns.filter(function (c) { return c[0] === k; })[0];
      var counts = {};
      cfg.rows.forEach(function (r) { var v = fmt(r[k]) || "(none)"; counts[v] = (counts[v] || 0) + 1; });
      var sel = document.createElement("select");
      sel.innerHTML = '<option value="">all</option>' + Object.keys(counts).sort().map(function (v) {
        return '<option value="' + esc(v) + '">' + esc(v) + " (" + counts[v] + ")</option>"; }).join("");
      sel.addEventListener("change", function () { st.f[k] = sel.value; draw(); });
      var l = document.createElement("label"); l.textContent = col ? col[1] : k; l.appendChild(sel); ctl.appendChild(l);
    });
    var count = document.createElement("span"); count.className = "muted"; ctl.appendChild(count);
    if (cfg.extraControls) cfg.extraControls(ctl);
    var shown = [];
    function match(r) {
      for (var k in st.f) if (st.f[k] && (fmt(r[k]) || "(none)") !== st.f[k]) return false;
      if (!st.q) return true;
      return cfg.columns.some(function (c) { return fmt(r[c[0]]).toLowerCase().indexOf(st.q) >= 0; });
    }
    function cmp(a, b) {
      for (var i = 0; i < st.sort.length; i++) {
        var k = st.sort[i][0], d = st.sort[i][1], x = a[k], y = b[k];
        if (typeof x === "number" && typeof y === "number") { if (x !== y) return (x - y) * d; continue; }
        x = fmt(x); y = fmt(y);
        var c = x.localeCompare(y, undefined, {numeric: true});
        if (c) return c * d;
      }
      return 0;
    }
    function draw() {
      shown = cfg.rows.filter(match).sort(cmp);
      count.textContent = shown.length + " of " + cfg.rows.length + " " + cfg.label;
      var h = '<table class="grid"><thead><tr>' + (cfg.pre ? '<th class="nosort">' + cfg.pre.head() + "</th>" : "") +
        cfg.columns.map(function (c) {
          var s = st.sort.filter(function (x) { return x[0] === c[0]; })[0];
          return '<th data-k="' + c[0] + '" class="' + (s ? (s[1] > 0 ? "asc" : "desc") : "") + '">' + esc(c[1]) + "</th>";
        }).join("") + (cfg.post ? '<th class="nosort"></th>' : "") + "</tr></thead><tbody>";
      shown.forEach(function (r, i) {
        h += '<tr data-i="' + i + '"' + (cfg.rowClass ? ' class="' + cfg.rowClass(r) + '"' : "") + ">" +
          (cfg.pre ? "<td>" + cfg.pre.cell(r) + "</td>" : "") +
          cfg.columns.map(function (c) { return '<td class="m">' + (c[2] ? c[2](r) : esc(fmt(r[c[0]]))) + "</td>"; }).join("") +
          (cfg.post ? "<td>" + cfg.post(r) + "</td>" : "") + "</tr>";
      });
      tw.innerHTML = h + "</tbody></table>" + (shown.length ? "" : '<p class="muted">No rows match.</p>');
      tw.querySelectorAll("th[data-k]").forEach(function (th) {
        th.addEventListener("click", function (e) {
          var k = th.getAttribute("data-k"), cur = st.sort.filter(function (x) { return x[0] === k; })[0];
          var dir = cur ? -cur[1] : 1;
          if (e.shiftKey) { st.sort = st.sort.filter(function (x) { return x[0] !== k; }); st.sort.push([k, dir]); }
          else st.sort = [[k, dir]];
          draw();
        });
      });
      if (cfg.onDraw) cfg.onDraw(tw, shown);
    }
    this.draw = draw;
    this.shown = function () { return shown; };
    draw();
  }

  function pill(v, cls) { return '<span class="pill ' + cls + '">' + esc(v) + "</span>"; }
  function statusCell(r) {
    return r.status === "associated" ? pill(r.status, "ok") : r.status === "authorized" ? pill("authorized (stale)", "warn") : pill(r.status, "");
  }
  function crossCell(r) { return r.cross_account == null ? '<span class="muted">unknown</span>' : r.cross_account ? pill("yes", "warn") : "no"; }
  function acctCell(k) { return function (r) { return /^\d{12}$/.test(r[k] || "") ? esc(r[k]) : '<span class="muted">' + esc(r[k] || "unknown") + "</span>"; }; }

  // ---------------------------------------------------------------- zones
  var zt = new Table({
    id: "zones", label: "zones", rows: D.zones, sort: ["name", 1], filters: ["owner"],
    columns: [["name", "Name"], ["zone_id", "Zone ID"], ["owner", "Owner account", acctCell("owner")],
              ["vpc_count", "VPCs"], ["records", "Records"], ["comment", "Comment"], ["tags", "Tags"]],
    post: function (r) { return '<button type="button" data-target="' + esc(r.zone_id) + '">Use as target</button>'; },
    onDraw: function (tw) {
      tw.querySelectorAll("button[data-target]").forEach(function (b) {
        b.addEventListener("click", function () { setTarget(b.getAttribute("data-target")); $("planner").scrollIntoView(); });
      });
    }
  });

  // ---------------------------------------------------------------- associations
  var selected = {};
  var at = new Table({
    id: "assocs", label: "associations", rows: D.associations, sort: ["zone_name", 1],
    filters: ["zone_name", "zone_owner", "vpc_owner", "vpc_region", "cross_account", "status"],
    columns: [["zone_name", "Zone"], ["zone_id", "Zone ID"], ["zone_owner", "Zone owner", acctCell("zone_owner")],
              ["vpc_id", "VPC"], ["vpc_region", "Region"], ["vpc_owner", "VPC owner", acctCell("vpc_owner")],
              ["cross_account", "Cross-account", crossCell], ["status", "Status", statusCell]],
    pre: {
      head: function () { return '<input type="checkbox" id="selall" title="Select all shown associated rows">'; },
      cell: function (r) {
        return r.status === "associated" ? '<input type="checkbox" class="pick" data-k="' + esc(akey(r)) + '"' +
          (selected[akey(r)] ? " checked" : "") + ">" : "";
      }
    },
    rowClass: function (r) { return selected[akey(r)] ? "sel" : ""; },
    extraControls: function (ctl) {
      var b = document.createElement("button"); b.type = "button"; b.textContent = "Clear selection";
      b.addEventListener("click", function () { selected = {}; at.draw(); plan(); }); ctl.appendChild(b);
    },
    onDraw: function (tw, shown) {
      tw.querySelectorAll("input.pick").forEach(function (c) {
        c.addEventListener("change", function () {
          var k = c.getAttribute("data-k");
          if (c.checked) selected[k] = true; else delete selected[k];
          c.closest("tr").className = c.checked ? "sel" : ""; plan();
        });
      });
      var all = tw.querySelector("#selall");
      all.addEventListener("change", function () {
        shown.forEach(function (r) { if (r.status === "associated") { if (all.checked) selected[akey(r)] = true; else delete selected[akey(r)]; } });
        at.draw(); plan();
      });
    }
  });

  // ---------------------------------------------------------------- planner
  var profiles = {}, owners = {}, lastAccounts = "", lastUnknown = "";
  var tsel = $("t-zone");
  tsel.innerHTML = '<option value="">\u2014 choose \u2014</option>' + D.zones.slice().sort(function (a, b) {
      return a.name.localeCompare(b.name) || a.owner.localeCompare(b.owner); }).map(function (z) {
      return '<option value="' + esc(z.zone_id) + '">' + esc(z.name + "  " + z.zone_id + "  (" + z.owner + ")") + "</option>"; }).join("") +
    '<option value="__other">Other PHZ (enter below)</option>';
  function setTarget(zid) {
    tsel.value = zid;
    var z = D.zones.filter(function (x) { return x.zone_id === zid; })[0];
    if (z) { $("t-id").value = z.zone_id; $("t-name").value = z.name; $("t-owner").value = /^\d{12}$/.test(z.owner) ? z.owner : ""; }
    plan();
  }
  tsel.addEventListener("change", function () {
    if (tsel.value === "__other") { $("t-id").value = ""; $("t-name").value = ""; $("t-owner").value = ""; $("t-id").focus(); plan(); }
    else setTarget(tsel.value);
  });
  ["t-id", "t-name", "t-owner"].forEach(function (id) {
    $(id).addEventListener("input", function () { if (id !== "t-owner") tsel.value = "__other"; plan(); }); });
  ["o-dis", "o-delauth", "o-srcauth"].forEach(function (id) { $(id).addEventListener("change", plan); });
  $("o-as").addEventListener("change", plan);

  function opts() {
    return {
      target: {zone_id: $("t-id").value.trim().replace(/^.*\//, ""), name: $("t-name").value.trim(), owner: $("t-owner").value.trim()},
      disassociate: $("o-dis").checked, disassociateAs: $("o-as").value, deleteTargetAuth: $("o-delauth").checked,
      cleanupSourceAuth: $("o-srcauth").checked, vpcOwners: owners, profiles: profiles
    };
  }
  function picks() {
    return D.associations.filter(function (a) { return selected[akey(a)]; })
      .map(function (a) { return {zone_id: a.zone_id, vpc_id: a.vpc_id, vpc_region: a.vpc_region}; });
  }
  function inputs(box, keys, store, label, placeholder, pattern) {
    box.innerHTML = keys.length ? "<h4>" + esc(label) + '</h4><div class="kv">' + keys.map(function (k) {
      return "<code>" + esc(k) + '</code><input data-k="' + esc(k) + '" value="' + esc(store[k] || "") + '" placeholder="' +
        esc(placeholder) + '"' + (pattern ? ' pattern="' + pattern + '"' : "") + ">"; }).join("") + "</div>" : "";
    box.querySelectorAll("input").forEach(function (i) {
      i.addEventListener("input", function () { var v = i.value.trim(); if (v) store[i.getAttribute("data-k")] = v; else delete store[i.getAttribute("data-k")]; plan(true); });
    });
  }
  function plan(keepInputs) {
    var sel = picks();
    $("sel-count").textContent = sel.length + " association(s) selected";
    var unknown = [];
    sel.forEach(function (s) {
      var known = D.associations.some(function (a) { return a.vpc_id === s.vpc_id && /^\d{12}$/.test(a.vpc_owner || ""); });
      if (!known && unknown.indexOf(s.vpc_id) < 0) unknown.push(s.vpc_id);
    });
    if (!keepInputs || unknown.join() !== lastUnknown) {
      lastUnknown = unknown.join();
      inputs($("owners"), unknown, owners, "VPC owner accounts (not visible from this report)", "12-digit account", "\\d{12}");
    }
    var o = opts(), p = planMigration(D, sel, o);
    var accts = [];
    p.steps.forEach(function (s) { if (!s.skipped && accts.indexOf(s.account) < 0) accts.push(s.account); });
    accts.sort();
    if (accts.join() !== lastAccounts) {
      lastAccounts = accts.join();
      inputs($("profiles"), accts, profiles, "AWS CLI profile per account (optional, added as --profile)", "profile name");
    }
    $("msgs").innerHTML = p.errors.map(function (e) { return '<div class="err">' + esc(e) + "</div>"; }).join("") +
      p.warnings.map(function (w) { return '<div class="wrn">' + esc(w) + "</div>"; }).join("");
    var ok = !p.errors.length && p.steps.length;
    $("script").textContent = ok ? renderScript(p, o, D) : "# Fix the items above to generate the commands.";
    $("copy").disabled = $("dl").disabled = !ok;
  }
  $("copy").addEventListener("click", function () {
    navigator.clipboard.writeText($("script").textContent).then(function () { $("copy").textContent = "Copied"; setTimeout(function () { $("copy").textContent = "Copy"; }, 1500); });
  });
  $("dl").addEventListener("click", function () {
    var a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([$("script").textContent], {type: "text/x-shellscript"}));
    a.download = "phz-migration.sh"; a.click(); URL.revokeObjectURL(a.href);
  });
  document.querySelector(".themebtn").addEventListener("click", function () {
    var r = document.documentElement, c = r.getAttribute("data-theme");
    if (c === "auto") c = matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
    r.setAttribute("data-theme", c === "light" ? "dark" : "light");
  });
  plan();
})();
"""


def _e(v: Any) -> str:
    return html.escape("" if v is None else str(v), quote=True)


def _cards(d: dict) -> str:
    a = d["associations"]
    assoc = [r for r in a if r["status"] == "associated"]
    accounts = {r["zone_owner"] for r in a} | {r["vpc_owner"] for r in a} | {z["owner"] for z in d["zones"]}
    stats = [
        (len(d["zones"]), "private hosted zones"),
        (len(assoc), "associations"),
        (len({(r["vpc_region"], r["vpc_id"]) for r in assoc}), "VPCs"),
        (len({x for x in accounts if x and x.isdigit()}), "accounts"),
        (sum(1 for r in assoc if r["cross_account"]), "cross-account"),
        (sum(1 for r in a if r["status"] == "authorized-pending"), "pending authorizations"),
        (sum(1 for r in a if r["status"] == "authorized"), "stale authorizations"),
        (len({r["vpc_id"] for r in a if not r["vpc_owner"].isdigit()}), "VPCs with unknown owner"),
    ]
    return '<div class="cards">' + "".join(f'<div class="stat"><b>{n}</b><span>{_e(label)}</span></div>' for n, label in stats) + "</div>"


def render_html(d: dict, theme: str = "dark") -> str:
    data = json.dumps(d, default=str).replace("</", "<\\/")
    notes = "".join(f'<div class="card note">{_e(n)}</div>' for n in d.get("notes", []))
    return f"""<!doctype html>
<html lang="en" data-theme="{_e(theme)}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PHZ Review: {_e(d.get("scope"))}</title><style>{CSS}</style></head>
<body><main>
<div class="top"><div><h1>PHZ Review</h1>
<div class="muted">Route 53 private hosted zones and VPC associations · <code>{_e(d.get("command"))}</code> ·
account {_e(d.get("scope"))} · generated {_e(d.get("generated_at"))}</div></div>
<button class="themebtn" type="button" title="Toggle light/dark">◐ Theme</button></div>
{_cards(d)}
{notes}
<div class="card"><h3>Private hosted zones</h3><div id="zones"></div></div>
<div class="card"><h3>Associations</h3>
<p class="muted">One row per PHZ and VPC, with the account that owns each. <b>authorized-pending</b>: the PHZ owner allowed a
VPC in another account to associate, and it hasn't yet. <b>authorized (stale)</b>: the VPC is associated and the authorization
is no longer needed. Tick associated rows to move those VPCs off that PHZ in the planner below.</p>
<div id="assocs"></div></div>
<div class="card" id="planner"><h3>Migration planner</h3>
<p class="muted">Prepares the AWS CLI commands to move the selected VPCs to a different PHZ. Nothing runs from this page.
Order: the target PHZ owner authorizes each VPC from another account, the VPC owner associates it, the old PHZ is
disassociated, and the authorization is removed. Commands are grouped by the account that has to run them.</p>
<div class="grid2"><div>
<h4>Target PHZ</h4>
<div class="controls"><label>Zone<select id="t-zone"></select></label></div>
<div class="kv"><span class="muted">Zone ID</span><input id="t-id" placeholder="Z0123456789ABC">
<span class="muted">Name</span><input id="t-name" placeholder="example.internal">
<span class="muted">Owner account</span><input id="t-owner" placeholder="12-digit account" pattern="\\d{{12}}"></div>
<h4>Options</h4>
<div class="controls">
<label class="check"><input type="checkbox" id="o-dis" checked> Disassociate from the old PHZ</label>
<label>Disassociate as<select id="o-as"><option value="vpc">VPC owner</option><option value="phz">old PHZ owner</option></select></label>
<label class="check"><input type="checkbox" id="o-delauth" checked> Delete the target authorization after associating</label>
<label class="check"><input type="checkbox" id="o-srcauth" checked> Delete leftover authorizations on the old PHZ</label>
</div>
<p class="muted" id="sel-count"></p>
<div id="owners"></div><div id="profiles"></div>
</div><div>
<div class="msgs" id="msgs"></div>
<div class="controls"><button type="button" class="primary" id="copy">Copy</button><button type="button" id="dl">Download .sh</button></div>
<pre class="script" id="script"></pre>
</div></div></div>
<footer>Read-only review generated by phz_review. The planner only prepares commands; review them before running.
Route 53 rules applied: a VPC from another account needs an authorization from the PHZ owner before it can associate;
a VPC can't be associated with two PHZs of the same name; a PHZ's last VPC can't be disassociated.</footer>
</main>
<script type="application/json" id="phz-data">{data}</script>
<script>{PLANNER_JS}{UI_JS}</script></body></html>
"""
