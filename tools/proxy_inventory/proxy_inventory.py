#!/usr/bin/env python3
"""Inventory the proxy-capable resources in each VPC of the VPC owner map, by AppCatID (read-only).

Purpose: know which applications (AppCatID tag) live in which VPC, so their owners can be
contacted to test when a VPC changes (e.g. an egress proxy is introduced).

The VPCs come from the local VPC owner map that ``ou_vpcs`` writes
(~/.cache/aws-net-tools/vpc-owners.json), optionally narrowed by OU, account, Region or VPC.
Each account is read with the profile that maps to its account ID in ~/.aws/config (never
one ending in -priv or -cpar); see pi_core for the resource types and how shared VPCs work.

Writes an interactive HTML report: AppCatIDs per VPC, every resource with all its tags,
the VPCs read, network interfaces no reported resource accounts for, and anything that
couldn't be read. Tables sort, filter, download as CSV, and the whole report downloads as
HTML that opens on the current filters. A summary report without individual resources
(no Resources table, no Resource IDs) is written next to it as proxy-inventory-summary.html.
The current reports are overwritten on each run; timestamped copies are kept. Logs go to
stderr; the full report's path goes to stdout.

--rerender FILE rebuilds a report from the data embedded in it, with this version's layout
and a new timestamp, without any AWS call.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import Any

import truststore

# Use the OS certificate store. Injecting after urllib3 has captured ssl.SSLContext recurses
# forever, which only happens when something imported boto3 first (e.g. the tests).
if "urllib3" not in sys.modules:
    truststore.inject_into_ssl()

import boto3  # noqa: E402
from dotenv import load_dotenv  # noqa: E402

import pi_core as core  # noqa: E402
import pi_html  # noqa: E402

load_dotenv()

log = logging.getLogger("proxy_inventory")

INCOMPLETE_EXIT = 3
REPORT_NAME = "proxy-inventory"
SUMMARY_SUFFIX = "-summary"


def configure_logging(verbose: bool = False, quiet: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.WARNING if quiet else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
                        datefmt="%Y-%m-%dT%H:%M:%S", stream=sys.stderr)
    logging.getLogger().setLevel(level)
    # Never DEBUG, even with -v: botocore would log whole responses, e.g. Lambda environment variables.
    for noisy in ("botocore", "boto3", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def build_parser() -> argparse.ArgumentParser:
    env = os.getenv
    p = argparse.ArgumentParser(description="Inventory proxy-capable resources per VPC, by AppCatID (read-only).")
    p.add_argument("--cache", default=env("PROXY_INV_CACHE") or env("OU_VPCS_CACHE"), metavar="FILE",
                   help="VPC owner map written by ou_vpcs (default: ~/.cache/aws-net-tools/vpc-owners.json; "
                        "env PROXY_INV_CACHE / OU_VPCS_CACHE)")
    p.add_argument("--ou", action="append", metavar="OU",
                   help="Only VPCs of accounts in this OU: an OU ID (that OU only) or an OU path such as Root/Prod "
                        "(that OU and every OU below it); repeat or comma-separate (env PROXY_INV_OU)")
    p.add_argument("--account", action="append", metavar="ID", help="Only VPCs owned by this account; repeat or comma-separate")
    p.add_argument("--exclude-account", action="append", metavar="ID",
                   help="Never read this account: neither its VPCs nor as a shared-VPC participant (its interfaces in "
                        "other VPCs show as unattributed); repeat or comma-separate (env PROXY_INV_EXCLUDE_ACCOUNTS)")
    p.add_argument("--regions", action="append", help="Only VPCs in these Regions; repeat or comma-separate (env PROXY_INV_REGIONS)")
    p.add_argument("--vpc", action="append", metavar="VPC_ID", help="Only these VPCs; repeat or comma-separate")
    p.add_argument("--profile", default=env("AWS_PROFILE"),
                   help="Preferred profile when several map to an account (default: AWS_PROFILE)")
    p.add_argument("--account-profile", action="append", metavar="ACCOUNT=PROFILE",
                   help="Profile to use for an account (when several or none map to it); repeat or comma-separate")
    p.add_argument("--key-tag", default=env("PROXY_INV_KEY_TAG") or core.DEFAULT_KEY_TAG,
                   help="Tag that identifies the application, matched without regard to case "
                        f"(default: {core.DEFAULT_KEY_TAG}; env PROXY_INV_KEY_TAG)")
    p.add_argument("--no-participants", action="store_true",
                   help="Don't read other accounts with interfaces in shared VPCs (their workloads then show as unattributed)")
    p.add_argument("--include", action="append", metavar="SERVICE",
                   help=f"Also read these opt-in services: {', '.join(core.OPT_IN)} (they need workspaces:DescribeWorkspaces / "
                        "glue:GetConnections / airflow:GetEnvironment / apprunner:ListVpcConnectors); repeat or comma-separate (env PROXY_INV_INCLUDE)")
    workers = env("PROXY_INV_WORKERS", "")
    p.add_argument("--workers", type=int, default=int(workers) if workers.isdigit() and int(workers) > 0 else 4,
                   help="Accounts read in parallel (default: 4; env PROXY_INV_WORKERS)")
    p.add_argument("--reports-dir", default=env("PROXY_INV_REPORTS_DIR", "reports"), metavar="DIR",
                   help="Reports root: current report in DIR/<scope>/, timestamped copies in DIR/<YYYY-MM-DD>/<scope>/ "
                        "(default: ./reports; env PROXY_INV_REPORTS_DIR)")
    p.add_argument("--out", metavar="FILE", help="Write the report here instead, and the summary as FILE's name + "
                                                 "-summary (each plus a timestamped copy next to it)")
    p.add_argument("--json-out", metavar="FILE", help="Also write every row, with all tags, as JSON")
    p.add_argument("--rerender", metavar="FILE",
                   help="Rebuild this existing report from the data embedded in it, with the current layout and a new "
                        "timestamp; no AWS calls. A full report also rebuilds its summary. The current report is overwritten "
                        "(with a timestamped copy); any other file gets a timestamped copy next to it. --out, "
                        "--json-out and --title apply; filters don't")
    p.add_argument("--title", help="Report title")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    p.add_argument("-q", "--quiet", action="store_true", help="Warnings/errors only")
    return p


# --------------------------------------------------------------------------- rows


def tag_list(tags: dict[str, str]) -> list[str]:
    return [f"{k}={v}" for k, v in sorted(tags.items(), key=lambda kv: kv[0].lower())]


def build_rows(scan: core.Scan, vpcs: list[core.Vpc], key_tag: str) -> dict[str, list[dict[str, Any]]]:
    """Report rows: resources, AppCatIDs per VPC, VPCs, unattributed interfaces and issues."""
    meta = {(v.region, v.vpc_id): v for v in vpcs}
    names = {v.account: v.account_name for v in vpcs if v.account_name}
    vpc_tags = {(d["region"], d["vpc_id"]): d for d in scan.vpcs}

    def vpc_cols(region: str, vpc_id: str) -> dict[str, Any]:
        v = meta.get((region, vpc_id)) or core.Vpc(region, vpc_id, "")
        tags = (vpc_tags.get((region, vpc_id)) or {}).get("tags") or {}
        return {"vpc_id": vpc_id, "vpc_name": v.name or tags.get("Name", ""), "vpc_owner": v.account,
                "vpc_owner_name": v.account_name, "ou_path": v.ou_path or "unknown",
                "vpc_appcatid": core.key_tag_value(tags, key_tag)}

    resources = []
    for r in scan.resources:
        app, source = core.key_tag_value(r["tags"], key_tag), "resource"
        if not app and r["inherited"] and (app := core.key_tag_value(r["inherited"][1], key_tag)):
            source = f"inherited from {r['inherited'][0]}"
        elif not app:
            app, source = core.MISSING, ""
        resources.append({
            "appcatid": app, "appcatid_source": source, "type": r["type"], "id": r["id"], "name": r["name"],
            "state": r["state"], "account": r["account"], "account_name": names.get(r["account"], ""),
            "region": r["region"], **vpc_cols(r["region"], r["vpc_id"]), "subnets": r["subnets"],
            "private_ips": r["private_ips"], "detail": r["detail"], "tags": tag_list(r["tags"]),
            "tag_keys": sorted(r["tags"]), "arn": r["arn"], "all_tags": r["tags"],
        })
    resources.sort(key=lambda r: (r["ou_path"], r["vpc_owner"], r["region"], r["vpc_id"], r["appcatid"], r["type"], r["id"]))

    groups: dict[tuple, list[dict]] = {}
    for r in resources:
        groups.setdefault((r["region"], r["vpc_id"], r["appcatid"]), []).append(r)
    apps = [{
        "appcatid": app, **vpc_cols(region, vpc_id), "region": region, "resources": len(rs),
        "types": sorted({r["type"] for r in rs}), "accounts": sorted({r["account"] for r in rs}),
        "resource_ids": [f"{r['type']}: {r['id']}" for r in rs],
    } for (region, vpc_id, app), rs in groups.items()]

    unattributed = core.classify_enis(scan.enis, scan.resources, scan.read)
    enis = [{**{k: n[k] for k in ("eni_id", "likely", "interface_type", "description", "requester", "eni_owner",
                                  "instance_id", "private_ips", "status", "subnet")},
             "region": n["region"], **vpc_cols(n["region"], n["vpc_id"]), "tags": tag_list(n["tags"])}
            for n in unattributed]

    gone = {(d["region"], d["vpc_id"]) for d in scan.vpcs if d["gone"]}
    read = {(d["region"], d["vpc_id"]) for d in scan.vpcs}
    vpc_rows = []
    for v in vpcs:
        k = (v.region, v.vpc_id)
        rs = [r for r in resources if (r["region"], r["vpc_id"]) == k]
        vpc_rows.append({
            **vpc_cols(v.region, v.vpc_id), "region": v.region, "cidrs": list(v.cidrs),
            "status": "gone" if k in gone else "read" if k in read else "not read",
            "resources": len(rs), "appcatids": sorted({r["appcatid"] for r in rs}),
            "unattributed": sum(1 for n in enis if (n["region"], n["vpc_id"]) == k),
        })
    # An owner account that couldn't be read can also come up as a participant; list it once.
    # (A row marked incomplete wins, so the table agrees with the exit code.)
    merged: dict[tuple, dict] = {}
    for i in scan.issues:
        key = (i.account, i.region, "account" if i.scope == "participant" else i.scope)
        row = {"account": i.account, "account_name": names.get(i.account, ""), "region": i.region or "(all)",
               "scope": i.scope, "reason": i.reason, "incomplete": "yes" if i.incomplete else "no"}
        if key not in merged or (row["incomplete"] == "yes" and merged[key]["incomplete"] == "no"):
            merged[key] = row
    issues = list(merged.values())
    return {"resources": resources, "apps": apps, "vpcs": vpc_rows, "enis": enis, "issues": issues}


# --------------------------------------------------------------------------- report


VPC_COLS = [["vpc_id", "VPC"], ["vpc_name", "VPC name"], ["region", "Region"], ["vpc_owner", "VPC owner"],
            ["vpc_owner_name", "Owner name"], ["ou_path", "OU"]]


def render_report(rows: dict[str, list[dict]], *, title: str, key_tag: str, meta: list[str],
                  generated_at: str = "", summary: bool = False) -> str:
    """The HTML report; summary=True leaves out individual resources (the Resources table and Resource IDs)."""
    apps = rows["apps"]
    known = {a["appcatid"] for a in apps} - {core.MISSING}
    total = sum(a["resources"] for a in apps)
    missing = sum(a["resources"] for a in apps if a["appcatid"] == core.MISSING)
    incomplete = sum(1 for i in rows["issues"] if i["incomplete"] == "yes")
    badge = {"appcatid": {core.MISSING: "warn"}}
    tables = [
        {"id": "apps", "title": f"{key_tag}s by VPC", "row_label": f"{key_tag} / VPC pairs",
         "note": f"One row per {key_tag} in each VPC: whom to contact before changing that VPC. "
                 f"{core.MISSING} = resources without the tag (owner unknown)." +
                 (" Individual resources are in the full report." if summary else ""),
         "columns": [["appcatid", key_tag]] + VPC_COLS[:3] + [["vpc_appcatid", f"VPC's {key_tag}"]] + VPC_COLS[3:] +
                    [["resources", "Resources"], ["types", "Types"], ["accounts", "Resource accounts"]] +
                    ([] if summary else [["resource_ids", "Resource IDs"]]),
         "rows": [{k: v for k, v in a.items() if k != "resource_ids"} for a in apps] if summary else apps, "filters": ["appcatid", "vpc_id", "region", "vpc_owner", "ou_path", "types"],
         "uniq": [["appcatid", f"{key_tag}s"], ["vpc_id", "VPCs"], ["vpc_owner", "VPC owners"]],
         "lines": ["resource_ids"], "fold": {"resource_ids": "resources"}, "wrap": ["resource_ids", "types"], "badges": badge,
         "sort": [["vpc_id", 1], ["appcatid", 1]],
         "by": {"key": "appcatid", "label": f"VPCs per {key_tag}", "badge": None}},
        {"id": "res", "title": "Resources", "row_label": "resources",
         "note": "Every proxy-capable resource with all of its tags. Search matches any text, e.g. a tag as key=value.",
         "columns": [["appcatid", key_tag], ["appcatid_source", f"{key_tag} from"], ["type", "Type"], ["id", "ID"],
                     ["name", "Name"], ["state", "State"], ["account", "Account"], ["account_name", "Account name"]] +
                    VPC_COLS[:3] + [["vpc_owner", "VPC owner"], ["ou_path", "OU"], ["subnets", "Subnets"],
                                    ["private_ips", "Private IPs"], ["detail", "Detail"], ["tags", "Tags"]],
         "rows": [{k: v for k, v in r.items() if k != "all_tags"} for r in rows.get("resources", [])],
         "filters": ["appcatid", "type", "account", "vpc_id", "region", "ou_path", "state", "appcatid_source", "tag_keys"],
         "uniq": [["appcatid", f"{key_tag}s"], ["vpc_id", "VPCs"], ["account", "Accounts"]],
         "labels": [["tag_keys", "Has tag key"]],
         "lines": ["tags", "private_ips", "subnets"], "wrap": ["tags", "detail"], "badges": badge,
         "sort": [["vpc_id", 1], ["appcatid", 1], ["type", 1]]},
        {"id": "vpcs", "title": "VPCs read", "row_label": "VPCs", "collapsed": True,
         "note": "Every selected VPC from the owner map. gone = in the owner map but no longer in AWS.",
         "columns": VPC_COLS + [["cidrs", "CIDRs"], ["vpc_appcatid", f"VPC's {key_tag}"], ["status", "Status"],
                                ["resources", "Resources"], ["appcatids", f"{key_tag}s"], ["unattributed", "Unattributed ENIs"]],
         "rows": rows["vpcs"], "filters": ["region", "vpc_owner", "ou_path", "status"],
         "badges": {"status": {"gone": "warn", "not read": "error", "read": "ok"}}, "sort": [["ou_path", 1], ["vpc_id", 1]]},
        {"id": "eni", "title": "Unattributed network interfaces", "row_label": "interfaces", "collapsed": True,
         "note": "Interfaces in these VPCs that belong to no resource above and to no excluded type (endpoints, NAT, "
                 "load balancers, databases ...). Review them for workloads of other types.",
         "columns": [["eni_id", "Interface"], ["likely", "Likely"], ["interface_type", "Type"], ["description", "Description"],
                     ["requester", "Requester"], ["eni_owner", "Owner"], ["instance_id", "Attached to"],
                     ["private_ips", "Private IPs"], ["status", "Status"]] + VPC_COLS[:4] + [["tags", "Tags"]],
         "rows": rows["enis"], "filters": ["likely", "interface_type", "requester", "eni_owner", "vpc_id", "region"],
         "lines": ["tags"], "wrap": ["description", "tags"], "sort": [["vpc_id", 1], ["likely", 1]]},
        {"id": "issues", "title": "Not read", "row_label": "issues", "collapsed": not incomplete,
         "note": "Accounts, Regions or services that couldn't be read. incomplete = yes means resources may be missing "
                 "from this report. A denied service (incomplete = no) is often simply unused; its interfaces still "
                 "show as unattributed.",
         "columns": [["account", "Account"], ["account_name", "Account name"], ["region", "Region"], ["scope", "What"],
                     ["incomplete", "Incomplete"], ["reason", "Reason"]],
         "rows": rows["issues"], "filters": ["scope", "account", "region", "incomplete"], "wrap": ["reason"],
         "badges": {"incomplete": {"yes": "error", "no": "info"}}, "sort": [["incomplete", -1], ["account", 1]]},
    ]
    if summary:
        tables = [t for t in tables if t["id"] != "res"]
    cards = [(len(rows["vpcs"]), "VPCs"), (len(known), f"{key_tag}s"), (total, "resources"),
             (missing, f"without {key_tag}"), (len(rows["enis"]), "unattributed ENIs"),
             (incomplete, "accounts / Regions not read")]
    # title, key tag and collection time, so --rerender can rebuild the page from it
    return pi_html.render(f"{title} (summary)" if summary else title, meta=meta, cards=cards, tables=tables,
                          file=REPORT_NAME + SUMMARY_SUFFIX if summary else REPORT_NAME,
                          extra_data={"key_tag": key_tag, "generated_at": generated_at, "title": title,
                                      "summary": summary})


def report_path(scope: str, reports_dir: str) -> Path:
    """The current report, overwritten on every run: DIR/<scope>/proxy-inventory.html."""
    return Path(reports_dir) / scope / f"{REPORT_NAME}.html"


def summary_path(full: Path) -> Path:
    """The summary written next to a full report: <name>-summary<ext>."""
    return full.with_name(f"{full.stem}{SUMMARY_SUFFIX}{full.suffix}")


def history_path(current: Path, reports_dir: str | None, now: dt.datetime) -> Path:
    """DIR/<YYYY-MM-DD>/<scope>/<name>_<HHMMSS>.html, or next to --out FILE as <name>_<YYYYMMDD-HHMMSS>.html."""
    if reports_dir is None:
        return current.with_name(f"{current.stem}_{now:%Y%m%d-%H%M%S}{current.suffix}")
    return Path(reports_dir) / now.date().isoformat() / current.parent.name / f"{current.stem}_{now:%H%M%S}{current.suffix}"


def write_report(page: str, path: Path, copy: Path) -> None:
    for p in (copy, path):
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(page, encoding="utf-8")
    log.info("Wrote %s", path) if copy == path else log.info("Wrote %s (history copy: %s)", path, copy)


def write_json(path: str, rows: dict[str, list[dict]], **header: Any) -> None:
    out = {**header,
           "resources": [{**{k: v for k, v in r.items() if k not in ("tags", "tag_keys")}, "tags": r["all_tags"]}
                         for r in rows.get("resources", [])],
           "apps": rows["apps"], "vpcs": rows["vpcs"], "unattributed_enis": rows["enis"], "issues": rows["issues"]}
    Path(path).write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
    log.info("Wrote JSON %s", path)


# --------------------------------------------------------------------------- --rerender

DATA_RE = re.compile(r'<script id="data" type="application/json">(.*?)</script>', re.S)
EXTRA_RE = re.compile(r'<script id="extra-data" type="application/json">(.*?)</script>', re.S)
TABLE_ROWS = {"apps": "apps", "res": "resources", "vpcs": "vpcs", "eni": "enis", "issues": "issues"}


def load_report(path: Path) -> tuple[dict[str, Any], dict[str, list[dict]], dict[str, Any]]:
    """(page data, report rows, extra data) of a report written by this tool; a summary's rows have no "resources"."""
    try:
        html = path.read_text(encoding="utf-8")
    except OSError as e:
        raise ValueError(f"--rerender: can't read {path}: {e.strerror or e}") from e
    m = DATA_RE.search(html)
    data = json.loads(m.group(1)) if m else {}
    tables = {t.get("id"): t for t in data.get("tables", [])}
    if set(TABLE_ROWS) - {"res"} - set(tables):  # a summary has no Resources table
        raise ValueError(f"--rerender: {path} isn't a {REPORT_NAME} report (no embedded report data)")
    rows = {name: tables[tid]["rows"] for tid, name in TABLE_ROWS.items() if tid in tables}
    for r in rows.get("resources", []):  # the JSON output wants tags as a dict; the page has them as key=value
        r.setdefault("all_tags", dict(t.split("=", 1) for t in r.get("tags") or [] if "=" in t))
    x = EXTRA_RE.search(html)
    extra = json.loads(x.group(1)) if x else {}
    return data, rows, extra


def rerendered_meta(meta: list[str], source: str, now: dt.datetime) -> list[str]:
    """The header lines with "Generated ..." turned into when the data was collected plus when it was re-rendered."""
    stamp = f"re-rendered {now.astimezone(dt.timezone.utc):%Y-%m-%d %H:%M:%S UTC} from {source} (no AWS calls)"
    first = re.sub(r"^Generated ", "Data collected ", re.sub(r"; re-rendered .*$", "", meta[0])) if meta else ""
    return [f"{first}; {stamp}" if first else stamp[0].upper() + stamp[1:], *meta[1:]]


def rerender(args: argparse.Namespace) -> int:
    src = Path(args.rerender)
    try:
        data, rows, extra = load_report(src)
    except (ValueError, json.JSONDecodeError) as e:
        log.error("%s", e)
        return 2
    now = dt.datetime.now().astimezone()
    key_tag = extra.get("key_tag") or rows_key_tag(data)
    kw = {"title": args.title or extra.get("title") or data.get("title") or f"Proxy-capable resources by {key_tag}",
          "key_tag": key_tag, "meta": rerendered_meta(data.get("meta") or [], src.name, now),
          "generated_at": extra.get("generated_at", "")}
    current = (src.name in (f"{REPORT_NAME}.html", f"{REPORT_NAME}{SUMMARY_SUFFIX}.html")
               and src.resolve().parent.parent == Path(args.reports_dir).resolve())
    # in place: --out, or the current report of a scope; otherwise never overwrite a history copy or another file
    base, in_place = (Path(args.out), True) if args.out else (src, current)
    copies = args.reports_dir if current and not args.out else None
    # a full report rebuilds the summary next to it as well; a summary has only itself to rebuild
    pages = [(base, False), (summary_path(base), True)] if "resources" in rows else [(base, True)]
    for p, summary in pages:
        copy = history_path(p, copies, now)
        write_report(render_report(rows, summary=summary, **kw), p if in_place else copy, copy)
    path = base if in_place else history_path(base, None, now)
    if args.json_out:
        write_json(args.json_out, rows, generated_at=extra.get("generated_at", ""), rerendered_at=now.isoformat(),
                   key_tag=key_tag, source=str(src), summary="resources" not in rows)
    print(path)
    return INCOMPLETE_EXIT if any(i.get("incomplete") == "yes" for i in rows["issues"]) else 0


def rows_key_tag(data: dict[str, Any]) -> str:
    """The key tag of a report written before it was embedded: the first column of the first table."""
    try:
        return data["tables"][0]["columns"][0][1]
    except (KeyError, IndexError, TypeError):
        return core.DEFAULT_KEY_TAG


def main(argv: list[str] | None = None, session_for=None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.verbose, args.quiet)
    if args.rerender:
        return rerender(args)
    cache = Path(args.cache).expanduser() if args.cache else core.default_cache_path()
    ous = core.split_csv(args.ou or [os.getenv("PROXY_INV_OU", "")])
    regions = core.split_csv(args.regions or [os.getenv("PROXY_INV_REGIONS", "")])
    include = [s.lower() for s in core.split_csv(args.include or [os.getenv("PROXY_INV_INCLUDE", "")])]
    excluded = core.split_csv(args.exclude_account or [os.getenv("PROXY_INV_EXCLUDE_ACCOUNTS", "")])
    try:
        if unknown := sorted(set(include) - set(core.OPT_IN)):
            raise ValueError(f"--include / PROXY_INV_INCLUDE: unknown service(s) {', '.join(unknown)} (choose from {', '.join(core.OPT_IN)})")
        overrides = core.parse_account_profiles(args.account_profile)
        vpcs = core.select_vpcs(core.load_vpcs(cache), ous=ous, accounts=core.split_csv(args.account),
                                regions=regions, vpc_ids=core.split_csv(args.vpc), exclude_accounts=excluded)
    except (ValueError, FileNotFoundError) as e:
        log.error("%s", e)
        return 2
    if not vpcs:
        log.error("No VPCs in %s match the filters given", cache)
        return 2
    log.info("%d VPC(s) in %d account(s) from %s", len(vpcs), len({v.account for v in vpcs}), cache)

    session_for = session_for or (lambda profile: boto3.Session(profile_name=profile))
    scan = core.scan(vpcs, session_for, overrides, preferred=args.profile, workers=args.workers,
                     participants=not args.no_participants, include=frozenset(core.OPT_IN[s] for s in include),
                     exclude_accounts=frozenset(excluded))
    rows = build_rows(scan, vpcs, args.key_tag)

    now = dt.datetime.now().astimezone()
    owners = sorted({v.account for v in vpcs})
    scope = owners[0] if len(owners) == 1 else "multi-account"
    filters = [f"{n} {', '.join(v)}" for n, v in (("OU", ous), ("account", core.split_csv(args.account)),
                                                   ("Region", regions), ("VPC", core.split_csv(args.vpc)),
                                                   ("excluding account", excluded)) if v]
    meta = [f"Generated {now.astimezone(dt.timezone.utc):%Y-%m-%d %H:%M:%S UTC} from the VPC owner map {cache.name}"
            f"{' (' + '; '.join(filters) + ')' if filters else ''}",
            f"Application tag: {args.key_tag} (any case). ECS services and tasks without it inherit their cluster's "
            "(shown in the \"from\" column)."]
    if skipped := [label for name, label in core.OPT_IN.items() if name not in include]:
        meta.append(f"Not read (opt-in with --include): {', '.join(skipped)}. "
                    "Their network interfaces show as unattributed.")
    kw = {"title": args.title or f"Proxy-capable resources by {args.key_tag}", "key_tag": args.key_tag, "meta": meta,
          "generated_at": now.isoformat()}
    path = Path(args.out) if args.out else report_path(scope, args.reports_dir)
    for p, summary in ((path, False), (summary_path(path), True)):
        write_report(render_report(rows, summary=summary, **kw), p, history_path(p, None if args.out else args.reports_dir, now))
    if args.json_out:
        write_json(args.json_out, rows, generated_at=now.isoformat(), key_tag=args.key_tag, cache=str(cache),
                   services_not_read=skipped, excluded_accounts=excluded)
    print(path)

    apps = {r["appcatid"] for r in rows["resources"]} - {core.MISSING}
    log.info("%d resource(s), %d %s(s), in %d VPC(s); %d unattributed interface(s)",
             len(rows["resources"]), len(apps), args.key_tag, len(vpcs), len(rows["enis"]))
    if any(i.incomplete for i in scan.issues):
        log.warning("Incomplete: some accounts or Regions weren't read (see the report's \"Not read\" table)")
        return INCOMPLETE_EXIT
    return 0


if __name__ == "__main__":
    sys.exit(main())
