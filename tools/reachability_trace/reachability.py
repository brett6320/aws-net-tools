#!/usr/bin/env python3
"""Create, run, inspect, and export AWS VPC Reachability Analyzer traces.

Command-line front end. Each subcommand is a cmd_* function taking (args, execute):

  create / analyze      mutating; dry-run unless --execute/--apply. Build the API
                        requests (ra_core), call the API, then _finish() waits for the
                        analysis, prints a summary, and writes the HTML report.
  paths / analyses /    read-only listings and lookups.
  show / export
  delete-*              mutating; dry-run by default.

Modules: ra_core (validation + EC2 API calls), ra_accounts (account attribution),
ra_export (HTML rendering), ra_icons (component icons), ra_codes (explanation text).
Logs go to stderr; summaries, listings and --json go to stdout.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

import truststore

# Use the OS certificate store (corporate proxies/CAs) before any HTTPS client is created.
truststore.inject_into_ssl()

from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound  # noqa: E402
from dotenv import load_dotenv  # noqa: E402

import ra_accounts as accounts  # noqa: E402
import ra_core as core  # noqa: E402
from ra_export import THEMES, blocking_targets, break_direction, port_range, proto, render_html  # noqa: E402
from ra_icons import classify, label_for  # noqa: E402

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("reachability")


# ---------- helpers ----------

def _ec2(args):
    """EC2 client for --profile/--region. The profile is only used here; it is never
    written to reports or JSON."""
    log.debug("Using profile=%s region=%s", args.profile or "default", args.region or "(profile default)")
    session = core.get_session(args.profile, args.region)
    if not session.region_name:
        raise core.ValidationError("No region configured; pass --region or set AWS_REGION")
    return core.get_client("ec2", session)


def _json_default(o: Any) -> str:
    """json.dumps fallback for boto3 datetimes."""
    return o.isoformat() if hasattr(o, "isoformat") else str(o)


def _dump(obj: Any) -> str:
    return json.dumps(obj, indent=2, default=_json_default)


def _write_export(bundles: list[dict], out: str | Path, title: str | None, theme: str = "dark") -> None:
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(render_html(bundles, title, theme), encoding="utf-8")
    log.info("Wrote HTML export %s", out)


def _write_json(bundles: list[dict], out: str) -> None:
    """Save bundles for offline re-rendering (export --from-json). One bundle is written
    as an object, several as a list; export accepts both."""
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(_dump(bundles if len(bundles) > 1 else bundles[0]), encoding="utf-8")
    log.info("Wrote JSON %s", out)


def _comp_line(pc: dict, show_account: bool = False, blocked: dict[str, list[str]] | None = None) -> str:
    """One summary line per hop: sequence, type, ID, name, the rule/route it matched,
    and (when relevant) its account and a BLOCKED marker."""
    c = pc.get("Component") or {}
    kind, sub = classify(c.get("Id"), c.get("Arn"))
    ident = c.get("Id") or (c.get("Arn") or "").split("/")[-1]
    extra = ""
    if pc.get("SecurityGroupRule"):
        r = pc["SecurityGroupRule"]
        extra = (f"  [{r.get('Direction')} {proto(r.get('Protocol'))} {port_range(r.get('PortRange'))} "
                 f"{r.get('Cidr') or r.get('PrefixListId') or ''}]")
    elif pc.get("AclRule"):
        r = pc["AclRule"]
        extra = (f"  [rule {r.get('RuleNumber')} {'egress' if r.get('Egress') else 'ingress'} "
                 f"{(r.get('RuleAction') or '').upper()} {proto(r.get('Protocol'))} "
                 f"{port_range(r.get('PortRange'))} {r.get('Cidr')}]")
    elif pc.get("RouteTableRoute"):
        r = pc["RouteTableRoute"]
        tgt = next((v for k, v in r.items() if k.endswith("Id") and k != "DestinationPrefixListId" and v), "")
        extra = f"  [{r.get('DestinationCidr') or r.get('DestinationPrefixListId')} -> {tgt}]"
    name = f" ({c['Name']})" if c.get("Name") and c.get("Name") != ident else ""
    acct = f"  <{accounts.component_account(pc) or '?'}>" if show_account else ""
    blocked = blocked or {}
    codes = next((blocked[k] for k in (ident, c.get("Arn")) if k and k in blocked), None)
    blk = f"  << BLOCKED ({', '.join(codes)})" if codes is not None else ""
    return f"  {pc.get('SequenceNumber'):>3}. {label_for(kind, sub):<28} {ident}{name}{extra}{acct}{blk}"


def print_summary(bundle: dict) -> None:
    """Human-readable, hop-by-hop summary of one path + analysis (stdout)."""
    p, a = bundle["path"], bundle["analysis"]
    src = p.get("Source") or ""
    dst = p.get("Destination") or p.get("DestinationIp") or ""
    print(f"\nAnalysis {a.get('NetworkInsightsAnalysisId')}  (path {p.get('NetworkInsightsPathId')})")
    print(f"  {src} -> {dst}  {proto(p.get('Protocol'))}")
    acc = accounts.account_summary(p, a)
    print(f"  Accounts: owner={acc['owner'] or '?'} source={acc['source'] or '?'} "
          f"destination={acc['destination'] or '?'}" + ("  [CROSS-ACCOUNT]" if acc["cross_account"] else ""))
    if acc["cross_account"]:
        for acct, info in acc["accounts"].items():
            roles = ", ".join(info["roles"]) or "transit"
            print(f"    {acct}: {roles}; forward hops {info['forward']}, return hops {info['return']}")
    if a.get("SuggestedAccounts"):
        print(f"  Suggested accounts: {', '.join(a['SuggestedAccounts'])}")
    f = p.get("FilterAtSource")
    if f:
        print(f"  filter@source: src={f.get('SourceAddress') or 'any'}:{port_range(f.get('SourcePortRange'))} "
              f"dst={f.get('DestinationAddress') or 'any'}:{port_range(f.get('DestinationPortRange'))}")
    status = a.get("Status") or "unknown"
    result = ("REACHABLE" if a.get("NetworkPathFound") else "NOT REACHABLE") if status == "succeeded" else status.upper()
    print(f"  Status: {status}  Result: {result}")
    if a.get("StatusMessage"):
        print(f"  Message: {a['StatusMessage']}")
    if a.get("WarningMessage"):
        print(f"  Warning: {a['WarningMessage']}")
    # Same blocker/break logic as the HTML report, so both mark the same hops.
    targets = blocking_targets(a)
    blocked = {k: t["codes"] for t in targets for k in (t["component"].get("Id"), t["component"].get("Arn")) if k}
    brk = break_direction(p, a)
    for title, key, direction in (("Forward path", "ForwardPathComponents", "fwd"),
                                  ("Return path", "ReturnPathComponents", "ret")):
        comps = sorted(a.get(key) or [], key=lambda c: c.get("SequenceNumber") or 0)
        if comps or brk == direction:
            print(f"  {title}:")
            for pc in comps:
                print(_comp_line(pc, acc["cross_account"], blocked))
        if brk == direction:
            # Mark where the trace stops, the blocker(s), and the endpoint never reached.
            after = f"after hop {comps[-1].get('SequenceNumber')}" if comps else "before the first hop"
            print(f"    xx path stops {after}")
            for t in targets:
                c = t["component"]
                print(f"    xx BLOCKED at {c.get('Id') or c.get('Arn')} ({', '.join(t['codes'])})")
            missed = (p.get("Destination") or p.get("DestinationIp")) if direction == "fwd" else p.get("Source")
            print(f"    xx {'destination' if direction == 'fwd' else 'source (reply)'} not reached: {missed}")
    for x in a.get("Explanations") or []:
        comp = x.get("Component") or {}
        print(f"  Explanation: {x.get('ExplanationCode')} {comp.get('Id') or ''} {x.get('Direction') or ''}".rstrip())


def _bundle_for_analysis(ec2, analysis_id: str) -> dict:
    """Fetch an analysis and its path; the export format needs both."""
    analysis = core.get_analysis(ec2, analysis_id)
    path = core.get_path(ec2, analysis["NetworkInsightsPathId"])
    return core.build_bundle(path, analysis)


def _finish(ec2, args, path: dict, analysis: dict) -> int:
    """Shared tail for create/analyze: wait, summarize, and write the HTML report
    (to --export, or the reports folder unless --no-report)."""
    if args.no_report and not (args.wait or args.export or args.json_out):
        print(f"Analysis {analysis['NetworkInsightsAnalysisId']} started. "
              f"Use: reachability.py show {analysis['NetworkInsightsAnalysisId']}")
        return 0
    analysis = core.wait_for_analysis(ec2, analysis["NetworkInsightsAnalysisId"], timeout=args.timeout)
    bundle = core.build_bundle(path, analysis)
    print_summary(bundle)
    _warn_suggested_accounts(analysis)
    if args.export:
        _write_export([bundle], args.export, args.title, args.theme)
    elif not args.no_report:
        _write_export([bundle], core.report_path(bundle, args.reports_dir), args.title, args.theme)
    if args.json_out:
        _write_json([bundle], args.json_out)
    return 0 if analysis.get("Status") == "succeeded" else 2


# ---------- commands ----------

def cmd_types(args, _execute: bool) -> int:
    """List supported source/destination and intermediate types (no AWS calls)."""
    print("Source / destination resource types:")
    for key, (prefix, _, label) in core.ENDPOINT_TYPES.items():
        print(f"  {label:<30} {prefix}*   (ARN type: {key})")
    print("  IP address (destination only)  --dest-ip A.B.C.D")
    print("\nIntermediate components (--filter-in / --filter-out, ARNs):")
    for t in core.INTERMEDIATE_TYPES:
        print(f"  {t}")
    return 0


def _parse_tags(values: list[str] | None) -> dict[str, str]:
    tags = {}
    for t in values or []:
        if "=" not in t or not t.split("=", 1)[0]:
            raise core.ValidationError(f"Invalid --tag {t!r}; use KEY=VALUE")
        k, v = t.split("=", 1)
        tags[k] = v
    return tags


def cmd_create(args, execute: bool) -> int:
    """Create a path and (unless --no-analyze) start an analysis on it.

    Requests are fully built and validated first, so a dry-run shows exactly what
    --execute would send. On execute: create the path, add any other accounts its
    ARNs reference (_auto_accounts), start the analysis, then _finish()."""
    spec = core.PathSpec(
        source=args.source,
        destination=args.dest,
        protocol=args.protocol,
        source_ip=args.source_ip,
        destination_ip=args.dest_ip,
        source_ports=core.parse_port_range(args.source_port),
        destination_ports=core.parse_port_range(args.dest_port),
        name=args.name,
        tags=_parse_tags(args.tag),
    )
    path_req = core.build_create_path_request(spec)
    an_req = None
    if not args.no_analyze:
        # The path ID isn't known until the path exists; filled in after create_path.
        an_req = core.build_start_analysis_request("<new-path-id>", args.filter_in, args.filter_out,
                                                   args.additional_account, args.analysis_name)
    if not execute:
        log.info("[DRY-RUN] Would call CreateNetworkInsightsPath:\n%s", _dump(path_req))
        if an_req:
            log.info("[DRY-RUN] Would call StartNetworkInsightsAnalysis:\n%s", _dump(an_req))
            # The path owner (caller's account) isn't known without an API call, so
            # list every account the ARNs mention; non-owner ones get added on execute.
            arn_accts = sorted({a for a in map(accounts.arn_account, [args.source, args.dest,
                                *(args.filter_in or []), *(args.filter_out or [])]) if a})
            if arn_accts and not args.no_auto_accounts:
                log.info("[DRY-RUN] Would also add to AdditionalAccounts any of %s not owning the path",
                         ", ".join(arn_accts))
            _log_dry_run_report(args)
        if args.check_permissions:
            _check_permission(_ec2(args).create_network_insights_path, path_req)
        return 0

    ec2 = _ec2(args)
    path = core.create_path(ec2, path_req)
    print(f"Path {path['NetworkInsightsPathId']}  {path['NetworkInsightsPathArn']}")
    if not an_req:
        return 0
    an_req["NetworkInsightsPathId"] = path["NetworkInsightsPathId"]
    _auto_accounts(args, path, an_req)
    analysis = core.start_analysis(ec2, an_req)
    return _finish(ec2, args, path, analysis)


def cmd_analyze(args, execute: bool) -> int:
    """Start a new analysis on an existing path, then _finish()."""
    an_req = core.build_start_analysis_request(args.path_id, args.filter_in, args.filter_out,
                                               args.additional_account, args.analysis_name)
    if not execute:
        log.info("[DRY-RUN] Would call StartNetworkInsightsAnalysis:\n%s", _dump(an_req))
        _log_dry_run_report(args)
        if args.check_permissions:
            _check_permission(_ec2(args).start_network_insights_analysis, an_req)
        return 0
    ec2 = _ec2(args)
    path = core.get_path(ec2, args.path_id)
    _auto_accounts(args, path, an_req)
    analysis = core.start_analysis(ec2, an_req)
    return _finish(ec2, args, path, analysis)


def _auto_accounts(args, path: dict, an_req: dict) -> None:
    """Add accounts that own the source, destination, or filter components (but not the
    path) to AdditionalAccounts, so Reachability Analyzer can describe them."""
    if args.no_auto_accounts:
        return
    have = an_req.get("AdditionalAccounts") or []
    new = [a for a in accounts.related_accounts(path, (args.filter_in or []) + (args.filter_out or []))
           if a not in have]
    if new:
        an_req["AdditionalAccounts"] = have + new
        log.info("Adding accounts %s to AdditionalAccounts (resources outside path owner account %s)",
                 ", ".join(new), accounts.path_owner(path) or "?")


def _warn_suggested_accounts(analysis: dict) -> None:
    missing = [a for a in analysis.get("SuggestedAccounts") or []
               if a not in (analysis.get("AdditionalAccounts") or [])]
    if missing:
        log.warning("AWS suggests including accounts %s. Re-run with %s for a complete result.",
                    ", ".join(missing), " ".join(f"--additional-account {a}" for a in missing))


def _log_dry_run_report(args) -> None:
    """Dry-run note on where the HTML report would be written."""
    if args.export:
        log.info("[DRY-RUN] Would wait for the analysis and write %s", args.export)
    elif not args.no_report:
        log.info("[DRY-RUN] Would wait for the analysis and write %s/<date>/<account>/<analysis>.html",
                 args.reports_dir)


def _check_permission(fn, req: dict) -> None:
    """Call an EC2 API with DryRun=True. AWS answers DryRunOperation if the caller is
    allowed (nothing is created) or UnauthorizedOperation if not."""
    try:
        fn(DryRun=True, **req)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "DryRunOperation":
            log.info("[DRY-RUN] Permission check passed")
            return
        log.error("[DRY-RUN] Permission check failed: %s %s", code, e.response["Error"]["Message"])
        raise


def cmd_paths(args, _execute: bool) -> int:
    """List paths: ID, source -> destination, protocol/destination ports, Name tag."""
    ec2 = _ec2(args)
    rows = list(core.iter_paths(ec2))
    if args.json:
        print(_dump(rows))
        return 0
    for p in rows:
        name = next((t["Value"] for t in p.get("Tags") or [] if t["Key"] == "Name"), "")
        f = p.get("FilterAtSource") or {}
        # Ports live in FilterAtSource for paths made by this tool; older paths may use
        # the top-level DestinationPort.
        ports = port_range(f.get("DestinationPortRange")) if f else (p.get("DestinationPort") or "All")
        print(f"{p['NetworkInsightsPathId']}  {p.get('Source')} -> {p.get('Destination') or p.get('DestinationIp')}"
              f"  {proto(p.get('Protocol'))}/{ports}  {name}")
    return 0


def cmd_analyses(args, _execute: bool) -> int:
    """List analyses (newest first), optionally for one path."""
    ec2 = _ec2(args)
    rows = list(core.iter_analyses(ec2, args.path_id))
    if args.json:
        print(_dump(rows))
        return 0
    for a in sorted(rows, key=lambda r: str(r.get("StartDate")), reverse=True):
        found = {True: "reachable", False: "not-reachable"}.get(a.get("NetworkPathFound"), "-")
        print(f"{a['NetworkInsightsAnalysisId']}  {a['NetworkInsightsPathId']}  {a.get('Status'):<9}  "
              f"{found:<13}  {a.get('StartDate')}")
    return 0


def cmd_show(args, _execute: bool) -> int:
    """Print one analysis summary, or the raw bundle with --json."""
    ec2 = _ec2(args)
    bundle = _bundle_for_analysis(ec2, args.analysis_id)
    if args.json:
        print(_dump(bundle))
    else:
        print_summary(bundle)
    return 0


def cmd_export(args, _execute: bool) -> int:
    """Render analyses to HTML. Bundles come from saved JSON (--from-json, offline)
    and/or the API (analysis IDs). Without -o, each gets its own file in the reports
    folder; with -o, they're combined into one file."""
    bundles: list[dict] = []
    for f in args.from_json or []:
        data = json.loads(Path(f).read_text(encoding="utf-8"))
        bundles.extend(data if isinstance(data, list) else [data])
    if args.analysis_ids:
        ec2 = _ec2(args)
        if args.wait:
            for aid in args.analysis_ids:
                core.wait_for_analysis(ec2, aid, timeout=args.timeout)
        bundles.extend(_bundle_for_analysis(ec2, aid) for aid in args.analysis_ids)
    if not bundles:
        raise core.ValidationError("Provide analysis IDs and/or --from-json files")
    if args.output:
        _write_export(bundles, args.output, args.title, args.theme)
    else:
        for b in bundles:
            _write_export([b], core.report_path(b, args.reports_dir), args.title, args.theme)
    if args.json_out:
        _write_json(bundles, args.json_out)
    return 0


def cmd_delete_path(args, execute: bool) -> int:
    """Delete paths (and optionally their analyses). A dry-run with --with-analyses
    still lists the analyses through the API so it can say what would be deleted."""
    ec2 = _ec2(args) if execute or args.with_analyses else None
    for pid in args.path_ids:
        if args.with_analyses:
            for a in core.iter_analyses(ec2, pid):
                if execute:
                    core.delete_analysis(ec2, a["NetworkInsightsAnalysisId"])
                else:
                    log.info("[DRY-RUN] Would delete analysis %s", a["NetworkInsightsAnalysisId"])
        if execute:
            core.delete_path(ec2, pid)
        else:
            log.info("[DRY-RUN] Would delete path %s", pid)
    return 0


def cmd_delete_analysis(args, execute: bool) -> int:
    """Delete analyses."""
    ec2 = _ec2(args) if execute else None
    for aid in args.analysis_ids:
        if execute:
            core.delete_analysis(ec2, aid)
        else:
            log.info("[DRY-RUN] Would delete analysis %s", aid)
    return 0


# ---------- argument parsing ----------
# Global options are added to each subparser, so they go after the subcommand.

def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--profile", default=os.getenv("AWS_PROFILE"), help="AWS profile name (not included in exports)")
    p.add_argument("--region", default=os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION"),
                   help="AWS region (default: AWS_REGION or profile region)")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    p.add_argument("-q", "--quiet", action="store_true", help="Warnings and errors only")


def _add_mutating(p: argparse.ArgumentParser) -> None:
    p.add_argument("--execute", action="store_true", help="Apply changes (default: dry-run)")
    p.add_argument("--apply", action="store_true", help="Alias for --execute")


def _add_report_opts(p: argparse.ArgumentParser) -> None:
    p.add_argument("--theme", choices=THEMES, default=os.getenv("RA_THEME", "dark"),
                   help="HTML report theme: dark (default), light, or auto (follow OS); toggle in-page")
    p.add_argument("--reports-dir", default=os.getenv("RA_REPORTS_DIR", "reports"), metavar="DIR",
                   help="Reports root; reports go to DIR/<YYYY-MM-DD>/<account-id>/ (default: ./reports)")


def _add_analysis_opts(p: argparse.ArgumentParser) -> None:
    p.add_argument("--filter-in", action="append", metavar="ARN",
                   help="Require path through this intermediate component (repeatable)")
    p.add_argument("--filter-out", action="append", metavar="ARN",
                   help="Exclude this intermediate component (repeatable)")
    p.add_argument("--additional-account", action="append", metavar="ACCOUNT_ID",
                   help="Additional account for cross-account analysis (repeatable)")
    p.add_argument("--no-auto-accounts", action="store_true",
                   help="Don't add source/destination/filter ARN accounts to AdditionalAccounts automatically")
    p.add_argument("--analysis-name", help="Name tag for the analysis")
    p.add_argument("--wait", action="store_true", help="Wait for analysis to complete and print a summary")
    p.add_argument("--timeout", type=int, default=int(os.getenv("RA_WAIT_TIMEOUT", "600")),
                   help="Wait timeout in seconds (default 600)")
    p.add_argument("--export", metavar="FILE.html",
                   help="Write the HTML report to this file instead of the reports folder")
    _add_report_opts(p)
    p.add_argument("--no-report", action="store_true",
                   help="Don't write an HTML report (and don't wait unless --wait/--json-out)")
    p.add_argument("--json-out", metavar="FILE.json", help="Wait, then save path+analysis JSON")
    p.add_argument("--title", help="Title for the HTML export")
    p.add_argument("--check-permissions", action="store_true",
                   help="In dry-run, call the API with DryRun=True to verify IAM permissions")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("types", help="List supported source/destination and intermediate types")
    _add_common(p)
    p.set_defaults(func=cmd_types)

    p = sub.add_parser("create", help="Create a path and (by default) run an analysis",
                       description="Source IP and source/destination ports are applied as FilterAtSource, "
                                   "so the packet header is defined where traffic originates.")
    _add_common(p)
    _add_mutating(p)
    p.add_argument("--source", "-s", required=True, help="Source resource ID or ARN")
    p.add_argument("--dest", "-d", help="Destination resource ID or ARN")
    p.add_argument("--dest-ip", help="Destination IPv4 address (alone, or to pick an IP on --dest)")
    p.add_argument("--source-ip", help="Source IPv4 address (applied at source)")
    p.add_argument("--protocol", "-p", choices=core.PROTOCOLS, default="tcp")
    p.add_argument("--dest-port", help="Destination port or range, e.g. 443 or 8000-8100 (applied at source)")
    p.add_argument("--source-port", help="Source port or range, e.g. 1024-65535 (applied at source)")
    p.add_argument("--name", help="Name tag for the path")
    p.add_argument("--tag", action="append", metavar="KEY=VALUE", help="Extra path tag (repeatable)")
    p.add_argument("--no-analyze", action="store_true", help="Create the path only")
    _add_analysis_opts(p)
    p.set_defaults(func=cmd_create, mutating=True)

    p = sub.add_parser("analyze", help="Start an analysis on an existing path")
    _add_common(p)
    _add_mutating(p)
    p.add_argument("path_id")
    _add_analysis_opts(p)
    p.set_defaults(func=cmd_analyze, mutating=True)

    p = sub.add_parser("paths", help="List paths")
    _add_common(p)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_paths)

    p = sub.add_parser("analyses", help="List analyses")
    _add_common(p)
    p.add_argument("--path-id")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_analyses)

    p = sub.add_parser("show", help="Show an analysis summary")
    _add_common(p)
    p.add_argument("analysis_id")
    p.add_argument("--json", action="store_true", help="Print path+analysis JSON bundle")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("export", help="Export analyses to self-contained HTML reports")
    _add_common(p)
    p.add_argument("analysis_ids", nargs="*")
    p.add_argument("--output", "-o", metavar="FILE.html",
                   help="Write one combined file here instead of one report per analysis in the reports folder")
    _add_report_opts(p)
    p.add_argument("--from-json", action="append", metavar="FILE.json",
                   help="Render from a saved JSON bundle instead of the API (repeatable)")
    p.add_argument("--json-out", metavar="FILE.json", help="Also save the JSON bundle(s)")
    p.add_argument("--title")
    p.add_argument("--wait", action="store_true", help="Wait for running analyses first")
    p.add_argument("--timeout", type=int, default=600)
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("delete-path", help="Delete paths")
    _add_common(p)
    _add_mutating(p)
    p.add_argument("path_ids", nargs="+")
    p.add_argument("--with-analyses", action="store_true", help="Also delete the path's analyses")
    p.set_defaults(func=cmd_delete_path, mutating=True)

    p = sub.add_parser("delete-analysis", help="Delete analyses")
    _add_common(p)
    _add_mutating(p)
    p.add_argument("analysis_ids", nargs="+")
    p.set_defaults(func=cmd_delete_analysis, mutating=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Parse arguments, set log level, run the subcommand. Expected errors are logged
    and become exit code 1; a failed analysis returns 2 (from _finish)."""
    args = build_parser().parse_args(argv)
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.quiet:
        logging.getLogger().setLevel(logging.WARNING)

    execute = bool(getattr(args, "execute", False) or getattr(args, "apply", False))
    if getattr(args, "mutating", False) and not execute:
        log.info("Dry-run mode. Pass --execute or --apply to apply changes.")
    try:
        return args.func(args, execute)
    except core.ValidationError as e:
        log.error("%s", e)
        return 1
    except (LookupError, TimeoutError, ValueError) as e:
        log.error("%s", e)
        return 1
    except (NoCredentialsError, ProfileNotFound) as e:
        log.error("Credentials error: %s", e)
        return 1
    except ClientError as e:
        log.error("AWS error %s: %s", e.response["Error"]["Code"], e.response["Error"]["Message"])
        return 1


if __name__ == "__main__":
    sys.exit(main())
