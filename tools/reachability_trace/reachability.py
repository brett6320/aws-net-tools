#!/usr/bin/env python3
"""Create, run, inspect, and export AWS VPC Reachability Analyzer traces."""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

import truststore

truststore.inject_into_ssl()

from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound  # noqa: E402
from dotenv import load_dotenv  # noqa: E402

import ra_core as core  # noqa: E402
from ra_export import port_range, proto, render_html  # noqa: E402
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
    log.debug("Using profile=%s region=%s", args.profile or "default", args.region or "(profile default)")
    session = core.get_session(args.profile, args.region)
    if not session.region_name:
        raise core.ValidationError("No region configured; pass --region or set AWS_REGION")
    return core.get_client("ec2", session)


def _json_default(o: Any) -> str:
    return o.isoformat() if hasattr(o, "isoformat") else str(o)


def _dump(obj: Any) -> str:
    return json.dumps(obj, indent=2, default=_json_default)


def _write_export(bundles: list[dict], out: str, title: str | None) -> None:
    Path(out).write_text(render_html(bundles, title), encoding="utf-8")
    log.info("Wrote HTML export %s", out)


def _write_json(bundles: list[dict], out: str) -> None:
    Path(out).write_text(_dump(bundles if len(bundles) > 1 else bundles[0]), encoding="utf-8")
    log.info("Wrote JSON %s", out)


def _comp_line(pc: dict) -> str:
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
    return f"  {pc.get('SequenceNumber'):>3}. {label_for(kind, sub):<28} {ident}{name}{extra}"


def print_summary(bundle: dict) -> None:
    p, a = bundle["path"], bundle["analysis"]
    src = p.get("Source") or ""
    dst = p.get("Destination") or p.get("DestinationIp") or ""
    print(f"\nAnalysis {a.get('NetworkInsightsAnalysisId')}  (path {p.get('NetworkInsightsPathId')})")
    print(f"  {src} -> {dst}  {proto(p.get('Protocol'))}")
    f = p.get("FilterAtSource")
    if f:
        print(f"  filter@source: src={f.get('SourceAddress') or 'any'}:{port_range(f.get('SourcePortRange'))} "
              f"dst={f.get('DestinationAddress') or 'any'}:{port_range(f.get('DestinationPortRange'))}")
    status = a.get("Status")
    result = ("REACHABLE" if a.get("NetworkPathFound") else "NOT REACHABLE") if status == "succeeded" else status.upper()
    print(f"  Status: {status}  Result: {result}")
    if a.get("StatusMessage"):
        print(f"  Message: {a['StatusMessage']}")
    if a.get("WarningMessage"):
        print(f"  Warning: {a['WarningMessage']}")
    for title, key in (("Forward path", "ForwardPathComponents"), ("Return path", "ReturnPathComponents")):
        comps = sorted(a.get(key) or [], key=lambda c: c.get("SequenceNumber") or 0)
        if comps:
            print(f"  {title}:")
            for pc in comps:
                print(_comp_line(pc))
    for x in a.get("Explanations") or []:
        comp = x.get("Component") or {}
        print(f"  Explanation: {x.get('ExplanationCode')} {comp.get('Id') or ''} {x.get('Direction') or ''}".rstrip())


def _bundle_for_analysis(ec2, analysis_id: str) -> dict:
    analysis = core.get_analysis(ec2, analysis_id)
    path = core.get_path(ec2, analysis["NetworkInsightsPathId"])
    return core.build_bundle(path, analysis)


def _finish(ec2, args, path: dict, analysis: dict) -> int:
    """Shared tail for create/analyze: optionally wait, then summarize/export."""
    if not (args.wait or args.export or args.json_out):
        print(f"Analysis {analysis['NetworkInsightsAnalysisId']} started. "
              f"Use: reachability.py show {analysis['NetworkInsightsAnalysisId']}")
        return 0
    analysis = core.wait_for_analysis(ec2, analysis["NetworkInsightsAnalysisId"], timeout=args.timeout)
    bundle = core.build_bundle(path, analysis)
    print_summary(bundle)
    if args.export:
        _write_export([bundle], args.export, args.title)
    if args.json_out:
        _write_json([bundle], args.json_out)
    return 0 if analysis.get("Status") == "succeeded" else 2


# ---------- commands ----------

def cmd_types(args, _execute: bool) -> int:
    print("Source / destination resource types:")
    for key, (prefix, _, label) in core.ENDPOINT_TYPES.items():
        print(f"  {label:<30} {prefix}*   (ARN type: {key})")
    print("  IP address (destination only)  --dest-ip A.B.C.D")
    print("\nIntermediate components (--filter-in / --filter-out, ARNs):")
    for t in core.INTERMEDIATE_TYPES:
        print(f"  {t}")
    return 0


def cmd_create(args, execute: bool) -> int:
    spec = core.PathSpec(
        source=args.source,
        destination=args.dest,
        protocol=args.protocol,
        source_ip=args.source_ip,
        destination_ip=args.dest_ip,
        source_ports=core.parse_port_range(args.source_port),
        destination_ports=core.parse_port_range(args.dest_port),
        name=args.name,
        tags=dict(t.split("=", 1) for t in args.tag or []),
    )
    path_req = core.build_create_path_request(spec)
    an_req = None
    if not args.no_analyze:
        an_req = core.build_start_analysis_request("<new-path-id>", args.filter_in, args.filter_out,
                                                   args.additional_account, args.analysis_name)
    if not execute:
        log.info("[DRY-RUN] Would call CreateNetworkInsightsPath:\n%s", _dump(path_req))
        if an_req:
            log.info("[DRY-RUN] Would call StartNetworkInsightsAnalysis:\n%s", _dump(an_req))
        if args.check_permissions:
            _check_permission(_ec2(args).create_network_insights_path, path_req)
        return 0

    ec2 = _ec2(args)
    path = core.create_path(ec2, path_req)
    print(f"Path {path['NetworkInsightsPathId']}  {path['NetworkInsightsPathArn']}")
    if not an_req:
        return 0
    an_req["NetworkInsightsPathId"] = path["NetworkInsightsPathId"]
    analysis = core.start_analysis(ec2, an_req)
    return _finish(ec2, args, path, analysis)


def cmd_analyze(args, execute: bool) -> int:
    an_req = core.build_start_analysis_request(args.path_id, args.filter_in, args.filter_out,
                                               args.additional_account, args.analysis_name)
    if not execute:
        log.info("[DRY-RUN] Would call StartNetworkInsightsAnalysis:\n%s", _dump(an_req))
        if args.check_permissions:
            _check_permission(_ec2(args).start_network_insights_analysis, an_req)
        return 0
    ec2 = _ec2(args)
    path = core.get_path(ec2, args.path_id)
    analysis = core.start_analysis(ec2, an_req)
    return _finish(ec2, args, path, analysis)


def _check_permission(fn, req: dict) -> None:
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
    ec2 = _ec2(args)
    rows = list(core.iter_paths(ec2))
    if args.json:
        print(_dump(rows))
        return 0
    for p in rows:
        name = next((t["Value"] for t in p.get("Tags") or [] if t["Key"] == "Name"), "")
        f = p.get("FilterAtSource") or {}
        ports = port_range(f.get("DestinationPortRange")) if f else (p.get("DestinationPort") or "All")
        print(f"{p['NetworkInsightsPathId']}  {p.get('Source')} -> {p.get('Destination') or p.get('DestinationIp')}"
              f"  {proto(p.get('Protocol'))}/{ports}  {name}")
    return 0


def cmd_analyses(args, _execute: bool) -> int:
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
    ec2 = _ec2(args)
    bundle = _bundle_for_analysis(ec2, args.analysis_id)
    if args.json:
        print(_dump(bundle))
    else:
        print_summary(bundle)
    return 0


def cmd_export(args, _execute: bool) -> int:
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
    _write_export(bundles, args.output, args.title)
    if args.json_out:
        _write_json(bundles, args.json_out)
    return 0


def cmd_delete_path(args, execute: bool) -> int:
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
    ec2 = _ec2(args) if execute else None
    for aid in args.analysis_ids:
        if execute:
            core.delete_analysis(ec2, aid)
        else:
            log.info("[DRY-RUN] Would delete analysis %s", aid)
    return 0


# ---------- argument parsing ----------

def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--profile", default=os.getenv("AWS_PROFILE"), help="AWS profile name (not included in exports)")
    p.add_argument("--region", default=os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION"),
                   help="AWS region (default: AWS_REGION or profile region)")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    p.add_argument("-q", "--quiet", action="store_true", help="Warnings and errors only")


def _add_mutating(p: argparse.ArgumentParser) -> None:
    p.add_argument("--execute", action="store_true", help="Apply changes (default: dry-run)")
    p.add_argument("--apply", action="store_true", help="Alias for --execute")


def _add_analysis_opts(p: argparse.ArgumentParser) -> None:
    p.add_argument("--filter-in", action="append", metavar="ARN",
                   help="Require path through this intermediate component (repeatable)")
    p.add_argument("--filter-out", action="append", metavar="ARN",
                   help="Exclude this intermediate component (repeatable)")
    p.add_argument("--additional-account", action="append", metavar="ACCOUNT_ID",
                   help="Additional account for cross-account analysis (repeatable)")
    p.add_argument("--analysis-name", help="Name tag for the analysis")
    p.add_argument("--wait", action="store_true", help="Wait for analysis to complete and print a summary")
    p.add_argument("--timeout", type=int, default=int(os.getenv("RA_WAIT_TIMEOUT", "600")),
                   help="Wait timeout in seconds (default 600)")
    p.add_argument("--export", metavar="FILE.html", help="Wait, then export the trace to self-contained HTML")
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

    p = sub.add_parser("export", help="Export analyses to a self-contained HTML file")
    _add_common(p)
    p.add_argument("analysis_ids", nargs="*")
    p.add_argument("--output", "-o", required=True, metavar="FILE.html")
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
    except (LookupError, TimeoutError) as e:
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
