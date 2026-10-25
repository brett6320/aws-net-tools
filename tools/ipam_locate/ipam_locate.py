#!/usr/bin/env python3
"""Find the account, Region, VPC and resource behind an IP or CIDR using Amazon VPC IPAM.

For each query, il_core.collect() reads the IPAM (pools, pool CIDRs and
allocations, discovered resource CIDRs, public addresses, address history) from
the IPAM home Region, il_core.locate() narrows it to candidate owners or, failing
that, the most specific parent CIDR, and il_export renders an HTML report with
the full hierarchy. Read-only: no IPAM or EC2 resources are changed, so there's
no dry-run mode.

Logs go to stderr; the summary (or --json) goes to stdout.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

import truststore

truststore.inject_into_ssl()

from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound  # noqa: E402
from dotenv import load_dotenv  # noqa: E402

import il_core as core  # noqa: E402
from il_export import THEMES, render_html  # noqa: E402

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("ipam_locate")


def _ec2(args):
    """EC2 client in the IPAM home Region. The profile is only used here; it is never
    written to reports or JSON."""
    log.debug("Using profile=%s region=%s", args.profile or "default", args.region or "(profile default)")
    session = core.get_session(args.profile, args.region)
    if not session.region_name:
        raise core.ValidationError("No region configured; pass --region (the IPAM home Region) or set AWS_REGION")
    return core.get_client("ec2", session)


def _dump(obj) -> str:
    return json.dumps(obj, indent=2, default=lambda o: o.isoformat() if hasattr(o, "isoformat") else str(o))


def print_summary(b: dict) -> None:
    """Short answer for the terminal: owners, or the most specific parent and its pool."""
    loc = core.locate(b)
    ipam = b.get("ipam") or {}
    home = ipam.get("IpamRegion")
    part = core.partition_of(ipam.get("IpamArn"))
    print(f"Query  {b['query']}  ({b.get('family')}, {'address' if loc['single'] else 'CIDR'})")
    print(f"IPAM   {ipam.get('IpamId')}  home {home}  owner {ipam.get('OwnerId')}  {ipam.get('Tier')} tier")
    labels = {"resource": "resource found", "network": "network found (no specific resource)",
              "pool": "pool only (no discovered resource)", "none": "not found in IPAM"}
    print(f"Result {labels[loc['status']]}")
    for i, c in enumerate(loc["candidates"], 1):
        parts = [f"account {c['account']}", c["region"] or "?"]
        for k in ("vpc", "subnet"):
            if c[k]:
                parts.append(c[k].get("ResourceId"))
        if c["resource"] and c["resource"].get("ResourceType") not in ("vpc", "subnet"):
            parts.append(c["resource"].get("ResourceId"))
        elif c["eni_id"]:
            parts.append(c["eni_id"])
        if c["instance"]:
            parts.append(c["instance"].get("ResourceId"))
        if c["public"] and c["public"].get("Service") not in (None, "other"):
            parts.append(f"{c['public']['Service']} {c['public'].get('ServiceResource') or ''}".strip())
        print(f"  {i}. " + " · ".join(p for p in parts if p) + f"  [{c['cidr']}]")
    if loc["most_specific"]:
        print(f"Most specific parent  {loc['most_specific']['cidr']}  (from {loc['most_specific']['source']})")
    pool = loc["deepest_pool"]
    if pool:
        print(f"Most specific pool    {pool['IpamPoolId']}  {core.best_cidr(pool)}  "
              f"{core.console_url('pool', pool['IpamPoolId'], home, part)}")
    if loc["allocation"]:
        a = loc["allocation"]
        print(f"Pool allocation       {a.get('Cidr')} -> {a.get('ResourceType')} {a.get('ResourceId') or ''} "
              f"account {a.get('ResourceOwner')} {a.get('ResourceRegion')}")
    if not loc["single"] and loc["within"]:
        print(f"Inside the CIDR       {len(loc['within'])} discovered resource CIDR(s) (see the report)")
    for w in b.get("warnings") or []:
        log.warning("%s", w)


def _write_report(bundles: list[dict], out: Path, title: str | None, theme: str) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_html(bundles, title, theme), encoding="utf-8")
    log.info("Wrote HTML report %s", out)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("queries", nargs="*", metavar="IP_OR_CIDR", help="IPv4/IPv6 address or CIDR (repeatable)")
    p.add_argument("--profile", default=os.getenv("AWS_PROFILE"),
                   help="AWS profile for the IPAM owner / delegated admin account (not included in reports)")
    p.add_argument("--region", default=os.getenv("IPAM_REGION") or os.getenv("AWS_REGION")
                   or os.getenv("AWS_DEFAULT_REGION"), help="IPAM home Region")
    p.add_argument("--ipam-id", default=os.getenv("IPAM_ID"), help="IPAM to use when the Region has several")
    p.add_argument("--regions", metavar="R1,R2", help="Only search these operating Regions (comma-separated)")
    p.add_argument("--output", "-o", metavar="FILE.html", help="Write one combined report here")
    p.add_argument("--reports-dir", default=os.getenv("IPAM_REPORTS_DIR", "reports"), metavar="DIR",
                   help="Reports root; reports go to DIR/<YYYY-MM-DD>/<account-id>/ (default: ./reports)")
    p.add_argument("--no-report", action="store_true", help="Print the summary only")
    p.add_argument("--theme", choices=THEMES, default=os.getenv("IPAM_THEME", "dark"),
                   help="HTML report theme: dark (default), light, or auto")
    p.add_argument("--title", help="HTML page title")
    p.add_argument("--json", action="store_true", help="Print the bundle(s) as JSON instead of the summary")
    p.add_argument("--json-out", metavar="FILE.json", help="Also save the bundle(s) for --from-json")
    p.add_argument("--from-json", action="append", metavar="FILE.json",
                   help="Re-render saved bundles offline instead of calling the API (repeatable)")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    return p


def run(args) -> int:
    bundles: list[dict] = []
    for f in args.from_json or []:
        data = json.loads(Path(f).read_text(encoding="utf-8"))
        bundles.extend(data if isinstance(data, list) else [data])
    queries = [core.parse_query(q) for q in args.queries]
    if queries:
        ec2 = _ec2(args)
        regions = [r.strip() for r in args.regions.split(",") if r.strip()] if args.regions else None
        for q in queries:
            # Round-trip through JSON so datetimes become strings, same as a saved bundle.
            bundles.append(json.loads(_dump(core.collect(ec2, q, args.ipam_id, regions))))
    if not bundles:
        raise core.ValidationError("Give an IP or CIDR (or --from-json FILE)")

    if args.json:
        print(_dump(bundles[0] if len(bundles) == 1 else bundles))
    else:
        for i, b in enumerate(bundles):
            if i:
                print()
            print_summary(b)
    if args.json_out:
        Path(args.json_out).write_text(_dump(bundles[0] if len(bundles) == 1 else bundles), encoding="utf-8")
        log.info("Wrote JSON %s", args.json_out)
    if args.output:
        _write_report(bundles, Path(args.output), args.title, args.theme)
    elif not args.no_report:
        for b in bundles:
            _write_report([b], core.report_path(b, args.reports_dir), args.title, args.theme)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.quiet:
        logging.getLogger().setLevel(logging.WARNING)
    try:
        return run(args)
    except (core.ValidationError, LookupError, ValueError) as e:
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
