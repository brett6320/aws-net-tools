#!/usr/bin/env python3
"""List every VPC owned by the accounts in one or more AWS Organizations OUs (read-only).

OUs are resolved to accounts with the Organizations API (``--profile``: management or
delegated-administrator account), including every OU below them unless ``--no-recurse``.
Each account is then read with the profile that maps to its account ID in ~/.aws/config
(never one ending in -priv or -cpar), one DescribeVpcs per Region.

Every VPC found is written to the local VPC owner map that ``phz_review`` uses
(~/.cache/aws-net-tools/vpc-owners.json), with its account name, OU, Name tag and CIDRs.

Logs go to stderr; the table / CSV / JSON goes to stdout.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Sequence

import truststore

# Use the OS certificate store. Injecting after urllib3 has captured ssl.SSLContext recurses
# forever, which only happens when something imported boto3 first (e.g. the tests).
if "urllib3" not in sys.modules:
    truststore.inject_into_ssl()

import boto3  # noqa: E402
from botocore.exceptions import BotoCoreError, ClientError  # noqa: E402
from dotenv import load_dotenv  # noqa: E402

import ov_core as core  # noqa: E402
from ov_cache import VpcOwnerCache, default_path  # noqa: E402

load_dotenv()

log = logging.getLogger("ou_vpcs")

COLUMNS = ("ou_path", "account", "account_name", "region", "vpc_id", "name", "cidrs", "is_default")
SKIPPED_EXIT = 3


def configure_logging(verbose: bool = False, quiet: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.WARNING if quiet else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
                        datefmt="%Y-%m-%dT%H:%M:%S", stream=sys.stderr)
    logging.getLogger().setLevel(level)
    if not verbose:
        for noisy in ("botocore", "boto3", "urllib3"):
            logging.getLogger(noisy).setLevel(logging.WARNING)


def _cell(v: Any) -> str:
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, (list, tuple)):
        return ",".join(str(x) for x in v)
    return "" if v is None else str(v)


def render(rows: Sequence[dict[str, Any]], columns: Sequence[str], fmt: str, stream=None) -> None:
    stream = stream or sys.stdout
    if fmt == "json":
        json.dump(list(rows), stream, indent=2, default=str)
        stream.write("\n")
        return
    if fmt == "csv":
        w = csv.writer(stream)
        w.writerow(columns)
        for r in rows:
            w.writerow([_cell(r.get(c)) for c in columns])
        return
    table = [[_cell(r.get(c)) for c in columns] for r in rows]
    widths = [max([len(c)] + [len(row[i]) for row in table]) for i, c in enumerate(columns)]
    buf = io.StringIO()
    buf.write("  ".join(c.upper().ljust(widths[i]) for i, c in enumerate(columns)).rstrip() + "\n")
    buf.write("  ".join("-" * w for w in widths) + "\n")
    for row in table:
        buf.write("  ".join(v.ljust(widths[i]) for i, v in enumerate(row)).rstrip() + "\n")
    stream.write(buf.getvalue())
    if not rows:
        stream.write("(no results)\n")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="List the VPCs owned by every account in one or more OUs (read-only).")
    p.add_argument("--ou", action="append", metavar="OU_ID", help="OU ID (ou-xxxx-xxxxxxxx), root ID (r-xxxx) or organization ID (o-xxxxxxxxxx); repeat or comma-separate (env OU_VPCS_OU)")
    p.add_argument("--profile", default=os.getenv("OU_VPCS_ORG_PROFILE") or os.getenv("AWS_PROFILE"),
                   help="Profile for the Organizations calls: management or delegated-administrator account "
                        "(default: OU_VPCS_ORG_PROFILE, AWS_PROFILE, default chain)")
    p.add_argument("--regions", action="append", help=f"Regions to scan in each account; repeat or comma-separate (default: {','.join(core.DEFAULT_REGIONS)}; env OU_VPCS_REGIONS)")
    p.add_argument("--no-recurse", action="store_true", help="Only accounts directly in the OU, not in OUs below it")
    p.add_argument("--account-profile", action="append", metavar="ACCOUNT=PROFILE",
                   help="Profile to use for an account (when several or none map to it); repeat or comma-separate")
    p.add_argument("--cache", default=os.getenv("OU_VPCS_CACHE") or os.getenv("VPCE_OWNER_CACHE"), metavar="FILE",
                   help="VPC owner map shared with phz_review (default: ~/.cache/aws-net-tools/vpc-owners.json; "
                        "env OU_VPCS_CACHE / VPCE_OWNER_CACHE)")
    p.add_argument("--no-cache", action="store_true", help="Don't write the VPC owner map")
    p.add_argument("--output", "-o", choices=("table", "json", "csv"), default="table", help="Output format (default: table)")
    p.add_argument("--json", dest="output", action="store_const", const="json", help="Shortcut for --output json")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    p.add_argument("-q", "--quiet", action="store_true", help="Warnings/errors only")
    return p


def main(argv: list[str] | None = None, session_for=None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.verbose, args.quiet)
    try:
        ou_ids = core.parse_ou_ids(args.ou or [os.getenv("OU_VPCS_OU", "")])
        regions = core.parse_regions(args.regions or [os.getenv("OU_VPCS_REGIONS", "")])
        overrides = core.parse_account_profiles(args.account_profile)
    except ValueError as e:
        log.error("%s", e)
        return 2
    session_for = session_for or (lambda profile: boto3.Session(profile_name=profile))

    try:
        org = session_for(args.profile).client("organizations", region_name="us-east-1", config=core.BOTO_CONFIG)
        accounts = core.accounts_in_ous(org, ou_ids, recurse=not args.no_recurse)
    except ValueError as e:
        log.error("%s", e)
        return 2
    except (ClientError, BotoCoreError) as e:
        log.error("Organizations (profile %s): %s", args.profile or "default", core._error(e))
        return 1

    scan = core.scan_accounts(accounts, regions, session_for, overrides, preferred=args.profile)

    if not args.no_cache:
        cache = VpcOwnerCache(Path(args.cache).expanduser() if args.cache else default_path())
        changed = core.store(cache, scan.rows)
        log.info("VPC owner map: %d entr%s added or updated", changed, "y" if changed == 1 else "ies")
        cache.save()

    render(scan.rows, COLUMNS, args.output)
    scanned = len(accounts) - sum(1 for r in scan.skipped if not r.region)
    log.info("%d VPC(s) in %d of %d account(s), Region(s): %s", len(scan.rows), scanned, len(accounts), ", ".join(regions))
    if scan.skipped:
        log.warning("Incomplete: %d account/Region(s) skipped (see warnings above)", len(scan.skipped))
        return SKIPPED_EXIT
    return 0


if __name__ == "__main__":
    sys.exit(main())
