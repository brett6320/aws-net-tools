#!/usr/bin/env python3
"""Show who a VPC is shared with through RAM: its owner account and every principal its subnets are shared to (read-only).

Each VPC's owner account and Region come from the VPC owner map that ``ou_vpcs`` writes
(~/.cache/aws-net-tools/vpc-owners.json). The owner account is read with the profile that maps
to its account ID in ~/.aws/config (never one ending in -priv, -adm, -cpar or -ro): its subnets
in the VPC, the RAM resource shares that contain them, and each share's principals. OU and
organization principals are expanded to their accounts with Organizations (``--org-profile``),
or else from the accounts the owner map knows.

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

import vp_core as core  # noqa: E402

load_dotenv()

log = logging.getLogger("vpc_participants")

TABLE_COLUMNS = ("vpc_id", "region", "vpc_name", "role", "principal", "principal_type", "principal_name", "status",
                 "shares", "subnets", "member_count")
FULL_COLUMNS = ("vpc_id", "region", "vpc_name", "owner", "role", "principal", "principal_type", "principal_name",
                "status", "external", "shares", "subnets", "members", "members_source", "error")
ERROR_EXIT = 1


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


def member_count(row: dict[str, Any]) -> str:
    """Accounts an OU or organization principal covers; "?" when they couldn't be found."""
    if row.get("principal_type") not in ("ou", "organization"):
        return ""
    return "?" if row.get("members_source") == "unknown" else str(len(row.get("members") or []))


def render(rows: Sequence[dict[str, Any]], fmt: str, stream=None) -> None:
    stream = stream or sys.stdout
    if fmt == "json":
        json.dump(list(rows), stream, indent=2, default=str)
        stream.write("\n")
        return
    if fmt == "csv":
        w = csv.writer(stream)
        w.writerow(FULL_COLUMNS)
        for r in rows:
            w.writerow([_cell(r.get(c)) for c in FULL_COLUMNS])
        return
    columns = TABLE_COLUMNS + (("error",) if any(r.get("error") for r in rows) else ())
    table = [[_cell(member_count(r) if c == "member_count" else r.get(c)) for c in columns] for r in rows]
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
    env = os.getenv
    p = argparse.ArgumentParser(description="Show a VPC's owner account and the RAM principals its subnets are shared with (read-only).")
    p.add_argument("vpc_ids", nargs="+", metavar="VPC_ID", help="VPC(s) to look up; comma-separate or repeat")
    p.add_argument("--regions", action="append",
                   help="Only look for the VPCs in these Regions (needed when a VPC ID is in the owner map in several); "
                        "repeat or comma-separate")
    p.add_argument("--cache", default=env("VPC_PART_CACHE") or env("OU_VPCS_CACHE"), metavar="FILE",
                   help="VPC owner map written by ou_vpcs (default: ~/.cache/aws-net-tools/vpc-owners.json; "
                        "env VPC_PART_CACHE / OU_VPCS_CACHE)")
    p.add_argument("--profile", default=env("AWS_PROFILE"),
                   help="Preferred profile when several map to the owner account (default: AWS_PROFILE)")
    p.add_argument("--account-profile", action="append", metavar="ACCOUNT=PROFILE",
                   help="Profile to use for an owner account (when several or none map to it); repeat or comma-separate")
    p.add_argument("--org-profile", default=env("VPC_PART_ORG_PROFILE") or env("OU_VPCS_ORG_PROFILE"),
                   help="Profile for Organizations (management or delegated-administrator account): expands OU and "
                        "organization principals to their accounts and names accounts the owner map doesn't know "
                        "(env VPC_PART_ORG_PROFILE / OU_VPCS_ORG_PROFILE; without it, the owner map is used)")
    p.add_argument("--all-statuses", action="store_true",
                   help="Also list principals whose association is disassociated or failed, and shares that aren't active")
    p.add_argument("--output", "-o", choices=("table", "json", "csv"), default="table", help="Output format (default: table)")
    p.add_argument("--json", dest="output", action="store_const", const="json", help="Shortcut for --output json")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    p.add_argument("-q", "--quiet", action="store_true", help="Warnings/errors only")
    return p


def main(argv: list[str] | None = None, session_for=None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.verbose, args.quiet)
    cache = Path(args.cache).expanduser() if args.cache else core.default_cache_path()
    try:
        overrides = core.parse_account_profiles(args.account_profile)
        catalog = core.load_vpcs(cache)
        vpcs = core.find_vpcs(catalog, core.split_csv(args.vpc_ids), core.split_csv(args.regions))
    except (ValueError, FileNotFoundError) as e:
        log.error("%s", e)
        return 2
    session_for = session_for or (lambda profile: boto3.Session(profile_name=profile))

    org = None
    if args.org_profile:
        try:
            org = session_for(args.org_profile).client("organizations", region_name="us-east-1", config=core.BOTO_CONFIG)
        except (ClientError, BotoCoreError) as e:
            log.warning("Organizations (profile %s): %s; using the VPC owner map", args.org_profile, core._error(e))

    results = core.read_sharing(vpcs, session_for, overrides, preferred=args.profile)
    rows = core.build_rows(results, core.Directory.from_catalog(catalog, org), include_inactive=args.all_statuses)
    render(rows, args.output)

    participants = [r for r in rows if r["role"] == "participant"]
    log.info("%d VPC(s): %d principal(s) across %d account(s) owning them", len(vpcs), len(participants),
             len({v.account for v in vpcs}))
    if any(r.get("members_source") == "catalog" for r in participants):
        log.info("OU / organization members come from the VPC owner map, which only knows accounts that own VPCs; "
                 "pass --org-profile for the full list")
    if failed := [r for r in results if r.error]:
        log.warning("Incomplete: %d VPC(s) couldn't be read (see warnings above)", len(failed))
        return ERROR_EXIT
    return 0


if __name__ == "__main__":
    sys.exit(main())
