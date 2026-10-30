#!/usr/bin/env python3
"""Review Route 53 private hosted zones and their VPC associations (read-only).

Subcommands:
  zones    List PHZs in the PHZ account with their associated VPCs
  by-vpc   Which PHZs (any owner account) are associated with the given VPC(s)
  by-zone  Which VPCs are associated with (or authorized for) the given PHZ(s)

Every subcommand can also write an interactive HTML report (``-o html``) with
sortable / filterable tables and a planner that prepares the AWS CLI commands to
move VPCs to a different PHZ, including cross-account authorizations.
"""
from __future__ import annotations

import argparse
import datetime as dt
import logging
import os
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from lib.aws_common import (  # noqa: E402
    AccountContext,
    ClientError,
    add_account_args,
    add_common_args,
    add_output_args,
    configure_logging,
    log_client_error,
    parse_tag_filters,
    parse_vpc_refs,
    render,
)
from lib.route53_helpers import Zone, list_authorizations, load_tags, load_vpcs, select_zones, zones_by_vpc  # noqa: E402
from phz_html import render_html  # noqa: E402

log = logging.getLogger("phz_review")

UNKNOWN = "unknown"


@dataclass
class Review:
    """Rows for table/json/csv output plus the zone/association model behind the HTML report."""

    rows: list[dict[str, Any]]
    zones: list[dict[str, Any]] = field(default_factory=list)
    associations: list[dict[str, Any]] = field(default_factory=list)
    scope: str = ""  # account the report is filed under
    notes: list[str] = field(default_factory=list)


def add_zone_selectors(p: argparse.ArgumentParser) -> None:
    p.add_argument("--zone", action="append", default=[], metavar="ID|ARN", help="Hosted zone ID/ARN (repeatable)")
    p.add_argument("--zone-name", action="append", default=[], metavar="GLOB", help="Zone name glob, e.g. '*.amazonaws.com'")
    p.add_argument("--zone-tag", action="append", metavar="KEY[=V1,V2]", help="Zone tag include filter (repeat to AND)")
    p.add_argument("--exclude-zone-tag", action="append", metavar="KEY[=V1,V2]", help="Zone tag exclude filter")


def add_owner_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--no-resolve-owners", action="store_true",
                   help="Don't look up VPC owner accounts (shown as 'unknown')")
    p.add_argument("--resolve-owners", action="store_true", help=argparse.SUPPRESS)  # now the default; kept for old scripts


def resolve_vpc_owners(ctx: AccountContext, pairs: set[tuple[str, str]]) -> dict[str, str]:
    """Best-effort VPC owner lookup from the PHZ account (sees own + RAM-shared VPCs only)."""
    sessions = ctx.phz_sessions()
    by_region: dict[str, list[str]] = defaultdict(list)
    for region, vpc_id in pairs:
        by_region[region].append(vpc_id)
    owners: dict[str, str] = {}
    for region, ids in by_region.items():
        ec2 = sessions.client("ec2", ctx.phz_account, region)
        for i in range(0, len(ids), 200):
            for page in ec2.get_paginator("describe_vpcs").paginate(Filters=[{"Name": "vpc-id", "Values": ids[i : i + 200]}]):
                for v in page["Vpcs"]:
                    owners[v["VpcId"]] = v["OwnerId"]
    return owners


def cross_account(zone_owner: str, vpc_owner: str) -> bool | None:
    if not zone_owner.isdigit() or not vpc_owner.isdigit():
        return None
    return zone_owner != vpc_owner


def zone_record(z: Zone, owner: str) -> dict[str, Any]:
    return {
        "zone_id": z.zone_id, "name": z.name, "owner": owner, "private": z.private, "records": z.record_count,
        "vpc_count": len(z.vpcs), "comment": z.comment, "tags": z.tags,
    }


def zone_associations(z: Zone, owner: str, owners: dict[str, str], authorizations: list[tuple[str, str]] | None) -> list[dict[str, Any]]:
    """One row per associated VPC, then one per authorization (stale if the VPC is already associated)."""
    def row(region: str, vpc_id: str, status: str) -> dict[str, Any]:
        vpc_owner = owners.get(vpc_id, UNKNOWN)
        return {
            "zone_id": z.zone_id, "zone_name": z.name, "zone_owner": owner, "vpc_id": vpc_id, "vpc_region": region,
            "vpc_owner": vpc_owner, "cross_account": cross_account(owner, vpc_owner), "status": status,
        }

    rows = [row(r, v, "associated") for r, v in sorted(z.vpcs)]
    for r, v in sorted(authorizations or []):
        rows.append(row(r, v, "authorized" if (r, v) in z.vpcs else "authorized-pending"))
    return rows


def lookup_owners(args: argparse.Namespace, ctx: AccountContext, zones: list[Zone], auths: dict[str, list[tuple[str, str]]]) -> dict[str, str]:
    if args.no_resolve_owners:
        return {}
    pairs = {p for z in zones for p in z.vpcs} | {p for a in auths.values() for p in a}
    return resolve_vpc_owners(ctx, pairs) if pairs else {}


def cmd_zones(args: argparse.Namespace, ctx: AccountContext) -> Review:
    sessions = ctx.phz_sessions()
    route53 = sessions.client("route53", ctx.phz_account)
    account = ctx.phz_account or sessions.caller_account
    log.info("Listing hosted zones in account %s", account)
    zones = select_zones(
        route53, args.zone, args.zone_name, parse_tag_filters(args.zone_tag), parse_tag_filters(args.exclude_zone_tag),
        include_public=args.include_public, require_selector=False,
    )
    html = args.output == "html"
    if (args.wide or html) and zones:
        load_tags(route53, [z for z in zones if not z.tags])
    zones = sorted(zones, key=lambda z: z.name)
    auths: dict[str, list[tuple[str, str]]] = {}
    for z in zones:
        if z.private and not z.vpcs:
            load_vpcs(route53, z)
        if (args.authorizations or html) and z.private:
            auths[z.zone_id] = z.authorizations = list_authorizations(route53, z.zone_id)
    owners = lookup_owners(args, ctx, zones, auths)

    rows = []
    for z in zones:
        rows.append(
            {
                "zone_id": z.zone_id,
                "name": z.name,
                "account": account,
                "private": z.private,
                "records": z.record_count,
                "vpc_count": len(z.vpcs),
                "vpcs": [f"{r}/{v}" for r, v in sorted(z.vpcs)],
                "vpc_owners": {v: owners.get(v, UNKNOWN) for _, v in sorted(z.vpcs)},
                "pending_authorizations": [f"{r}/{v}" for r, v in sorted(z.authorizations)],
                "comment": z.comment,
                "tags": z.tags,
            }
        )
    private = [z for z in zones if z.private]
    return Review(
        rows,
        zones=[zone_record(z, account) for z in private],
        associations=[a for z in private for a in zone_associations(z, account, owners, auths.get(z.zone_id))],
        scope=account,
    )


def cmd_by_vpc(args: argparse.Namespace, ctx: AccountContext) -> Review:
    sessions = ctx.vpc_sessions()
    refs = parse_vpc_refs(args.vpc, args.vpc_region or args.region, ctx.vpc_account)
    rows = []
    for ref in refs:
        log.info("Listing PHZs associated with %s", ref)
        route53 = sessions.client("route53", ref.account)
        vpc_account = ref.account or sessions.caller_account
        for z in zones_by_vpc(route53, ref.vpc_id, ref.region):
            rows.append(
                {
                    "vpc_id": ref.vpc_id,
                    "vpc_region": ref.region,
                    "vpc_account": vpc_account,
                    **z,
                    "cross_account": bool(z["zone_owner"].isdigit() and z["zone_owner"] != vpc_account),
                }
            )
    rows.sort(key=lambda r: (r["vpc_id"], r["zone_name"]))

    zones: dict[str, dict[str, Any]] = {}
    for r in rows:
        zones.setdefault(r["zone_id"], {
            "zone_id": r["zone_id"], "name": r["zone_name"], "owner": r["zone_owner"], "private": True,
            "records": None, "vpc_count": None, "comment": "", "tags": {},
        })
    associations = [
        {
            "zone_id": r["zone_id"], "zone_name": r["zone_name"], "zone_owner": r["zone_owner"], "vpc_id": r["vpc_id"],
            "vpc_region": r["vpc_region"], "vpc_owner": r["vpc_account"],
            "cross_account": cross_account(r["zone_owner"], r["vpc_account"]), "status": "associated",
        }
        for r in rows
    ]
    accounts = sorted({r["vpc_account"] for r in rows} or {ref.account or sessions.caller_account for ref in refs})
    return Review(
        rows, zones=sorted(zones.values(), key=lambda z: z["name"]), associations=associations,
        scope=accounts[0] if len(accounts) == 1 else "multi-account",
        notes=[
            "Built from the VPC side (ListHostedZonesByVPC): each zone shows only the VPCs given with --vpc, and "
            "authorizations are not visible. The planner can't check whether a disassociation would remove a "
            "zone's last VPC; run by-zone in the PHZ account for that.",
        ],
    )


def cmd_by_zone(args: argparse.Namespace, ctx: AccountContext) -> Review:
    sessions = ctx.phz_sessions()
    route53 = sessions.client("route53", ctx.phz_account)
    account = ctx.phz_account or sessions.caller_account
    zones = select_zones(
        route53, args.zone, args.zone_name, parse_tag_filters(args.zone_tag), parse_tag_filters(args.exclude_zone_tag)
    )
    private = []
    for z in sorted(zones, key=lambda z: z.name):
        if not z.private:
            log.warning("Skipping public zone %s (%s)", z.zone_id, z.name)
            continue
        if not z.vpcs:
            load_vpcs(route53, z)
        private.append(z)
    if args.output == "html" and private:
        load_tags(route53, [z for z in private if not z.tags])
    auths = {} if args.no_authorizations else {z.zone_id: list_authorizations(route53, z.zone_id) for z in private}
    owners = lookup_owners(args, ctx, private, auths)
    associations = [a for z in private for a in zone_associations(z, account, owners, auths.get(z.zone_id))]
    return Review(
        associations, zones=[zone_record(z, account) for z in private], associations=associations, scope=account,
        notes=["Authorizations were not listed (--no-authorizations)."] if args.no_authorizations else [],
    )


def build_parser() -> argparse.ArgumentParser:
    parent = argparse.ArgumentParser(add_help=False)
    add_common_args(parent)
    add_account_args(parent)
    add_output_args(parent, extra=("html",))
    parent.add_argument("--out", metavar="FILE", help="html: write the report here instead of the reports directory")
    parent.add_argument("--reports-dir", default=os.getenv("VPCE_REPORTS_DIR", "reports"), metavar="DIR",
                        help="html: reports go to DIR/<YYYY-MM-DD>/<account>/ (default: ./reports)")

    p = argparse.ArgumentParser(description="Review Route 53 private hosted zones and VPC associations (read-only).")
    sub = p.add_subparsers(dest="command", required=True)

    z = sub.add_parser("zones", parents=[parent], help="List PHZs in the PHZ account with associated VPCs")
    add_zone_selectors(z)
    z.add_argument("--include-public", action="store_true", help="Include public hosted zones")
    z.add_argument("--authorizations", action="store_true", help="Also list pending cross-account association authorizations (always on for html)")
    z.add_argument("--wide", action="store_true", help="Show VPC list, VPC owners, comment and tags in table output")
    add_owner_args(z)

    v = sub.add_parser("by-vpc", parents=[parent], help="PHZs associated with VPC(s); queried from the VPC owner account")
    v.add_argument("--vpc", action="append", required=True, metavar="ID|ARN", help="VPC ID or ARN (repeatable / comma-separated)")
    v.add_argument("--vpc-region", help="Region for VPC IDs given without an ARN (default: --region)")

    b = sub.add_parser("by-zone", parents=[parent], help="VPCs associated with / authorized for PHZ(s)")
    add_zone_selectors(b)
    b.add_argument("--no-authorizations", action="store_true", help="Skip listing association authorizations")
    add_owner_args(b)
    return p


COLUMNS = {
    "zones": ["zone_id", "name", "account", "private", "records", "vpc_count"],
    "zones_wide": ["zone_id", "name", "account", "private", "records", "vpc_count", "vpcs", "vpc_owners", "comment", "tags"],
    "by-vpc": ["vpc_id", "vpc_region", "vpc_account", "zone_id", "zone_name", "zone_owner", "cross_account"],
    "by-zone": ["zone_id", "zone_name", "zone_owner", "vpc_id", "vpc_region", "vpc_owner", "cross_account", "status"],
}


def report_path(review: Review, command: str, reports_dir: str) -> Path:
    day = dt.date.today().isoformat()
    return Path(reports_dir) / day / (review.scope or "unknown") / f"phz-review_{command}.html"


def write_html(review: Review, args: argparse.Namespace) -> Path:
    data = {
        "command": args.command,
        "generated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "scope": review.scope,
        "zones": review.zones,
        "associations": review.associations,
        "authorizations_listed": args.command == "zones" or (args.command == "by-zone" and not args.no_authorizations),
        "vpc_counts_complete": args.command != "by-vpc",
        "notes": review.notes,
    }
    path = Path(args.out) if args.out else report_path(review, args.command, args.reports_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(data), encoding="utf-8")
    return path


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.verbose, args.quiet)
    handlers = {"zones": cmd_zones, "by-vpc": cmd_by_vpc, "by-zone": cmd_by_zone}
    try:
        ctx = AccountContext.from_args(args)
        review = handlers[args.command](args, ctx)
    except (ValueError, LookupError, PermissionError) as e:
        log.error("%s", e)
        return 2
    except ClientError as e:
        log_client_error(e)
        return 1

    if args.output == "html":
        path = write_html(review, args)
        log.info("%d zone(s), %d association row(s)", len(review.zones), len(review.associations))
        print(path)
        return 0

    if args.command == "zones":
        cols = COLUMNS["zones_wide"] if args.wide else COLUMNS["zones"]
        if args.authorizations:
            cols = cols + ["pending_authorizations"]
    else:
        cols = COLUMNS[args.command]
    render(review.rows, cols, args.output)
    log.info("%d row(s)", len(review.rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
