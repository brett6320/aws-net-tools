#!/usr/bin/env python3
"""Review Route 53 private hosted zones and their VPC associations (read-only).

Subcommands:
  zones    List PHZs in the PHZ account with their associated VPCs
  by-vpc   Which PHZs (any owner account) are associated with the given VPC(s)
  by-zone  Which VPCs are associated with (or authorized for) the given PHZ(s)
"""
from __future__ import annotations

import argparse
import logging
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

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
from lib.route53_helpers import list_authorizations, load_tags, load_vpcs, select_zones, zones_by_vpc  # noqa: E402

log = logging.getLogger("phz_review")


def add_zone_selectors(p: argparse.ArgumentParser) -> None:
    p.add_argument("--zone", action="append", default=[], metavar="ID|ARN", help="Hosted zone ID/ARN (repeatable)")
    p.add_argument("--zone-name", action="append", default=[], metavar="GLOB", help="Zone name glob, e.g. '*.amazonaws.com'")
    p.add_argument("--zone-tag", action="append", metavar="KEY[=V1,V2]", help="Zone tag include filter (repeat to AND)")
    p.add_argument("--exclude-zone-tag", action="append", metavar="KEY[=V1,V2]", help="Zone tag exclude filter")


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


def cmd_zones(args: argparse.Namespace, ctx: AccountContext) -> list[dict[str, Any]]:
    sessions = ctx.phz_sessions()
    route53 = sessions.client("route53", ctx.phz_account)
    log.info("Listing hosted zones in account %s", ctx.phz_account or sessions.caller_account)
    zones = select_zones(
        route53, args.zone, args.zone_name, parse_tag_filters(args.zone_tag), parse_tag_filters(args.exclude_zone_tag),
        include_public=args.include_public, require_selector=False,
    )
    if args.wide and zones:
        load_tags(route53, [z for z in zones if not z.tags])
    rows = []
    for z in sorted(zones, key=lambda z: z.name):
        if z.private and not z.vpcs:
            load_vpcs(route53, z)
        if args.authorizations and z.private:
            z.authorizations = list_authorizations(route53, z.zone_id)
        rows.append(
            {
                "zone_id": z.zone_id,
                "name": z.name,
                "private": z.private,
                "records": z.record_count,
                "vpc_count": len(z.vpcs),
                "vpcs": [f"{r}/{v}" for r, v in sorted(z.vpcs)],
                "pending_authorizations": [f"{r}/{v}" for r, v in sorted(z.authorizations)],
                "comment": z.comment,
                "tags": z.tags,
            }
        )
    return rows


def cmd_by_vpc(args: argparse.Namespace, ctx: AccountContext) -> list[dict[str, Any]]:
    sessions = ctx.vpc_sessions()
    refs = parse_vpc_refs(args.vpc, args.vpc_region or args.region, ctx.vpc_account)
    rows = []
    for ref in refs:
        log.info("Listing PHZs associated with %s", ref)
        route53 = sessions.client("route53", ref.account)
        for z in zones_by_vpc(route53, ref.vpc_id, ref.region):
            rows.append(
                {
                    "vpc_id": ref.vpc_id,
                    "vpc_region": ref.region,
                    "vpc_account": ref.account or sessions.caller_account,
                    **z,
                    "cross_account": bool(z["zone_owner"].isdigit() and z["zone_owner"] != (ref.account or sessions.caller_account)),
                }
            )
    return sorted(rows, key=lambda r: (r["vpc_id"], r["zone_name"]))


def cmd_by_zone(args: argparse.Namespace, ctx: AccountContext) -> list[dict[str, Any]]:
    sessions = ctx.phz_sessions()
    route53 = sessions.client("route53", ctx.phz_account)
    zones = select_zones(
        route53, args.zone, args.zone_name, parse_tag_filters(args.zone_tag), parse_tag_filters(args.exclude_zone_tag)
    )
    rows = []
    for z in sorted(zones, key=lambda z: z.name):
        if not z.private:
            log.warning("Skipping public zone %s (%s)", z.zone_id, z.name)
            continue
        if not z.vpcs:
            load_vpcs(route53, z)
        for region, vpc_id in sorted(z.vpcs):
            rows.append({"zone_id": z.zone_id, "zone_name": z.name, "vpc_id": vpc_id, "vpc_region": region, "status": "associated"})
        if not args.no_authorizations:
            for region, vpc_id in sorted(list_authorizations(route53, z.zone_id)):
                status = "authorized" if (region, vpc_id) in z.vpcs else "authorized-pending"
                rows.append({"zone_id": z.zone_id, "zone_name": z.name, "vpc_id": vpc_id, "vpc_region": region, "status": status})
    if args.resolve_owners and rows:
        owners = resolve_vpc_owners(ctx, {(r["vpc_region"], r["vpc_id"]) for r in rows})
        for r in rows:
            r["vpc_owner"] = owners.get(r["vpc_id"], "external/unknown")
    return rows


def build_parser() -> argparse.ArgumentParser:
    parent = argparse.ArgumentParser(add_help=False)
    add_common_args(parent)
    add_account_args(parent)
    add_output_args(parent)

    p = argparse.ArgumentParser(description="Review Route 53 private hosted zones and VPC associations (read-only).")
    sub = p.add_subparsers(dest="command", required=True)

    z = sub.add_parser("zones", parents=[parent], help="List PHZs in the PHZ account with associated VPCs")
    add_zone_selectors(z)
    z.add_argument("--include-public", action="store_true", help="Include public hosted zones")
    z.add_argument("--authorizations", action="store_true", help="Also list pending cross-account association authorizations")
    z.add_argument("--wide", action="store_true", help="Show VPC list, comment and tags in table output")

    v = sub.add_parser("by-vpc", parents=[parent], help="PHZs associated with VPC(s); queried from the VPC owner account")
    v.add_argument("--vpc", action="append", required=True, metavar="ID|ARN", help="VPC ID or ARN (repeatable / comma-separated)")
    v.add_argument("--vpc-region", help="Region for VPC IDs given without an ARN (default: --region)")

    b = sub.add_parser("by-zone", parents=[parent], help="VPCs associated with / authorized for PHZ(s)")
    add_zone_selectors(b)
    b.add_argument("--no-authorizations", action="store_true", help="Skip listing association authorizations")
    b.add_argument("--resolve-owners", action="store_true", help="Look up VPC owner accounts (own/RAM-shared VPCs only)")
    return p


COLUMNS = {
    "zones": ["zone_id", "name", "private", "records", "vpc_count"],
    "zones_wide": ["zone_id", "name", "private", "records", "vpc_count", "vpcs", "comment", "tags"],
    "by-vpc": ["vpc_id", "vpc_region", "vpc_account", "zone_id", "zone_name", "zone_owner", "cross_account"],
    "by-zone": ["zone_id", "zone_name", "vpc_id", "vpc_region", "status"],
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.verbose, args.quiet)
    handlers = {"zones": cmd_zones, "by-vpc": cmd_by_vpc, "by-zone": cmd_by_zone}
    try:
        ctx = AccountContext.from_args(args)
        rows = handlers[args.command](args, ctx)
    except (ValueError, LookupError, PermissionError) as e:
        log.error("%s", e)
        return 2
    except ClientError as e:
        log_client_error(e)
        return 1

    if args.command == "zones":
        cols = COLUMNS["zones_wide"] if args.wide else COLUMNS["zones"]
        if args.authorizations:
            cols = cols + ["pending_authorizations"]
    else:
        cols = COLUMNS[args.command]
        if args.command == "by-zone" and args.resolve_owners:
            cols = cols + ["vpc_owner"]
    render(rows, cols, args.output)
    log.info("%d row(s)", len(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
