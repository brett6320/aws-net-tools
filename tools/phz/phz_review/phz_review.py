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
from typing import Any, Callable, Iterable

from botocore.exceptions import BotoCoreError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from lib.aws_common import (  # noqa: E402
    AccountContext,
    AccountSessions,
    ClientError,
    add_account_args,
    add_common_args,
    add_output_args,
    configure_logging,
    log_client_error,
    parse_tag_filters,
    parse_vpc_refs,
    render,
    validate_account,
)
from lib.aws_profiles import exclude_suffixes, profile_accounts  # noqa: E402
from lib.vpc_owner_cache import VpcOwnerCache, default_path  # noqa: E402
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
    p.add_argument("--owner-accounts", metavar="ACCT[,ACCT]|org", default=os.getenv("VPCE_OWNER_ACCOUNTS"),
                   help="Accounts to search for VPCs the PHZ account can't see (default: every account in your "
                        "local AWS config; 'org' lists the AWS Organization's accounts)")
    p.add_argument("--no-owner-search", action="store_true",
                   help="Don't search other accounts for VPC owners (IPAM and the PHZ account are still used)")
    p.add_argument("--ipam-profile", default=os.getenv("VPCE_IPAM_PROFILE"),
                   help="Profile for the IPAM owner / delegated admin account. VPC owners are then read from IPAM "
                        "in one bulk pull before any per-account lookups")
    p.add_argument("--ipam-region", default=os.getenv("VPCE_IPAM_REGION"), help="IPAM home Region (default: --region)")
    p.add_argument("--ipam-id", default=os.getenv("VPCE_IPAM_ID"), help="IPAM to use when the Region has several")
    p.add_argument("--owner-cache", metavar="FILE", default=os.getenv("VPCE_OWNER_CACHE"),
                   help=f"Local VPC -> owner map; only VPCs missing from it are looked up (default: {default_path()})")
    p.add_argument("--no-owner-cache", action="store_true", help="Don't read or write the local VPC owner map")
    p.add_argument("--refresh-owner-cache", action="store_true",
                   help="Look up every VPC again and update the local map")


ClientFor = Callable[[str, str], Any]  # (account, region) -> ec2 client


def describe_owners(ec2, ids: list[str]) -> dict[str, str]:
    owners: dict[str, str] = {}
    for i in range(0, len(ids), 200):
        for page in ec2.get_paginator("describe_vpcs").paginate(Filters=[{"Name": "vpc-id", "Values": ids[i : i + 200]}]):
            for v in page["Vpcs"]:
                owners[v["VpcId"]] = v["OwnerId"]
    return owners


def find_owners(pairs: set[tuple[str, str]], accounts: Iterable[str], client_for: ClientFor) -> dict[str, str]:
    """Look up each VPC's owner by searching ``accounts`` in order until every VPC is found.

    DescribeVpcs returns a VPC's OwnerId to its owner and to accounts it is shared with, so the
    first account that can see a VPC is enough. Accounts we can't get into are skipped.
    """
    owners: dict[str, str] = {}
    skipped: list[str] = []
    for account in accounts:
        by_region: dict[str, list[str]] = defaultdict(list)
        for region, vpc_id in sorted(pairs):
            if vpc_id not in owners:
                by_region[region].append(vpc_id)
        if not by_region:
            break
        for region, ids in by_region.items():
            try:
                found = describe_owners(client_for(account, region), ids)
            except (ClientError, BotoCoreError, PermissionError, ValueError) as e:
                log.debug("Owner search: skipping account %s: %s", account, e)
                skipped.append(account)
                break
            if found:
                log.info("Owner search: account %s sees %d VPC(s) in %s", account, len(found), region)
            owners.update(found)
    if skipped:
        log.warning("Owner search: couldn't query %d account(s): %s (-v for details)", len(skipped), ", ".join(skipped))
    return owners


def ipam_vpc_owners(ec2, ipam_id: str | None = None) -> dict[tuple[str, str], str]:
    """Every VPC IPAM knows about, (region, vpc_id) -> owner account, from one paginated GetIpamResourceCidrs pull.

    Covers all accounts and Regions the IPAM monitors. A VPC with several CIDRs appears once per CIDR.
    """
    ipams = ec2.describe_ipams(**({"IpamIds": [ipam_id]} if ipam_id else {})).get("Ipams", [])
    if not ipams:
        log.warning("IPAM: none found in this Region; use --ipam-region with the IPAM's home Region")
        return {}
    if len(ipams) > 1:
        raise ValueError(f"Several IPAMs in this Region ({', '.join(i['IpamId'] for i in ipams)}); choose one with --ipam-id")
    scope = ipams[0]["PrivateDefaultScopeId"]
    owners: dict[tuple[str, str], str] = {}
    for page in ec2.get_paginator("get_ipam_resource_cidrs").paginate(
        IpamScopeId=scope, ResourceType="vpc", PaginationConfig={"PageSize": 1000}
    ):
        for r in page.get("IpamResourceCidrs", []):
            if r.get("ResourceId") and r.get("ResourceOwnerId") and r.get("ResourceRegion"):
                owners[(r["ResourceRegion"], r["ResourceId"])] = r["ResourceOwnerId"]
    log.info("IPAM %s: %d VPC(s) across %d account(s)", ipams[0]["IpamId"], len(owners), len(set(owners.values())))
    return owners


def owner_search_accounts(args: argparse.Namespace, ctx: AccountContext) -> list[str]:
    raw = (args.owner_accounts or "").strip()
    if raw.lower() == "org":
        org = ctx.phz_sessions().client("organizations")
        accounts = [a["Id"] for page in org.get_paginator("list_accounts").paginate() for a in page["Accounts"]
                    if a.get("Status", "ACTIVE") == "ACTIVE"]
        log.info("Owner search: %d account(s) in the organization", len(accounts))
        return sorted(accounts)
    if raw:
        return [validate_account(a.strip(), "--owner-accounts") for a in raw.split(",") if a.strip()]
    excluded = exclude_suffixes()
    return sorted({acct for name, acct in profile_accounts().items() if not name.endswith(excluded)})


def owner_cache(args: argparse.Namespace) -> VpcOwnerCache:
    if args.no_owner_cache:
        return VpcOwnerCache(None)
    return VpcOwnerCache(Path(args.owner_cache).expanduser() if args.owner_cache else default_path())


def resolve_vpc_owners(args: argparse.Namespace, ctx: AccountContext, pairs: set[tuple[str, str]],
                       cache: VpcOwnerCache | None = None) -> dict[str, str]:
    """VPC owner accounts. The local map answers first; only VPCs missing from it are looked up,
    cheapest source first, each source asked only about the VPCs still unknown:

    1. IPAM (with --ipam-profile): every monitored VPC in one bulk pull (all of it goes into the map)
    2. DescribeVpcs in the PHZ account (its own and RAM-shared VPCs)
    3. DescribeVpcs in other accounts, one batched call per account and Region, until all are found
    """
    cache = cache if cache is not None else owner_cache(args)
    owners: dict[str, str] = {}
    if not args.refresh_owner_cache:
        for region, vpc in pairs:
            acct = cache.get(region, vpc)
            if acct:
                owners[vpc] = acct
    missing = {p for p in pairs if p[1] not in owners}
    log.info("VPC owners: %d from the local map, %d to look up", len(owners), len(missing))

    if missing and args.ipam_profile:
        try:
            ipam = AccountSessions(args.ipam_profile, args.ipam_region or ctx.region, label="IPAM")
            known = ipam_vpc_owners(ipam.client("ec2"), args.ipam_id)
            for (region, vpc), acct in known.items():
                cache.put(region, vpc, acct, "ipam")
            owners.update({vpc: known[(region, vpc)] for region, vpc in missing if (region, vpc) in known})
        except (ClientError, BotoCoreError) as e:
            log.warning("IPAM lookup failed (%s); falling back to per-account lookups", e)
        missing = {p for p in pairs if p[1] not in owners}

    def remember(found: dict[str, str], source: str) -> None:
        for region, vpc in missing:
            if vpc in found:
                cache.put(region, vpc, found[vpc], source)
        owners.update(found)

    if missing:
        phz = ctx.phz_sessions()
        phz_account = ctx.phz_account or phz.caller_account
        remember(find_owners(missing, [phz_account], lambda a, r: phz.client("ec2", ctx.phz_account, r)), "phz-account")
        missing = {p for p in pairs if p[1] not in owners}
        if missing and not args.no_owner_search:
            accounts = [a for a in owner_search_accounts(args, ctx) if a != phz_account]
            log.info("Owner search: %d VPC(s) not visible from %s; searching %d other account(s)", len(missing), phz_account, len(accounts))
            search = ctx.vpc_sessions()
            remember(find_owners(missing, accounts, lambda a, r: search.client("ec2", a, r)), "account-search")
    cache.save()
    unresolved = len({p[1] for p in pairs} - set(owners))
    if unresolved:
        log.warning("%d VPC owner(s) still unknown; pass --owner-accounts (or --role-name with --owner-accounts org)", unresolved)
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
    return resolve_vpc_owners(args, ctx, pairs) if pairs else {}


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
