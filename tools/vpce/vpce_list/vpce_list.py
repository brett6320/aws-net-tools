#!/usr/bin/env python3
"""Enumerate VPC endpoints (centralized or otherwise) with tag, service, VPC and type filters.

Read-only. Optionally correlates interface endpoints with private hosted zones whose
names match the endpoint service's private DNS name (the usual centralized-endpoint
pattern: private DNS disabled on the hub endpoint, PHZ per service shared to spokes).
"""
from __future__ import annotations

import argparse
import fnmatch
import logging
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterator

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib.aws_common import (  # noqa: E402
    AccountContext,
    AccountSessions,
    ClientError,
    TagFilter,
    add_account_args,
    add_common_args,
    add_output_args,
    configure_logging,
    log_client_error,
    parse_tag_filters,
    parse_vpc_refs,
    render,
    split_csv,
    tags_match,
    tags_to_dict,
    zone_name,
)

log = logging.getLogger("vpce_list")

BASE_COLUMNS = ["id", "name", "type", "service", "vpc_id", "state", "private_dns", "region"]
WIDE_COLUMNS = ["owner", "subnets", "dns_name", "tags"]


def service_matches(service: str, patterns: list[str]) -> bool:
    """Glob match; a bare pattern (no wildcard) matches the full name or its last dotted segments."""
    for p in patterns:
        if any(ch in p for ch in "*?["):
            if fnmatch.fnmatchcase(service, p):
                return True
        elif service == p or service.endswith("." + p):
            return True
    return False


def iter_endpoints(
    ec2, vpc_ids: list[str], include: list[TagFilter], types: list[str], states: list[str]
) -> Iterator[dict[str, Any]]:
    filters: list[dict[str, Any]] = [f.to_ec2_filter() for f in include]
    if vpc_ids:
        filters.append({"Name": "vpc-id", "Values": vpc_ids})
    if types:
        filters.append({"Name": "vpc-endpoint-type", "Values": types})
    if states:
        filters.append({"Name": "vpc-endpoint-state", "Values": states})
    log.debug("describe_vpc_endpoints filters=%s", filters)
    params = {"Filters": filters} if filters else {}
    for page in ec2.get_paginator("describe_vpc_endpoints").paginate(**params):
        yield from page.get("VpcEndpoints", [])


def to_row(ep: dict[str, Any], region: str) -> dict[str, Any]:
    tags = tags_to_dict(ep.get("Tags"))
    dns = ep.get("DnsEntries") or []
    return {
        "id": ep["VpcEndpointId"],
        "name": tags.get("Name", ""),
        "type": ep.get("VpcEndpointType"),
        "service": ep.get("ServiceName"),
        "vpc_id": ep.get("VpcId"),
        "state": ep.get("State"),
        "private_dns": ep.get("PrivateDnsEnabled", False),
        "region": region,
        "owner": ep.get("OwnerId"),
        "subnets": ep.get("SubnetIds", []),
        "dns_name": dns[0]["DnsName"] if dns else "",
        "tags": tags,
    }


def service_private_dns(ec2, services: set[str]) -> dict[str, list[str]]:
    """Map service name -> private DNS names (wildcard prefix stripped)."""
    out: dict[str, list[str]] = {}

    def collect(details: list[dict[str, Any]]) -> None:
        for d in details:
            names = [n["PrivateDnsName"] for n in d.get("PrivateDnsNames", []) if n.get("PrivateDnsName")]
            if not names and d.get("PrivateDnsName"):
                names = [d["PrivateDnsName"]]
            out[d["ServiceName"]] = sorted({zone_name(n.removeprefix("*.")) for n in names})

    names = sorted(services)
    for i in range(0, len(names), 50):
        chunk = names[i : i + 50]
        try:
            collect(ec2.describe_vpc_endpoint_services(ServiceNames=chunk).get("ServiceDetails", []))
        except ClientError:
            # One bad/inaccessible name fails the whole batch; retry individually.
            for name in chunk:
                try:
                    collect(ec2.describe_vpc_endpoint_services(ServiceNames=[name]).get("ServiceDetails", []))
                except ClientError as e:
                    log.debug("Cannot describe service %s: %s", name, e.response["Error"]["Code"])
    return out


def private_zones(route53) -> list[dict[str, Any]]:
    zones = []
    for page in route53.get_paginator("list_hosted_zones").paginate():
        for z in page["HostedZones"]:
            if z.get("Config", {}).get("PrivateZone"):
                zones.append(z)
    return zones


def attach_phz(rows: list[dict[str, Any]], vpc_side: AccountSessions, phz_side: AccountSessions, ctx: AccountContext) -> None:
    route53 = phz_side.client("route53", ctx.phz_account)
    zones = private_zones(route53)
    by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for z in zones:
        by_name[zone_name(z["Name"])].append(z)
    assoc_count: dict[str, int] = {}

    by_region: dict[str, set[str]] = defaultdict(set)
    for r in rows:
        if r["type"] == "Interface":
            by_region[r["region"]].add(r["service"])
    dns_map: dict[str, list[str]] = {}
    for region, services in by_region.items():
        dns_map.update(service_private_dns(vpc_side.client("ec2", ctx.vpc_account, region), services))

    for r in rows:
        matches = []
        for dns in dns_map.get(r["service"], []):
            for zname, zs in by_name.items():
                if dns == zname or dns.endswith("." + zname):
                    matches.extend(zs)
        labels = []
        for z in {z["Id"]: z for z in matches}.values():
            zid = z["Id"].rsplit("/", 1)[-1]
            if zid not in assoc_count:
                assoc_count[zid] = len(route53.get_hosted_zone(Id=zid).get("VPCs", []))
            labels.append(f"{zid}:{zone_name(z['Name'])}({assoc_count[zid]} vpc)")
        r["service_dns"] = dns_map.get(r["service"], [])
        r["phz"] = labels


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Enumerate VPC endpoints with tag/service/VPC filters (read-only).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    add_common_args(p)
    add_account_args(p)
    add_output_args(p)
    p.add_argument("--regions", help="Comma-separated regions to scan (default: --region)")
    p.add_argument("--tag", action="append", metavar="KEY[=V1,V2]", help="Include filter; repeat to AND. Values OR'd, '*' wildcards OK")
    p.add_argument("--exclude-tag", action="append", metavar="KEY[=V1,V2]", help="Exclude endpoints matching this tag filter")
    p.add_argument("--vpc", action="append", metavar="ID|ARN", help="Limit to VPC(s); ID or ARN, repeat or comma-separate")
    p.add_argument("--service", action="append", metavar="PATTERN", help="Service name glob, or short name e.g. 'ssm' (repeatable)")
    p.add_argument("--type", action="append", metavar="TYPE", help="Interface, Gateway, GatewayLoadBalancer, Resource, ServiceNetwork")
    p.add_argument("--state", action="append", metavar="STATE", help="e.g. available, pending, rejected")
    p.add_argument("--with-phz", action="store_true", help="Correlate interface endpoints with matching PHZs in the PHZ account")
    p.add_argument("--wide", action="store_true", help="Show owner, subnets, DNS name and tags in table/csv output")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.verbose, args.quiet)
    try:
        ctx = AccountContext.from_args(args)
        include = parse_tag_filters(args.tag)
        exclude = parse_tag_filters(args.exclude_tag)
        vpcs = parse_vpc_refs(args.vpc or [], None, ctx.vpc_account)
    except ValueError as e:
        log.error("%s", e)
        return 2

    regions = split_csv(args.regions) if args.regions else [args.region]
    for ref in vpcs:
        if ref.region and ref.region not in regions:
            regions.append(ref.region)
    accounts = {ref.account for ref in vpcs if ref.account}
    if len(accounts) > 1:
        log.error("VPC ARNs span multiple accounts (%s); run once per account", ", ".join(sorted(accounts)))
        return 2
    if accounts:
        ctx.vpc_account = accounts.pop()

    rows: list[dict[str, Any]] = []
    try:
        vpc_side = ctx.vpc_sessions()
        for region in regions:
            region_vpcs = [r.vpc_id for r in vpcs if r.region in (None, region)]
            if vpcs and not region_vpcs:
                continue
            log.info("Scanning VPC endpoints in account=%s region=%s", ctx.vpc_account or vpc_side.caller_account, region)
            ec2 = vpc_side.client("ec2", ctx.vpc_account, region)
            for ep in iter_endpoints(ec2, region_vpcs, include, args.type or [], args.state or []):
                row = to_row(ep, region)
                if args.service and not service_matches(row["service"], args.service):
                    continue
                if not tags_match(row["tags"], include, exclude):
                    continue
                rows.append(row)
        if args.with_phz and rows:
            attach_phz(rows, vpc_side, ctx.phz_sessions(), ctx)
    except ClientError as e:
        log_client_error(e)
        return 1
    except (PermissionError, ValueError) as e:
        log.error("%s", e)
        return 1

    rows.sort(key=lambda r: (r["region"], r["vpc_id"] or "", r["service"] or "", r["id"]))
    columns = BASE_COLUMNS + (WIDE_COLUMNS if args.wide else []) + (["service_dns", "phz"] if args.with_phz else [])
    render(rows, columns, args.output)
    log.info("%d endpoint(s) matched", len(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
