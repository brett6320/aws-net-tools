"""Route 53 private hosted zone helpers shared by phz_review and phz_assoc."""
from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass, field
from typing import Any, Iterator, Sequence

from lib.aws_common import ClientError, TagFilter, normalize_zone_id, tags_match, tags_to_dict, zone_name

log = logging.getLogger("aws_vpce_tools.route53")


@dataclass
class Zone:
    zone_id: str
    name: str
    private: bool
    record_count: int = 0
    comment: str = ""
    vpcs: list[tuple[str, str]] = field(default_factory=list)  # (region, vpc_id)
    tags: dict[str, str] = field(default_factory=dict)
    authorizations: list[tuple[str, str]] = field(default_factory=list)  # (region, vpc_id)


def iter_zones(route53, include_public: bool = False) -> Iterator[Zone]:
    for page in route53.get_paginator("list_hosted_zones").paginate():
        for z in page["HostedZones"]:
            private = bool(z.get("Config", {}).get("PrivateZone"))
            if private or include_public:
                yield Zone(
                    zone_id=normalize_zone_id(z["Id"]),
                    name=zone_name(z["Name"]),
                    private=private,
                    record_count=z.get("ResourceRecordSetCount", 0),
                    comment=z.get("Config", {}).get("Comment", "") or "",
                )


def load_tags(route53, zones: Sequence[Zone]) -> None:
    for i in range(0, len(zones), 10):
        chunk = zones[i : i + 10]
        resp = route53.list_tags_for_resources(ResourceType="hostedzone", ResourceIds=[z.zone_id for z in chunk])
        by_id = {t["ResourceId"]: tags_to_dict(t.get("Tags")) for t in resp.get("ResourceTagSets", [])}
        for z in chunk:
            z.tags = by_id.get(z.zone_id, {})


def get_zone(route53, zone_id: str) -> Zone:
    resp = route53.get_hosted_zone(Id=zone_id)
    hz = resp["HostedZone"]
    return Zone(
        zone_id=normalize_zone_id(hz["Id"]),
        name=zone_name(hz["Name"]),
        private=bool(hz.get("Config", {}).get("PrivateZone")),
        record_count=hz.get("ResourceRecordSetCount", 0),
        comment=hz.get("Config", {}).get("Comment", "") or "",
        vpcs=[(v["VPCRegion"], v["VPCId"]) for v in resp.get("VPCs", [])],
    )


def load_vpcs(route53, zone: Zone) -> None:
    zone.vpcs = get_zone(route53, zone.zone_id).vpcs


def list_authorizations(route53, zone_id: str) -> list[tuple[str, str]]:
    """Pending cross-account VPC association authorizations created by this zone's owner."""
    out: list[tuple[str, str]] = []
    params: dict[str, Any] = {"HostedZoneId": zone_id}
    while True:
        resp = route53.list_vpc_association_authorizations(**params)
        out.extend((v["VPCRegion"], v["VPCId"]) for v in resp.get("VPCs", []))
        token = resp.get("NextToken")
        if not token:
            return out
        params["NextToken"] = token


def zones_by_vpc(route53, vpc_id: str, region: str) -> list[dict[str, Any]]:
    """All PHZs associated with a VPC regardless of owning account. Must be called from the VPC owner account."""
    out: list[dict[str, Any]] = []
    params: dict[str, Any] = {"VPCId": vpc_id, "VPCRegion": region, "MaxItems": "100"}
    while True:
        resp = route53.list_hosted_zones_by_vpc(**params)
        for s in resp.get("HostedZoneSummaries", []):
            owner = s.get("Owner", {})
            out.append(
                {
                    "zone_id": normalize_zone_id(s["HostedZoneId"]),
                    "zone_name": zone_name(s["Name"]),
                    "zone_owner": owner.get("OwningAccount") or owner.get("OwningService", ""),
                }
            )
        token = resp.get("NextToken")
        if not token:
            return out
        params["NextToken"] = token


def select_zones(
    route53,
    zone_ids: Sequence[str] = (),
    name_patterns: Sequence[str] = (),
    include: Sequence[TagFilter] = (),
    exclude: Sequence[TagFilter] = (),
    include_public: bool = False,
    require_selector: bool = True,
) -> list[Zone]:
    """Resolve zones by explicit ID, name glob, and/or tag filters.

    Explicit IDs are always fetched directly (they may be referenced even if a name/tag
    filter wouldn't match). Name globs / tag filters select from the account's zones.
    """
    selected: dict[str, Zone] = {}
    for zid in zone_ids:
        try:
            z = get_zone(route53, normalize_zone_id(zid))
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchHostedZone":
                raise LookupError(f"Hosted zone {zid} not found in this account") from e
            raise
        selected[z.zone_id] = z

    if name_patterns or include or exclude or (not zone_ids and not require_selector):
        candidates = list(iter_zones(route53, include_public))
        if name_patterns:
            pats = [zone_name(p) for p in name_patterns]
            candidates = [z for z in candidates if any(fnmatch.fnmatchcase(z.name, p) for p in pats)]
        if include or exclude:
            load_tags(route53, candidates)
            candidates = [z for z in candidates if tags_match(z.tags, include, exclude)]
        for z in candidates:
            selected.setdefault(z.zone_id, z)
    elif not zone_ids and require_selector:
        raise ValueError("Specify at least one of --zone, --zone-name or --zone-tag")
    return list(selected.values())
