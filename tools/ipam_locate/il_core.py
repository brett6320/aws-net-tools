"""IPAM collection and IP/CIDR matching for ipam_locate.

Two halves:

  collect()  reads the IPAM through the EC2 API (all calls go to the IPAM home
             Region) and returns a JSON-serializable *bundle*: the IPAM, its
             scopes, the pools and pool CIDRs / allocations that touch the query,
             and the discovered resource CIDRs, public addresses and address
             history that touch it. Nothing outside what the API returns is kept,
             and never the AWS profile.

  locate()   pure function over a bundle: works out the candidate owners
             (account / Region / VPC / subnet / resource), the IPAM pool chain,
             and the most specific parent CIDR. The CLI summary and the HTML
             report both use it, so a saved bundle re-renders offline.

IPAM's Get* calls don't document their filter names, so every list is fetched in
full (paginated) and matched locally with the ipaddress module.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

log = logging.getLogger("ipam_locate")

Network = ipaddress.IPv4Network | ipaddress.IPv6Network

# Relation of a record's CIDR to the query.
CONTAINS = "contains"   # record CIDR is the query or a supernet of it
WITHIN = "within"       # record CIDR is inside the (CIDR) query
OVERLAPS = "overlaps"   # partial overlap: can't happen for CIDR-aligned blocks, kept for safety

# Specificity of a leaf, most specific first (used to rank candidates).
KIND_RANK = {"instance": 0, "service": 1, "eni": 2, "eip": 2, "public-ip": 2, "subnet": 3, "vpc": 4,
             "public-ipv4-pool": 5, "ipv6-pool": 5, "anycast-ip-list": 5, "allocation": 6, "pool": 7}

WORKERS = 8


class ValidationError(ValueError):
    pass


# ---------- query ----------

def parse_query(value: str) -> Network:
    """'10.1.2.3' -> 10.1.2.3/32, '10.1.0.0/16' -> itself. Host bits are an error, so a
    typo like 10.1.2.3/16 isn't silently widened."""
    try:
        return ipaddress.ip_network(value.strip(), strict=True)
    except ValueError as e:
        raise ValidationError(f"{value!r} is not an IP address or CIDR: {e}") from None


def is_single_address(net: Network) -> bool:
    return net.num_addresses == 1


# Never public: RFC 1918, shared (CGNAT), link-local, loopback, ULA. Anything else might be.
_NON_PUBLIC = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                                 "169.254.0.0/16", "127.0.0.0/8", "fc00::/7", "fe80::/10", "::1/128")]


def may_be_public(net: Network) -> bool:
    """Whether to look the query up in IPAM's public addresses."""
    return not any(net.version == n.version and net.subnet_of(n) for n in _NON_PUBLIC)


def family(net: Network) -> str:
    return "ipv4" if net.version == 4 else "ipv6"


def relation(cidr: str | None, query: Network) -> str | None:
    """How a record CIDR relates to the query, or None when they don't touch."""
    if not cidr:
        return None
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None
    if net.version != query.version or not net.overlaps(query):
        return None
    if query.subnet_of(net):
        return CONTAINS
    if net.subnet_of(query):
        return WITHIN
    return OVERLAPS


def prefixlen(cidr: str | None) -> int:
    try:
        return ipaddress.ip_network(cidr, strict=False).prefixlen
    except (TypeError, ValueError):
        return -1


# ---------- AWS plumbing ----------

def get_session(profile: str | None, region: str | None) -> boto3.Session:
    return boto3.Session(profile_name=profile, region_name=region)


def get_client(service: str, session: boto3.Session, region: str | None = None):
    config = Config(retries={"max_attempts": 5, "mode": "adaptive"})
    return session.client(service, region_name=region, config=config)


def _paginate(ec2, op: str, key: str, **params) -> Iterator[dict]:
    """Yield items across pages; falls back to NextToken for ops without a paginator."""
    log.debug("%s %s", op, params)
    if ec2.can_paginate(op):
        for page in ec2.get_paginator(op).paginate(**params):
            yield from page.get(key, [])
        return
    token = None
    while True:
        page = getattr(ec2, op)(**params, **({"NextToken": token} if token else {}))
        yield from page.get(key, [])
        token = page.get("NextToken")
        if not token:
            return


def _parallel(fn: Callable, items: Iterable) -> list:
    items = list(items)
    if len(items) <= 1:
        return [fn(i) for i in items]
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        return list(pool.map(fn, items))


# ---------- collection ----------

def pick_ipam(ec2, ipam_id: str | None) -> dict:
    ipams = list(_paginate(ec2, "describe_ipams", "Ipams", **({"IpamIds": [ipam_id]} if ipam_id else {})))
    if not ipams:
        raise LookupError("No IPAM found in this Region. Use --region with the IPAM's home Region "
                          "(and the IPAM owner / delegated administrator account).")
    if len(ipams) > 1:
        ids = ", ".join(i["IpamId"] for i in ipams)
        raise ValidationError(f"Several IPAMs in this Region ({ids}); choose one with --ipam-id")
    return ipams[0]


def resource_discoveries(ec2, ipam: dict) -> list[dict]:
    """Discoveries associated with the IPAM ({id, regions}). Includes discoveries shared
    from other accounts; falls back to the IPAM's default discovery."""
    assoc = [a for a in _paginate(ec2, "describe_ipam_resource_discovery_associations",
                                  "IpamResourceDiscoveryAssociations")
             if a.get("IpamId") == ipam["IpamId"] and a.get("State", "").startswith("associate-complete")]
    ids = [a["IpamResourceDiscoveryId"] for a in assoc] or [ipam.get("DefaultResourceDiscoveryId")]
    ids = [i for i in dict.fromkeys(ids) if i]
    try:
        found = {d["IpamResourceDiscoveryId"]: d for d in
                 _paginate(ec2, "describe_ipam_resource_discoveries", "IpamResourceDiscoveries",
                           IpamResourceDiscoveryIds=ids)} if ids else {}
    except ClientError as e:
        # Shared discoveries may not be describable; their Regions fall back to the IPAM's.
        log.warning("DescribeIpamResourceDiscoveries failed (%s); using the IPAM's operating Regions", _code(e))
        found = {}
    ipam_regions = [r["RegionName"] for r in ipam.get("OperatingRegions") or []]
    out = []
    for i in ids:
        d = found.get(i) or {}
        regions = [r["RegionName"] for r in d.get("OperatingRegions") or []] or ipam_regions
        out.append({"IpamResourceDiscoveryId": i, "OwnerId": d.get("OwnerId"), "IsDefault": d.get("IsDefault"),
                    "Regions": regions})
    return out


def collect(ec2, query: Network, ipam_id: str | None = None, regions: list[str] | None = None) -> dict:
    """Read everything relevant to `query` from the IPAM and return a bundle."""
    warnings: list[str] = []
    ipam = pick_ipam(ec2, ipam_id)
    log.info("IPAM %s (home %s, %s tier)", ipam["IpamId"], ipam.get("IpamRegion"), ipam.get("Tier", "?"))
    scopes = [s for s in _paginate(ec2, "describe_ipam_scopes", "IpamScopes")
              if s.get("IpamArn") == ipam.get("IpamArn")]
    discoveries = resource_discoveries(ec2, ipam)
    if regions:
        for d in discoveries:
            d["Regions"] = [r for r in d["Regions"] if r in regions]

    pools = _collect_pools(ec2, ipam, query, warnings)
    resources = _collect_resource_cidrs(ec2, discoveries, query, warnings)
    public = _collect_public_addresses(ec2, discoveries, query, warnings) if may_be_public(query) else []
    history = _collect_history(ec2, scopes, query, warnings) if is_single_address(query) else []

    return {
        "query": str(query),
        "family": family(query),
        "generated": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "ipam": {k: ipam.get(k) for k in ("IpamId", "IpamArn", "IpamRegion", "OwnerId", "Tier", "Description",
                                          "OperatingRegions", "Tags")},
        "scopes": scopes,
        "discoveries": discoveries,
        "pools": pools,
        "resources": resources,
        "public_addresses": public,
        "history": history,
        "warnings": warnings,
    }


def _collect_pools(ec2, ipam: dict, query: Network, warnings: list[str]) -> list[dict]:
    """Pools of the query's address family, each with the CIDRs and allocations that touch
    the query. Every pool is kept (for the hierarchy); only matching CIDRs are attached."""
    pools = [p for p in _paginate(ec2, "describe_ipam_pools", "IpamPools")
             if p.get("IpamArn") == ipam.get("IpamArn") and p.get("AddressFamily") == family(query)]

    def cidrs(pool: dict) -> dict:
        try:
            rows = list(_paginate(ec2, "get_ipam_pool_cidrs", "IpamPoolCidrs", IpamPoolId=pool["IpamPoolId"]))
        except ClientError as e:
            warnings.append(f"Pool {pool['IpamPoolId']}: GetIpamPoolCidrs failed ({_code(e)})")
            rows = []
        pool = dict(pool)
        pool["MatchedCidrs"] = [dict(c, Relation=rel) for c in rows if c.get("State") != "deprovisioned"
                                for rel in [relation(c.get("Cidr"), query)] if rel]
        return pool

    pools = _parallel(cidrs, pools)

    def allocations(pool: dict) -> dict:
        if pool["MatchedCidrs"]:
            try:
                rows = _paginate(ec2, "get_ipam_pool_allocations", "IpamPoolAllocations",
                                 IpamPoolId=pool["IpamPoolId"])
                pool["MatchedAllocations"] = [dict(a, Relation=rel) for a in rows
                                              for rel in [relation(a.get("Cidr"), query)] if rel]
            except ClientError as e:
                warnings.append(f"Pool {pool['IpamPoolId']}: GetIpamPoolAllocations failed ({_code(e)})")
        pool.setdefault("MatchedAllocations", [])
        return pool

    return _parallel(allocations, pools)


def _collect_resource_cidrs(ec2, discoveries: list[dict], query: Network, warnings: list[str]) -> list[dict]:
    jobs = [(d["IpamResourceDiscoveryId"], r) for d in discoveries for r in d["Regions"]]
    log.info("Searching discovered resources: %d Region(s) x %d discover%s", len({r for _, r in jobs}),
             len(discoveries), "y" if len(discoveries) == 1 else "ies")

    def one(job: tuple[str, str]) -> list[dict]:
        did, region = job
        try:
            rows = _paginate(ec2, "get_ipam_discovered_resource_cidrs", "IpamDiscoveredResourceCidrs",
                             IpamResourceDiscoveryId=did, ResourceRegion=region)
            return [dict(r, Relation=rel) for r in rows for rel in [relation(r.get("ResourceCidr"), query)] if rel]
        except ClientError as e:
            warnings.append(f"{region}: GetIpamDiscoveredResourceCidrs failed ({_code(e)})")
            return []

    return _dedupe([r for rows in _parallel(one, jobs) for r in rows],
                   ("ResourceOwnerId", "ResourceRegion", "ResourceId", "ResourceCidr"))


def _collect_public_addresses(ec2, discoveries: list[dict], query: Network, warnings: list[str]) -> list[dict]:
    jobs = [(d["IpamResourceDiscoveryId"], r) for d in discoveries for r in d["Regions"]]

    def one(job: tuple[str, str]) -> list[dict]:
        did, region = job
        try:
            rows = _paginate(ec2, "get_ipam_discovered_public_addresses", "IpamDiscoveredPublicAddresses",
                             IpamResourceDiscoveryId=did, AddressRegion=region)
            return [dict(r, Relation=rel) for r in rows for rel in [relation(r.get("Address"), query)] if rel]
        except ClientError as e:
            warnings.append(f"{region}: GetIpamDiscoveredPublicAddresses failed ({_code(e)})")
            return []

    return _dedupe([r for rows in _parallel(one, jobs) for r in rows],
                   ("AddressOwnerId", "AddressRegion", "Address", "NetworkInterfaceId"))


def _collect_history(ec2, scopes: list[dict], query: Network, warnings: list[str]) -> list[dict]:
    """Current address history for a single IP (it matches the exact CIDR only). This is
    where the instance behind an ENI comes from."""
    def one(scope: dict) -> list[dict]:
        try:
            rows = _paginate(ec2, "get_ipam_address_history", "HistoryRecords",
                             Cidr=str(query), IpamScopeId=scope["IpamScopeId"])
            return [dict(r, IpamScopeId=scope["IpamScopeId"]) for r in rows if not r.get("SampledEndTime")]
        except ClientError as e:
            warnings.append(f"Scope {scope['IpamScopeId']}: GetIpamAddressHistory failed ({_code(e)})")
            return []

    return [r for rows in _parallel(one, scopes) for r in rows]


def _dedupe(rows: list[dict], keys: tuple[str, ...]) -> list[dict]:
    seen, out = set(), []
    for r in rows:
        k = tuple(r.get(x) for x in keys)
        if k not in seen:
            seen.add(k)
            out.append(r)
    return out


def _code(e: ClientError) -> str:
    return e.response.get("Error", {}).get("Code", "error")


# ---------- locate (pure) ----------

def _tag(tags: Any, key: str = "Name") -> str | None:
    if isinstance(tags, dict):  # public addresses use {"EipTags": [...]}
        tags = [t for v in tags.values() for t in v or []]
    for t in tags or []:
        if t.get("Key") == key and t.get("Value"):
            return t["Value"]
    return None


def resource_kind(rtype: str | None) -> str:
    return {"network-interface": "eni"}.get(rtype or "", rtype or "resource")


def pool_chain(pools: list[dict]) -> list[list[dict]]:
    """Chains of pools (top-level first) that contain the query, one per deepest matching
    pool. A pool is in a chain only if one of its CIDRs contains the query."""
    by_id = {p["IpamPoolId"]: p for p in pools}
    containing = {p["IpamPoolId"] for p in pools
                  if any(c["Relation"] == CONTAINS for c in p.get("MatchedCidrs", []))}
    parents = {by_id[i].get("SourceIpamPoolId") for i in containing}
    chains = []
    for pid in containing - parents:
        chain, cur = [], by_id.get(pid)
        while cur:
            chain.insert(0, cur)
            cur = by_id.get(cur.get("SourceIpamPoolId"))
        chains.append(chain)
    return sorted(chains, key=lambda c: (-len(c), -max(prefixlen(x["Cidr"]) for x in c[-1]["MatchedCidrs"])))


def best_cidr(pool: dict) -> str | None:
    """Most specific CIDR of a pool that contains the query."""
    cands = [c["Cidr"] for c in pool.get("MatchedCidrs", []) if c["Relation"] == CONTAINS]
    return max(cands, key=prefixlen) if cands else None


def locate(bundle: dict) -> dict:
    """Candidates, pool chains, most specific parent and contained resources for a bundle.

    A candidate is one owner of the query: an (account, Region, VPC) group from the
    discovered resource CIDRs, or a public address. Private ranges are often reused, so
    there can be several. Each candidate's leaf is its most specific containing record;
    the instance comes from address history (or the public-address record) for its ENI.
    """
    query = ipaddress.ip_network(bundle["query"])
    resources = bundle.get("resources") or []
    history = bundle.get("history") or []
    containing = [r for r in resources if r.get("Relation") == CONTAINS]

    groups: dict[tuple, list[dict]] = {}
    for r in containing:
        vpc = r.get("VpcId") or (r["ResourceId"] if r.get("ResourceType") == "vpc" else None)
        key = (r.get("ResourceOwnerId"), r.get("ResourceRegion"), vpc or r.get("ResourceId"))
        groups.setdefault(key, []).append(r)

    candidates = []
    for (acct, region, vpc_or_res), rows in groups.items():
        rows = sorted(rows, key=lambda r: (prefixlen(r.get("ResourceCidr")),
                                           -KIND_RANK.get(resource_kind(r.get("ResourceType")), 9)))
        by_type = {resource_kind(r.get("ResourceType")): r for r in rows}
        leaf = rows[-1]
        cand = {
            "account": acct, "region": region,
            "vpc": by_type.get("vpc") or ({"ResourceId": leaf["VpcId"]} if leaf.get("VpcId") else None),
            "subnet": by_type.get("subnet") or ({"ResourceId": leaf["SubnetId"]} if leaf.get("SubnetId") else None),
            "resource": None, "instance": None, "public": None,
            "leaf_kind": resource_kind(leaf.get("ResourceType")), "cidr": leaf.get("ResourceCidr"),
            "records": rows,
        }
        if cand["leaf_kind"] in ("eni", "eip", "public-ipv4-pool", "ipv6-pool", "anycast-ip-list"):
            cand["resource"] = leaf
        eni = (cand["resource"] or {}).get("ResourceId")
        inst = next((h for h in history if h.get("ResourceType") == "instance"
                     and h.get("ResourceOwnerId") == acct and h.get("ResourceRegion") == region
                     and (h.get("VpcId") in (None, (cand["vpc"] or {}).get("ResourceId")))), None)
        if inst and cand["leaf_kind"] == "eni":
            cand["instance"] = inst
            cand["leaf_kind"] = "instance"
        cand["eni_id"] = eni if eni and eni.startswith("eni-") else None
        candidates.append(cand)

    for a in bundle.get("public_addresses") or []:
        if a.get("Relation") != CONTAINS:
            continue
        # Same owner and Region, and either the same EIP allocation or the same VPC.
        match = next((c for c in candidates if c["account"] == a.get("AddressOwnerId")
                      and c["region"] == a.get("AddressRegion")
                      and (((c["resource"] or {}).get("ResourceId") or "x") == a.get("AddressAllocationId")
                           or (c["vpc"] or {}).get("ResourceId") == a.get("VpcId"))), None)
        if match is None:
            match = {"account": a.get("AddressOwnerId"), "region": a.get("AddressRegion"),
                     "vpc": {"ResourceId": a["VpcId"]} if a.get("VpcId") else None,
                     "subnet": {"ResourceId": a["SubnetId"]} if a.get("SubnetId") else None,
                     "resource": None, "instance": None, "eni_id": None, "leaf_kind": "public-ip",
                     "cidr": a.get("Address"), "records": []}
            candidates.append(match)
        match["public"] = a
        match["eni_id"] = match["eni_id"] or a.get("NetworkInterfaceId")
        match["vpc"] = match["vpc"] or ({"ResourceId": a["VpcId"]} if a.get("VpcId") else None)
        match["subnet"] = match["subnet"] or ({"ResourceId": a["SubnetId"]} if a.get("SubnetId") else None)
        if a.get("InstanceId"):
            match["instance"] = match["instance"] or {"ResourceId": a["InstanceId"], "ResourceType": "instance"}
            match["leaf_kind"] = "instance"
        elif a.get("Service") and a["Service"] != "other":
            match["leaf_kind"] = "service"
        elif KIND_RANK.get(match["leaf_kind"], 9) > KIND_RANK["public-ip"]:
            match["leaf_kind"] = "public-ip"

    # Most specific leaf first; in-use ENIs before detached ones.
    candidates.sort(key=lambda c: (KIND_RANK.get(c["leaf_kind"], 9), -prefixlen(c["cidr"]),
                                   ((c["resource"] or {}).get("NetworkInterfaceAttachmentStatus") != "in-use"),
                                   c["account"] or "", c["region"] or ""))

    chains = pool_chain(bundle.get("pools") or [])
    deepest = chains[0][-1] if chains else None
    alloc = None
    if deepest:
        allocs = [a for a in deepest.get("MatchedAllocations", []) if a["Relation"] == CONTAINS
                  and a.get("ResourceType") != "ipam-pool"]
        alloc = max(allocs, key=lambda a: prefixlen(a.get("Cidr")), default=None)

    # Most specific parent CIDR anywhere: candidate leaf, allocation, then pool CIDR.
    parents = [(c["cidr"], "resource") for c in candidates if c["cidr"]]
    if alloc:
        parents.append((alloc["Cidr"], "allocation"))
    if deepest:
        parents.append((best_cidr(deepest), "pool"))
    parents = [p for p in parents if p[0]]
    most_specific = max(parents, key=lambda p: prefixlen(p[0])) if parents else None

    within = sorted((r for r in resources if r.get("Relation") == WITHIN),
                    key=lambda r: ipaddress.ip_network(r["ResourceCidr"], strict=False))

    if candidates and candidates[0]["leaf_kind"] in ("instance", "service", "eni", "eip", "public-ip"):
        status = "resource"
    elif candidates:
        status = "network"
    elif deepest:
        status = "pool"
    else:
        status = "none"
    return {
        "query": query, "single": is_single_address(query), "status": status,
        "candidates": candidates, "pool_chains": chains, "deepest_pool": deepest, "allocation": alloc,
        "most_specific": {"cidr": most_specific[0], "source": most_specific[1]} if most_specific else None,
        "within": within,
    }


# ---------- console links ----------

_CONSOLE_DOMAIN = {"aws": "console.aws.amazon.com", "aws-us-gov": "console.amazonaws-us-gov.com",
                   "aws-cn": "console.amazonaws.cn"}


def console_base(region: str, partition: str = "aws") -> str:
    domain = _CONSOLE_DOMAIN.get(partition, _CONSOLE_DOMAIN["aws"])
    if partition == "aws":
        return f"https://{region}.{domain}"
    return f"https://{domain}"


def partition_of(arn: str | None) -> str:
    parts = (arn or "").split(":")
    return parts[1] if len(parts) > 1 and parts[1] else "aws"


def console_url(kind: str, rid: str | None, region: str | None, partition: str = "aws") -> str | None:
    """Console deep link. Resource links open in whichever account you're signed in to,
    so cross-account resources need a session in the owning account. IPAM links use the
    IPAM home Region."""
    if not rid or not region:
        return None
    base = console_base(region, partition)
    q = f"?region={region}"
    return {
        "vpc": f"{base}/vpcconsole/home{q}#VpcDetails:VpcId={rid}",
        "subnet": f"{base}/vpcconsole/home{q}#SubnetDetails:subnetId={rid}",
        "eni": f"{base}/ec2/home{q}#NetworkInterface:networkInterfaceId={rid}",
        "instance": f"{base}/ec2/home{q}#InstanceDetails:instanceId={rid}",
        "eip": f"{base}/ec2/home{q}#ElasticIpDetails:AllocationId={rid}",
        "pool": f"{base}/ipam/home{q}#PoolDetails:PoolId={rid}",
        "ipam": f"{base}/ipam/home{q}#IPAMDetails:IPAMId={rid}",
        "scope": f"{base}/ipam/home{q}#ScopeDetails:ScopeId={rid}",
    }.get(kind)


# ---------- reports ----------

def _slug(text: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "-." else "_" for ch in text).strip("_")[:80] or "query"


def report_path(bundle: dict, reports_dir: str | Path) -> Path:
    """<reports_dir>/<YYYY-MM-DD>/<account>/ipam-locate_<query>.html. The account is the
    top candidate's owner when there is exactly one owning account, else the IPAM owner."""
    loc = locate(bundle)
    owners = {c["account"] for c in loc["candidates"] if c["account"]}
    account = owners.pop() if len(owners) == 1 else (bundle.get("ipam") or {}).get("OwnerId") or "unknown-account"
    day = (bundle.get("generated") or dt.datetime.now(dt.timezone.utc).isoformat())[:10]
    return Path(reports_dir) / day / account / f"ipam-locate_{_slug(bundle['query'].replace('/', '_'))}.html"
