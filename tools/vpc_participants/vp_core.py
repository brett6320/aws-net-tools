"""Find who a VPC is shared with: its owner account and the RAM principals its subnets are shared to.

The VPC's owner (and Region) comes from the VPC owner map that ``ou_vpcs`` writes
(~/.cache/aws-net-tools/vpc-owners.json). The owner account is read with the profile that maps
to its account ID in ~/.aws/config (never one ending in -priv, -adm, -cpar or -ro, as in ou_vpcs):
its subnets in the VPC, the RAM resource shares that contain them, and each share's principal
associations. OU and organization principals are expanded to their member accounts with
Organizations (``--org-profile``) or, without it, from the accounts the owner map knows.
No role is assumed; nothing is changed.
"""
from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

import botocore.session
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

log = logging.getLogger("vpc_participants")

BOTO_CONFIG = Config(retries={"max_attempts": 5, "mode": "adaptive"})
CACHE_FILENAME = "vpc-owners.json"
DEFAULT_EXCLUDE_SUFFIXES = ("-priv", "-adm", "-cpar", "-ro")
READ_ONLY_SUFFIXES = ("-ro", "-readonly", "-read-only")
# Principal associations in these states no longer give access; left out unless asked for.
GONE_STATUSES = frozenset({"DISASSOCIATED", "DISASSOCIATING", "FAILED"})
CHUNK = 20

ACCOUNT_RE = re.compile(r"^\d{12}$")
REGION_RE = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-\d$")
VPC_RE = re.compile(r"^vpc-[0-9a-f]{8,17}$")
_ROLE_ARN_ACCOUNT = re.compile(r"^arn:[^:]+:iam::(\d{12}):")
_OU_ARN = re.compile(r"^arn:[^:]+:organizations::\d{12}:ou/(o-[a-z0-9]+)/(ou-[0-9a-z]+-[0-9a-z]+)$")
_ORG_ARN = re.compile(r"^arn:[^:]+:organizations::\d{12}:organization/(o-[a-z0-9]+)$")


# --------------------------------------------------------------------------- input


def split_csv(values: Iterable[str] | None) -> list[str]:
    out: list[str] = []
    for raw in values or []:
        for item in raw.split(","):
            if item.strip() and item.strip() not in out:
                out.append(item.strip())
    return out


def parse_account_profiles(values: Iterable[str] | None) -> dict[str, str]:
    out = {}
    for raw in split_csv(values):
        acct, sep, profile = raw.partition("=")
        if not sep or not ACCOUNT_RE.match(acct.strip()) or not profile.strip():
            raise ValueError(f"--account-profile: '{raw}' is not ACCOUNT=PROFILE")
        out[acct.strip()] = profile.strip()
    return out


def default_cache_path() -> Path:
    if os.name == "nt" and os.getenv("LOCALAPPDATA"):
        base = Path(os.environ["LOCALAPPDATA"])
    else:
        base = Path(os.getenv("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / "aws-net-tools" / CACHE_FILENAME


@dataclass(frozen=True)
class Vpc:
    region: str
    vpc_id: str
    account: str
    account_name: str = ""
    ou_id: str = ""
    ou_path: str = ""
    name: str = ""


def load_vpcs(path: Path) -> list[Vpc]:
    """Every VPC in the owner map. Entries other tools wrote with only ``account`` are kept. Raises FileNotFoundError / ValueError."""
    if not path.exists():
        raise FileNotFoundError(f"VPC owner map {path} not found; run ou_vpcs first (or pass --cache)")
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError) as e:
        raise ValueError(f"VPC owner map {path} is unreadable: {e}") from e
    out = []
    for key, e in data.items() if isinstance(data, dict) else []:
        region, _, vpc_id = key.partition("/")
        if not isinstance(e, dict) or not ACCOUNT_RE.match(str(e.get("account", ""))) or not VPC_RE.match(vpc_id):
            log.debug("Ignoring owner map entry %s", key)
            continue
        out.append(Vpc(region, vpc_id, e["account"], e.get("account_name", ""), e.get("ou_id", ""),
                       e.get("ou_path", ""), e.get("name", "")))
    return sorted(out, key=lambda v: (v.account, v.region, v.vpc_id))


def find_vpcs(catalog: Iterable[Vpc], vpc_ids: list[str], regions: list[str] | None = None) -> list[Vpc]:
    """The catalog entry of each VPC ID. Raises ValueError for a bad ID, an unknown VPC, or one in several Regions."""
    if not vpc_ids:
        raise ValueError("Give at least one VPC ID")
    for v in vpc_ids:
        if not VPC_RE.match(v):
            raise ValueError(f"'{v}' is not a VPC ID")
    for r in regions or []:
        if not REGION_RE.match(r):
            raise ValueError(f"--regions: '{r}' is not a Region name")
    catalog = [v for v in catalog if not regions or v.region in regions]
    out = []
    for vid in vpc_ids:
        hits = [v for v in catalog if v.vpc_id == vid]
        if not hits:
            raise ValueError(f"{vid} is not in the VPC owner map{' for ' + ', '.join(regions) if regions else ''}; "
                             "run ou_vpcs for its OU first")
        if len(hits) > 1:
            raise ValueError(f"{vid} is in the VPC owner map in several Regions ({', '.join(h.region for h in hits)}); "
                             "choose one with --regions")
        out.append(hits[0])
    return out


# --------------------------------------------------------------------------- profiles (as in ou_vpcs)


def exclude_suffixes() -> tuple[str, ...]:
    raw = os.getenv("VPC_PART_PROFILE_EXCLUDE_SUFFIXES")
    if raw is None:
        return DEFAULT_EXCLUDE_SUFFIXES
    return tuple(s.strip().lower() for s in raw.split(",") if s.strip())


def profile_account(cfg: dict[str, str]) -> str | None:
    for key in ("sso_account_id", "aws_account_id"):
        if cfg.get(key):
            return str(cfg[key]).strip()
    m = _ROLE_ARN_ACCOUNT.match(cfg.get("role_arn", ""))
    return m.group(1) if m else None


@lru_cache(maxsize=1)
def profile_accounts() -> dict[str, str]:
    """Profile name -> account ID, for profiles whose account is in ~/.aws/config or ~/.aws/credentials."""
    profiles = botocore.session.Session().full_config.get("profiles", {})
    return {name: acct for name, cfg in profiles.items() if (acct := profile_account(cfg))}


def resolve_profile(account: str, overrides: dict[str, str] | None = None, preferred: str | None = None) -> str:
    """The profile to read ``account`` with. Raises LookupError when there's none or several."""
    if overrides and account in overrides:
        return overrides[account]
    excluded = exclude_suffixes()
    cands = sorted(n for n, a in profile_accounts().items() if a == account and not n.lower().endswith(excluded))
    if not cands:
        raise LookupError("no profile in ~/.aws/config maps to it")
    if preferred in cands:
        return preferred
    if len(cands) > 1:
        ro = [c for c in cands if c.endswith(READ_ONLY_SUFFIXES)]
        if len(ro) == 1:
            return ro[0]
        raise LookupError(f"several profiles map to it ({', '.join(cands)}); choose one with --account-profile")
    return cands[0]


# --------------------------------------------------------------------------- helpers


def _error(e: Exception) -> str:
    if isinstance(e, ClientError):
        err = e.response.get("Error", {})
        return f"{err.get('Code')}: {err.get('Message')}"
    return str(e)


def _chunks(items: list, n: int = CHUNK) -> Iterator[list]:
    for i in range(0, len(items), n):
        yield items[i:i + n]


def _pages(client: Any, op: str, key: str, **kw: Any) -> Iterator[dict[str, Any]]:
    for page in client.get_paginator(op).paginate(**kw):
        yield from page.get(key) or []


def principal_type(pid: str) -> str:
    if ACCOUNT_RE.match(pid):
        return "account"
    if _OU_ARN.match(pid):
        return "ou"
    if _ORG_ARN.match(pid):
        return "organization"
    return "other"  # an IAM role/user or service principal: not expected for subnets


# --------------------------------------------------------------------------- RAM


@dataclass
class Share:
    arn: str
    name: str
    status: str
    allow_external: bool


@dataclass
class Association:
    principal: str
    share_arn: str
    status: str
    external: bool


@dataclass
class VpcSharing:
    """One VPC: its subnets, which shares contain each, and the shares' principal associations."""
    vpc: Vpc
    profile: str = ""
    subnets: list[dict[str, str]] = field(default_factory=list)  # {id, arn, cidr, az, name}
    subnet_shares: dict[str, list[tuple[str, str]]] = field(default_factory=dict)  # subnet ID -> [(share ARN, resource status)]
    shares: dict[str, Share] = field(default_factory=dict)
    associations: list[Association] = field(default_factory=list)
    error: str = ""


def subnet_row(s: dict[str, Any], partition: str, region: str) -> dict[str, str]:
    tags = {t["Key"]: t["Value"] for t in s.get("Tags") or []}
    arn = s.get("SubnetArn") or f"arn:{partition}:ec2:{region}:{s['OwnerId']}:subnet/{s['SubnetId']}"
    return {"id": s["SubnetId"], "arn": arn, "cidr": s.get("CidrBlock", ""), "az": s.get("AvailabilityZone", ""),
            "name": tags.get("Name", "")}


def read_region(session: Any, region: str, vpcs: list[Vpc]) -> dict[str, VpcSharing]:
    """Subnets, resource shares and principal associations for the VPCs one account owns in one Region."""
    out = {v.vpc_id: VpcSharing(v) for v in vpcs}
    try:
        partition = session.get_partition_for_region(region)
    except Exception:  # noqa: BLE001 - only used when a subnet has no SubnetArn
        partition = "aws"
    ec2 = session.client("ec2", region_name=region, config=BOTO_CONFIG)
    by_arn: dict[str, tuple[str, str]] = {}  # subnet ARN -> (VPC ID, subnet ID)
    for s in _pages(ec2, "describe_subnets", "Subnets", Filters=[{"Name": "vpc-id", "Values": sorted(out)}]):
        row = subnet_row(s, partition, region)
        out[s["VpcId"]].subnets.append(row)
        by_arn[row["arn"]] = (s["VpcId"], row["id"])
    for sh in out.values():
        sh.subnets.sort(key=lambda r: r["id"])
    if not by_arn:
        return out

    ram = session.client("ram", region_name=region, config=BOTO_CONFIG)
    share_vpcs: dict[str, set[str]] = {}
    for chunk in _chunks(sorted(by_arn)):
        for r in _pages(ram, "list_resources", "resources", resourceOwner="SELF", resourceType="ec2:Subnet",
                        resourceArns=chunk):
            if r.get("arn") not in by_arn:
                continue
            vpc_id, subnet_id = by_arn[r["arn"]]
            out[vpc_id].subnet_shares.setdefault(subnet_id, []).append((r["resourceShareArn"], r.get("status", "")))
            share_vpcs.setdefault(r["resourceShareArn"], set()).add(vpc_id)
    if not share_vpcs:
        return out

    shares: dict[str, Share] = {}
    for chunk in _chunks(sorted(share_vpcs)):
        for s in _pages(ram, "get_resource_shares", "resourceShares", resourceOwner="SELF", resourceShareArns=chunk):
            shares[s["resourceShareArn"]] = Share(s["resourceShareArn"], s.get("name", ""), s.get("status", ""),
                                                  bool(s.get("allowExternalPrincipals")))
    for chunk in _chunks(sorted(share_vpcs)):
        for a in _pages(ram, "get_resource_share_associations", "resourceShareAssociations",
                        associationType="PRINCIPAL", resourceShareArns=chunk):
            assoc = Association(a["associatedEntity"], a["resourceShareArn"], a.get("status", ""), bool(a.get("external")))
            for vpc_id in share_vpcs.get(assoc.share_arn, ()):
                out[vpc_id].associations.append(assoc)
    for arn, vpc_ids in share_vpcs.items():
        for vpc_id in vpc_ids:
            out[vpc_id].shares[arn] = shares.get(arn) or Share(arn, "", "", False)
    return out


def read_sharing(vpcs: Iterable[Vpc], session_for: Callable[[str], Any], overrides: dict[str, str] | None = None,
                 preferred: str | None = None) -> list[VpcSharing]:
    """Read every VPC from its owner account, one session per account and one set of calls per Region.

    An account or Region that can't be read sets ``error`` on its VPCs; the others carry on.
    """
    groups: dict[str, dict[str, list[Vpc]]] = {}
    for v in vpcs:
        groups.setdefault(v.account, {}).setdefault(v.region, []).append(v)
    results: dict[tuple[str, str], VpcSharing] = {}
    for account, regions in groups.items():
        try:
            profile = resolve_profile(account, overrides, preferred)
            session = session_for(profile)
            actual = session.client("sts", region_name=next(iter(regions)), config=BOTO_CONFIG).get_caller_identity()["Account"]
            if actual != account:
                raise PermissionError(f"profile {profile} authenticates as {actual}")
        except (LookupError, PermissionError, ClientError, BotoCoreError) as e:
            log.warning("Can't read owner account %s: %s", account, _error(e))
            for region, vs in regions.items():
                for v in vs:
                    results[(region, v.vpc_id)] = VpcSharing(v, error=f"owner account {account}: {_error(e)}")
            continue
        log.info("Owner account %s: profile %s", account, profile)
        for region, vs in regions.items():
            try:
                found = read_region(session, region, vs)
            except (ClientError, BotoCoreError) as e:
                log.warning("Can't read %s in %s: %s", account, region, _error(e))
                found = {v.vpc_id: VpcSharing(v, error=f"{account} {region}: {_error(e)}") for v in vs}
            for vpc_id, sh in found.items():
                sh.profile = profile
                results[(region, vpc_id)] = sh
    return [results[(v.region, v.vpc_id)] for v in vpcs]


# --------------------------------------------------------------------------- principals


@dataclass
class Directory:
    """Account names and OU details, from Organizations when available, otherwise the owner map."""
    names: dict[str, str] = field(default_factory=dict)
    ou_paths: dict[str, str] = field(default_factory=dict)  # OU ID -> Root/... path
    catalog: list[Vpc] = field(default_factory=list)
    org: Any = None
    _members: dict[str, list[str]] = field(default_factory=dict)

    @classmethod
    def from_catalog(cls, catalog: list[Vpc], org: Any = None) -> "Directory":
        d = cls(catalog=catalog, org=org)
        for v in catalog:
            if v.account_name:
                d.names.setdefault(v.account, v.account_name)
            if v.ou_id and v.ou_path:
                d.ou_paths.setdefault(v.ou_id, v.ou_path)
        return d

    def account_name(self, account: str) -> str:
        if account not in self.names and self.org is not None:
            try:
                self.names[account] = self.org.describe_account(AccountId=account)["Account"].get("Name", "")
            except (ClientError, BotoCoreError) as e:
                log.debug("DescribeAccount %s: %s", account, _error(e))
                self.names[account] = ""
        return self.names.get(account, "")

    def ou_path(self, ou_id: str) -> str:
        if ou_id not in self.ou_paths and self.org is not None:
            try:
                self.ou_paths[ou_id] = _org_ou_path(self.org, ou_id)
            except (ClientError, BotoCoreError) as e:
                log.warning("Organizations: can't describe %s: %s", ou_id, _error(e))
                self.ou_paths[ou_id] = ""
        return self.ou_paths.get(ou_id, "")

    def members(self, principal: str) -> tuple[list[str], str]:
        """Accounts an OU or organization principal covers, and where that came from ("organizations" or "catalog")."""
        kind = principal_type(principal)
        if kind not in ("ou", "organization"):
            return [], ""
        if self.org is not None:
            if principal not in self._members:
                try:
                    self._members[principal] = _org_members(self.org, principal, self.names)
                except (ValueError, ClientError, BotoCoreError) as e:
                    log.warning("Organizations: can't list the accounts in %s: %s; using the VPC owner map", principal, _error(e))
                    self._members[principal] = None  # type: ignore[assignment]
            if self._members[principal] is not None:
                return self._members[principal], "organizations"
        if kind == "organization":
            return sorted({v.account for v in self.catalog}), "catalog"
        ou_id = _OU_ARN.match(principal).group(2)
        if not (path := self.ou_path(ou_id)):
            # The owner map only knows the OU each account sits in directly, not the OUs above it.
            log.warning("%s isn't in the VPC owner map (no account with a VPC sits directly in it); "
                        "pass --org-profile to list its accounts", ou_id)
            return [], "unknown"
        return sorted({v.account for v in self.catalog
                       if v.ou_path == path or v.ou_path.startswith(path + "/")}), "catalog"


def _org_ou_path(org: Any, ou_id: str) -> str:
    names, cur = [], ou_id
    while not cur.startswith("r-"):
        names.append(org.describe_organizational_unit(OrganizationalUnitId=cur)["OrganizationalUnit"]["Name"])
        cur = org.list_parents(ChildId=cur)["Parents"][0]["Id"]
    names.append("Root")
    return "/".join(reversed(names))


def _org_members(org: Any, principal: str, names: dict[str, str]) -> list[str]:
    """Active accounts in an OU and every OU below it, or in the whole organization."""
    if m := _ORG_ARN.match(principal):
        actual = org.describe_organization()["Organization"]["Id"]
        if actual != m.group(1):
            raise ValueError(f"the Organizations profile is in {actual}, not {m.group(1)}")
        start = org.list_roots()["Roots"][0]["Id"]
    else:
        start = _OU_ARN.match(principal).group(2)
    found, todo = set(), [start]
    while todo:
        parent = todo.pop()
        for a in _pages(org, "list_accounts_for_parent", "Accounts", ParentId=parent):
            if (a.get("State") or a.get("Status") or "ACTIVE") == "ACTIVE":
                found.add(a["Id"])
                names.setdefault(a["Id"], a.get("Name", ""))
        todo.extend(ou["Id"] for ou in _pages(org, "list_organizational_units_for_parent", "OrganizationalUnits",
                                               ParentId=parent))
    return sorted(found)


def principal_name(directory: Directory, principal: str) -> str:
    kind = principal_type(principal)
    if kind == "account":
        return directory.account_name(principal)
    if kind == "ou":
        return directory.ou_path(_OU_ARN.match(principal).group(2))
    if kind == "organization":
        return f"organization {_ORG_ARN.match(principal).group(1)}"
    return ""


# --------------------------------------------------------------------------- rows


def build_rows(results: Iterable[VpcSharing], directory: Directory, include_inactive: bool = False) -> list[dict[str, Any]]:
    """One owner row per VPC, then one row per principal its subnets are shared with."""
    rows: list[dict[str, Any]] = []
    for r in results:
        v = r.vpc
        base = {"region": v.region, "vpc_id": v.vpc_id, "vpc_name": v.name, "owner": v.account}
        rows.append({**base, "role": "owner", "principal": v.account, "principal_type": "account",
                     "principal_name": v.account_name or directory.account_name(v.account),
                     "status": "error" if r.error else "", "external": False, "shares": [], "share_arns": [],
                     "subnets": [s["id"] for s in r.subnets], "members": [], "members_source": "",
                     "error": r.error})
        if r.error:
            continue
        # principal -> share ARN -> association status
        by_principal: dict[str, dict[str, Association]] = {}
        for a in r.associations:
            share = r.shares.get(a.share_arn)
            if not include_inactive and (a.status in GONE_STATUSES or (share and share.status not in ("", "ACTIVE"))):
                continue
            by_principal.setdefault(a.principal, {})[a.share_arn] = a
        for principal in sorted(by_principal, key=lambda p: (principal_type(p) != "account", p)):
            assocs = by_principal[principal]
            subnets = sorted({sid for sid, shs in r.subnet_shares.items() for arn, _ in shs if arn in assocs})
            members, source = directory.members(principal)
            kind = principal_type(principal)
            rows.append({**base, "role": "participant", "principal": principal, "principal_type": kind,
                         "principal_name": principal_name(directory, principal),
                         "status": ",".join(sorted({a.status for a in assocs.values()})),
                         "external": any(a.external for a in assocs.values()),
                         "shares": sorted(r.shares[arn].name or arn for arn in assocs if arn in r.shares),
                         "share_arns": sorted(assocs),
                         "subnets": subnets, "members": members, "members_source": source, "error": ""})
            if kind == "other" or rows[-1]["external"]:
                log.warning("%s: shared with %s%s, which subnet sharing doesn't normally allow", v.vpc_id, principal,
                            " (external to the organization)" if rows[-1]["external"] else "")
        unavailable = sorted(f"{sid} ({st})" for sid, shs in r.subnet_shares.items() for _, st in shs
                             if st and st != "AVAILABLE")
        if unavailable:
            log.warning("%s: shared subnet(s) not available to participants: %s", v.vpc_id, ", ".join(unavailable))
    return rows
