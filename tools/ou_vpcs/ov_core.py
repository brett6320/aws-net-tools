"""Resolve OUs to accounts (AWS Organizations), accounts to local profiles, and list each account's VPCs.

Organizations calls use one profile (management or delegated-administrator account).
Every member account is then read with its own profile, found in ~/.aws/config by
account ID (``sso_account_id`` / ``aws_account_id`` / the account in ``role_arn``).
Profiles ending in ``-priv`` or ``-cpar`` are never used. No role is assumed.
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Callable, Iterable, Iterator

import botocore.session
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

log = logging.getLogger("ou_vpcs")

BOTO_CONFIG = Config(retries={"max_attempts": 5, "mode": "adaptive"})
DEFAULT_REGIONS = ("us-east-1", "ca-central-1")
DEFAULT_EXCLUDE_SUFFIXES = ("-priv", "-cpar")
READ_ONLY_SUFFIXES = ("-ro", "-readonly", "-read-only")

OU_ID_RE = re.compile(r"^(?:ou-[0-9a-z]{4,32}-[0-9a-z]{8,32}|r-[0-9a-z]{4,32}|o-[a-z0-9]{10,32})$")
ACCOUNT_RE = re.compile(r"^\d{12}$")
REGION_RE = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-\d$")
_ROLE_ARN_ACCOUNT = re.compile(r"^arn:[^:]+:iam::(\d{12}):")


# --------------------------------------------------------------------------- input


def split_csv(values: Iterable[str] | None) -> list[str]:
    out: list[str] = []
    for raw in values or []:
        for item in raw.split(","):
            if item.strip() and item.strip() not in out:
                out.append(item.strip())
    return out


def parse_ou_ids(values: Iterable[str] | None) -> list[str]:
    ids = split_csv(values)
    if not ids:
        raise ValueError("Give at least one --ou (ou-xxxx-xxxxxxxx, or r-xxxx / o-xxxxxxxxxx for the whole organization)")
    for v in ids:
        if not OU_ID_RE.match(v):
            raise ValueError(f"--ou: '{v}' is not an OU ID (ou-xxxx-xxxxxxxx), root ID (r-xxxx) or organization ID (o-xxxxxxxxxx)")
    return ids


def parse_regions(values: Iterable[str] | None) -> list[str]:
    regions = split_csv(values) or list(DEFAULT_REGIONS)
    for r in regions:
        if not REGION_RE.match(r):
            raise ValueError(f"--regions: '{r}' is not a Region name")
    return regions


def parse_account_profiles(values: Iterable[str] | None) -> dict[str, str]:
    out = {}
    for raw in split_csv(values):
        acct, sep, profile = raw.partition("=")
        if not sep or not ACCOUNT_RE.match(acct.strip()) or not profile.strip():
            raise ValueError(f"--account-profile: '{raw}' is not ACCOUNT=PROFILE")
        out[acct.strip()] = profile.strip()
    return out


# --------------------------------------------------------------------------- organizations


@dataclass(frozen=True)
class OrgAccount:
    id: str
    name: str
    ou_id: str
    ou_path: str


def _pages(client: Any, op: str, key: str, **kw: Any) -> Iterator[dict[str, Any]]:
    for page in client.get_paginator(op).paginate(**kw):
        yield from page[key]


def ou_path(org: Any, ou_id: str) -> str:
    """Root/Parent/.../Name for an OU, by walking up its parents."""
    names, cur = [], ou_id
    while not cur.startswith("r-"):
        names.append(org.describe_organizational_unit(OrganizationalUnitId=cur)["OrganizationalUnit"]["Name"])
        cur = org.list_parents(ChildId=cur)["Parents"][0]["Id"]
    names.append("Root")
    return "/".join(reversed(names))


def walk_ous(org: Any, ou_id: str, path: str, recurse: bool = True) -> Iterator[tuple[str, str]]:
    yield ou_id, path
    if recurse:
        for child in _pages(org, "list_organizational_units_for_parent", "OrganizationalUnits", ParentId=ou_id):
            yield from walk_ous(org, child["Id"], f"{path}/{child['Name']}", True)


def resolve_org_ids(org: Any, ids: Iterable[str]) -> list[str]:
    """Replace an organization ID (o-...) with its root, after checking it's the profile's organization."""
    out: list[str] = []
    for v in ids:
        if v.startswith("o-"):
            actual = org.describe_organization()["Organization"]["Id"]
            if actual != v:
                raise ValueError(f"--ou: organization {v} was requested, but the Organizations profile is in {actual}")
            v = org.list_roots()["Roots"][0]["Id"]  # an organization has exactly one root
            log.info("Organization %s: root %s", actual, v)
        if v not in out:
            out.append(v)
    return out


def accounts_in_ous(org: Any, ou_ids: Iterable[str], recurse: bool = True) -> list[OrgAccount]:
    """Active accounts directly in each OU, and (with ``recurse``) in every OU below it.

    ``ou_ids`` may include the root (r-...) or the organization ID (o-...), meaning every account.
    """
    found: dict[str, OrgAccount] = {}
    ous = 0
    for start in resolve_org_ids(org, ou_ids):
        for ou, path in walk_ous(org, start, ou_path(org, start), recurse):
            ous += 1
            for a in _pages(org, "list_accounts_for_parent", "Accounts", ParentId=ou):
                state = a.get("State") or a.get("Status") or "ACTIVE"
                if state != "ACTIVE":
                    log.info("Skipping account %s (%s): %s", a["Id"], a.get("Name", ""), state)
                    continue
                found.setdefault(a["Id"], OrgAccount(a["Id"], a.get("Name", ""), ou, path))
    log.info("Organizations: %d active account(s) in %d OU(s)", len(found), ous)
    return sorted(found.values(), key=lambda a: (a.ou_path, a.id))


# --------------------------------------------------------------------------- profiles


def exclude_suffixes() -> tuple[str, ...]:
    raw = os.getenv("OU_VPCS_PROFILE_EXCLUDE_SUFFIXES")
    if raw is None:
        return DEFAULT_EXCLUDE_SUFFIXES
    return tuple(s.strip() for s in raw.split(",") if s.strip())


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
    cands = sorted(n for n, a in profile_accounts().items() if a == account and not n.endswith(excluded))
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


# --------------------------------------------------------------------------- VPCs


@dataclass
class Skipped:
    account: str
    region: str  # "" when the whole account was skipped
    reason: str


@dataclass
class Scan:
    rows: list[dict[str, Any]] = field(default_factory=list)
    skipped: list[Skipped] = field(default_factory=list)


def _error(e: Exception) -> str:
    if isinstance(e, ClientError):
        err = e.response.get("Error", {})
        return f"{err.get('Code')}: {err.get('Message')}"
    return str(e)


def vpc_row(acct: OrgAccount, region: str, vpc: dict[str, Any]) -> dict[str, Any]:
    tags = {t["Key"]: t["Value"] for t in vpc.get("Tags") or []}
    primary = vpc.get("CidrBlock", "")
    # Primary first, the rest sorted, so a re-run never sees a change in AWS's ordering as a new entry.
    cidrs = sorted({c["CidrBlock"] for c in vpc.get("CidrBlockAssociationSet") or []
                    if c.get("CidrBlockState", {}).get("State", "associated") == "associated"},
                   key=lambda c: (c != primary, c))
    return {
        "ou_id": acct.ou_id,
        "ou_path": acct.ou_path,
        "account": acct.id,
        "account_name": acct.name,
        "region": region,
        "vpc_id": vpc["VpcId"],
        "name": tags.get("Name", ""),
        "cidr": primary,
        "cidrs": cidrs or [primary],
        "is_default": bool(vpc.get("IsDefault")),
        "state": vpc.get("State", ""),
    }


def scan_accounts(
    accounts: Iterable[OrgAccount],
    regions: Iterable[str],
    session_for: Callable[[str], Any],
    overrides: dict[str, str] | None = None,
    preferred: str | None = None,
) -> Scan:
    """One paginated DescribeVpcs per account and Region, limited to VPCs the account owns.

    Accounts without a usable profile, credentials for the wrong account, and Regions that
    refuse the call are recorded in ``Scan.skipped``; the rest of the scan carries on.
    """
    scan = Scan()
    regions = list(regions)
    for acct in accounts:
        try:
            profile = resolve_profile(acct.id, overrides, preferred)
            session = session_for(profile)
            actual = session.client("sts", config=BOTO_CONFIG).get_caller_identity()["Account"]
            if actual != acct.id:
                raise PermissionError(f"profile {profile} authenticates as {actual}")
        except (LookupError, PermissionError, ClientError, BotoCoreError) as e:
            scan.skipped.append(Skipped(acct.id, "", _error(e)))
            log.warning("Skipping account %s (%s): %s", acct.id, acct.name, _error(e))
            continue
        log.info("Account %s (%s): profile %s", acct.id, acct.name, profile)
        for region in regions:
            try:
                ec2 = session.client("ec2", region_name=region, config=BOTO_CONFIG)
                vpcs = list(_pages(ec2, "describe_vpcs", "Vpcs", Filters=[{"Name": "owner-id", "Values": [acct.id]}]))
            except (ClientError, BotoCoreError) as e:
                scan.skipped.append(Skipped(acct.id, region, _error(e)))
                log.warning("Skipping %s in %s: %s", acct.id, region, _error(e))
                continue
            scan.rows.extend(vpc_row(acct, region, v) for v in vpcs)
            log.debug("%s %s: %d VPC(s)", acct.id, region, len(vpcs))
    scan.rows.sort(key=lambda r: (r["ou_path"], r["account"], r["region"], r["vpc_id"]))
    return scan


CACHE_SOURCE = "ou_vpcs"


def store(cache: Any, rows: Iterable[dict[str, Any]]) -> int:
    """Write each VPC's owner and details into the shared owner map. Returns how many entries changed."""
    changed = 0
    for r in rows:
        changed += cache.put(
            r["region"], r["vpc_id"], r["account"], CACHE_SOURCE,
            account_name=r["account_name"], ou_id=r["ou_id"], ou_path=r["ou_path"],
            name=r["name"], cidrs=r["cidrs"],
        )
    return changed
