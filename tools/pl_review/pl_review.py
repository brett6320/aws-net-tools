#!/usr/bin/env python3
"""Review security groups that reference an AWS Managed Prefix List (PL).

The PL may be shared across accounts via AWS RAM. The tool discovers every
security group associated with the PL (any account), resolves the owning
account to a local AWS profile, and computes the weighted rule count of each
security group per direction (ingress/egress).

AWS counts a prefix-list reference in a security group rule as the prefix
list's *MaxEntries* (not its current entry count), so each referenced prefix
list is expanded to its MaxEntries. The tool then evaluates whether raising
the target PL to ``proposed_length`` would push any security group past the
per-direction rule ``limit``.

Read-only: no mutating API calls are made.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import re
import sys
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import ssl

if os.getenv("PL_REVIEW_NO_TRUSTSTORE") != "1":
    import truststore

    if ssl.SSLContext is not truststore.SSLContext:  # guard against double injection
        truststore.inject_into_ssl()

import boto3  # noqa: E402
from botocore.config import Config  # noqa: E402
from botocore.exceptions import BotoCoreError, ClientError, ProfileNotFound  # noqa: E402
from dotenv import load_dotenv  # noqa: E402

from plr_export import THEMES, render_html  # noqa: E402

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("pl_review")
for _noisy in ("botocore", "boto3", "urllib3"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)

PROFILE_PREFIX = "hcli-"
PROFILE_EXCLUDED_SUFFIXES = ("-priv", "-cpar")
DEFAULT_LIMIT = 100
DEFAULT_CACHE_PATH = os.getenv("PL_REVIEW_CACHE_PATH") or None  # None = in-memory only
DEFAULT_CACHE_TTL = int(os.getenv("PL_REVIEW_CACHE_TTL", str(7 * 24 * 3600)))
# AWS-managed prefix list weights (number of rule slots consumed), per
# https://docs.aws.amazon.com/vpc/latest/userguide/working-with-aws-managed-prefix-lists.html
# Keyed by name with the region segment normalised to "{region}". Checked 2026-10-08.
AWS_MANAGED_WEIGHTS: dict[str, int] = {
    "com.amazonaws.global.cloudfront.origin-facing": 55,
    "com.amazonaws.global.ipv6.cloudfront.origin-facing": 55,
    "com.amazonaws.{region}.dynamodb": 1,
    "com.amazonaws.{region}.ec2-instance-connect": 2,
    "com.amazonaws.{region}.ipv6.ec2-instance-connect": 2,
    "com.amazonaws.global.groundstation": 5,
    "com.amazonaws.{region}.route53-healthchecks": 25,
    "com.amazonaws.{region}.ipv6.route53-healthchecks": 25,
    "com.amazonaws.{region}.s3": 1,
    "com.amazonaws.{region}.s3express": 6,
    "com.amazonaws.{region}.secretsmanager-managed-external-secrets": 20,
    "com.amazonaws.{region}.vpc-lattice": 10,
    "com.amazonaws.{region}.ipv6.vpc-lattice": 10,
}
_REGION_RE = re.compile(r"^(com\.amazonaws\.)([a-z]{2}(?:-[a-z]+)+-\d+)(\..+)$")


def aws_managed_weight(name: str | None) -> int | None:
    """Documented weight for an AWS-managed prefix list name, or None if unknown."""
    if not name:
        return None
    m = _REGION_RE.match(name)
    key = f"{m.group(1)}{{region}}{m.group(3)}" if m else name
    return AWS_MANAGED_WEIGHTS.get(key)


AUTH_ERROR_CODES = {
    "UnauthorizedOperation", "AccessDenied", "AccessDeniedException",
    "AuthFailure", "Client.UnauthorizedOperation", "ExpiredToken", "ExpiredTokenException",
}


def is_auth_error(e: ClientError) -> bool:
    return e.response.get("Error", {}).get("Code") in AUTH_ERROR_CODES


class AccountAccessError(Exception):
    """Raised when a profile cannot perform a required read in an account."""


class _timed:
    """Context manager: DEBUG-log start and elapsed time of an operation."""

    def __init__(self, what: str, *args: Any):
        self.msg = what % args if args else what

    def __enter__(self):
        self.t0 = time.perf_counter()
        log.debug("-> %s", self.msg)
        return self

    def __exit__(self, *exc):
        log.debug("<- %s (%.2fs)%s", self.msg, time.perf_counter() - self.t0, " FAILED" if exc[0] else "")
        return False


BOTO_CONFIG = Config(retries={"max_attempts": 5, "mode": "adaptive"})


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class DirectionUsage:
    direction: str  # "ingress" | "egress"
    rule_count: int = 0  # raw number of SG rules
    current_weight: int = 0  # weighted count with PLs expanded to MaxEntries
    proposed_weight: int = 0  # weight if target PL grows to proposed_length
    target_pl_refs: int = 0  # how many rules reference the target PL
    prefix_lists: dict[str, int] = field(default_factory=dict)  # pl-id -> refs
    pl_weights: dict[str, int] = field(default_factory=dict)  # pl-id -> weight per reference (current)
    exceeds_now: bool = False
    exceeds_proposed: bool = False
    headroom_proposed: int = 0


@dataclass
class SecurityGroupReport:
    account_id: str
    profile: str | None
    region: str
    group_id: str
    group_name: str
    vpc_id: str | None
    ingress: DirectionUsage
    egress: DirectionUsage
    error: str | None = None
    fm_managed: bool = False  # AWS Firewall Manager (FMM) replica
    fm_policy_id: str | None = None

    @property
    def at_risk(self) -> bool:
        return self.ingress.exceeds_proposed or self.egress.exceeds_proposed


@dataclass
class PrefixListReport:
    generated_at: str
    date: str
    prefix_list_id: str
    prefix_list_name: str | None
    owner_account: str
    owner_profile: str
    region: str
    current_max_entries: int
    current_entry_count: int
    proposed_length: int
    limit: int
    profiles_scanned: list[str]
    accounts_without_profile: list[str]
    security_groups: list[SecurityGroupReport]
    at_risk_count: int = 0
    error_count: int = 0
    fm_policies: dict[str, dict[str, Any]] = field(default_factory=dict)  # policy id -> rollup

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        for sg in d["security_groups"]:
            sg["at_risk"] = sg["ingress"]["exceeds_proposed"] or sg["egress"]["exceeds_proposed"]
        return d


# --------------------------------------------------------------------------- #
# Profiles / sessions
# --------------------------------------------------------------------------- #
def is_valid_profile(name: str) -> bool:
    return name.startswith(PROFILE_PREFIX) and not name.endswith(PROFILE_EXCLUDED_SUFFIXES)


def discover_profiles() -> list[str]:
    """Return locally configured profiles that match the naming policy."""
    all_profiles = boto3.Session().available_profiles
    valid = sorted(p for p in all_profiles if is_valid_profile(p))
    log.debug("Discovered %d valid profiles of %d total", len(valid), len(all_profiles))
    return valid


class DiskCache:
    """Cache for constructs that are globally or regionally unique.

    In-memory for the life of the process; also persisted to a JSON file when
    ``path`` is given.

    Namespaces:
      account:<profile>          -> account id            (global)
      pl:<region>:<pl-id>        -> name/owner/MaxEntries (regionally unique id)
      sg:<region>:<sg-id>        -> name/vpc/owner        (regionally unique id)
    SG *rules* and PL *entries* are never cached: they are what is being reviewed.
    """

    def __init__(self, path: Path | None = None, ttl: int = 0, enabled: bool = True):
        self.path = path
        self.ttl = ttl
        self.enabled = enabled
        self._data: dict[str, dict[str, Any]] = {}
        self._dirty = False
        if enabled and path is not None and path.exists():
            try:
                self._data = json.loads(path.read_text())
                log.debug("Loaded cache %s (%d keys)", path, len(self._data))
            except (OSError, ValueError) as e:
                log.warning("Ignoring unreadable cache %s: %s", path, e)

    def get(self, key: str) -> Any | None:
        if not self.enabled:
            return None
        item = self._data.get(key)
        if not item:
            return None
        if self.ttl and time.time() - item.get("ts", 0) > self.ttl:
            log.debug("Cache expired: %s", key)
            return None
        log.debug("Cache hit: %s", key)
        return item.get("value")

    def set(self, key: str, value: Any) -> None:
        if not self.enabled:
            return
        self._data[key] = {"ts": time.time(), "value": value}
        self._dirty = True

    def save(self) -> None:
        if not (self.enabled and self._dirty and self.path is not None):
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._data, indent=1))
            tmp.replace(self.path)
            log.debug("Saved cache %s (%d keys)", self.path, len(self._data))
        except OSError as e:
            log.warning("Could not write cache %s: %s", self.path, e)
        self._dirty = False


class SessionCache:
    """Caches boto3 sessions, clients and account ids per profile."""

    def __init__(self, region: str, disk: DiskCache | None = None):
        self.region = region
        self.disk = disk or DiskCache()
        self._sessions: dict[str, boto3.Session] = {}
        self._clients: dict[tuple[str, str], Any] = {}
        self._account_by_profile: dict[str, str | None] = {}
        self._profile_by_account: dict[str, str] = {}

    def session(self, profile: str) -> boto3.Session:
        if profile not in self._sessions:
            with _timed("create session profile=%s region=%s", profile, self.region):
                self._sessions[profile] = boto3.Session(profile_name=profile, region_name=self.region)
        return self._sessions[profile]

    def client(self, profile: str, service: str):
        key = (profile, service)
        if key not in self._clients:
            with _timed("create %s client profile=%s", service, profile):
                self._clients[key] = self.session(profile).client(service, config=BOTO_CONFIG)
        return self._clients[key]

    @staticmethod
    def configured_account_id(profile: str) -> str | None:
        """Account id from ~/.aws/config without any network call.

        SSO profiles carry ``sso_account_id``; assumed-role profiles expose the
        account inside ``role_arn``. Returns None when neither is present.
        """
        try:
            cfg = boto3.Session(profile_name=profile)._session.get_scoped_config()
        except (ProfileNotFound, BotoCoreError):
            return None
        acct = cfg.get("sso_account_id")
        if not acct and cfg.get("role_arn"):
            m = re.search(r"arn:aws[^:]*:iam::(\d{12}):", cfg["role_arn"])
            acct = m.group(1) if m else None
        return str(acct) if acct else None

    def account_id(self, profile: str, allow_network: bool = True) -> str | None:
        """Resolve profile -> account id lazily: memory, disk cache, local config,
        then (only if allowed) sts:GetCallerIdentity."""
        if profile in self._account_by_profile and (
            self._account_by_profile[profile] is not None or not allow_network
        ):
            return self._account_by_profile[profile]
        acct = self.disk.get(f"account:{profile}")
        if acct is None:
            acct = self.configured_account_id(profile)
            if acct:
                log.debug("Profile %s -> account %s (from local config)", profile, acct)
        if acct is None and allow_network:
            try:
                with _timed("sts:GetCallerIdentity profile=%s (SSO token refresh may happen here)", profile):
                    acct = self.client(profile, "sts").get_caller_identity()["Account"]
                log.debug("Profile %s -> account %s (from STS)", profile, acct)
                self.disk.set(f"account:{profile}", acct)
            except (ClientError, BotoCoreError, ProfileNotFound) as e:
                log.warning("Profile %s unusable (%s); skipping", profile, e)
                acct = None
        self._account_by_profile[profile] = acct
        if acct and acct not in self._profile_by_account:
            self._profile_by_account[acct] = profile
        return acct

    def profile_for_account(self, account_id: str, candidates: Iterable[str]) -> str | None:
        """Find a profile for an account, just in time. Pass 1 uses only local
        config / cache (no sessions created); pass 2 falls back to STS per
        profile and stops at the first match."""
        if account_id in self._profile_by_account:
            return self._profile_by_account[account_id]
        candidates = list(candidates)
        for p in candidates:
            if self.account_id(p, allow_network=False) == account_id:
                return p
        for p in candidates:
            if self.account_id(p) == account_id:
                return p
        return None


# --------------------------------------------------------------------------- #
# Prefix list helpers
# --------------------------------------------------------------------------- #
class PrefixListResolver:
    """Resolves prefix list MaxEntries, cached per (profile, pl-id)."""

    def __init__(self, cache: SessionCache):
        self.cache = cache
        self._max_entries: dict[str, int] = {}

    def describe(self, profile: str, pl_id: str, use_cache: bool = True) -> dict[str, Any] | None:
        key = f"pl:{self.cache.region}:{pl_id}"
        if use_cache:
            cached = self.cache.disk.get(key)
            if cached is not None:
                return cached
        ec2 = self.cache.client(profile, "ec2")
        try:
            with _timed("ec2:DescribeManagedPrefixLists %s profile=%s", pl_id, profile):
                resp = ec2.describe_managed_prefix_lists(PrefixListIds=[pl_id])
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("InvalidPrefixListID.NotFound", "InvalidPrefixListId.NotFound"):
                return None
            if is_auth_error(e):
                log.warning("Not authorized to describe %s via %s (%s)", pl_id, profile, code)
                return None
            log.error("AWS error %s: %s", code, e.response["Error"]["Message"])
            raise
        pls = resp.get("PrefixLists", [])
        if not pls:
            return None
        pl = pls[0]
        slim = {k: pl.get(k) for k in ("PrefixListId", "PrefixListName", "OwnerId", "MaxEntries", "AddressFamily", "State")}
        self.cache.disk.set(key, slim)
        return slim

    def max_entries(self, profile: str, pl_id: str) -> int:
        """Expanded weight of a PL reference = its MaxEntries."""
        if pl_id in self._max_entries:
            return self._max_entries[pl_id]
        pl = self.describe(profile, pl_id)
        max_entries = pl.get("MaxEntries") if pl else None
        documented = aws_managed_weight(pl.get("PrefixListName")) if pl and pl.get("OwnerId") == "AWS" else None
        if documented is not None:
            # AWS-managed lists consume a documented fixed weight (e.g. S3 = 1).
            weight = documented
            log.debug("PL %s (%s) AWS-managed documented weight=%d", pl_id, pl.get("PrefixListName"), weight)
        elif max_entries is not None:
            weight = int(max_entries)
        else:
            if pl is None:
                log.warning("Could not describe %s via %s (not found or not authorized); using entry count", pl_id, profile)
            else:
                log.warning(
                    "PL %s (%s) has no MaxEntries and no documented weight; using entry count",
                    pl_id, pl.get("PrefixListName"),
                )
            weight = self.entry_count(profile, pl_id) or 1
        self._max_entries[pl_id] = weight
        log.debug("PL %s weight=%d", pl_id, weight)
        return weight

    def entry_count(self, profile: str, pl_id: str) -> int:
        ec2 = self.cache.client(profile, "ec2")
        try:
            paginator = ec2.get_paginator("get_managed_prefix_list_entries")
            with _timed("ec2:GetManagedPrefixListEntries %s profile=%s", pl_id, profile):
                return sum(len(p.get("Entries", [])) for p in paginator.paginate(PrefixListId=pl_id))
        except ClientError as e:
            log.warning("get_managed_prefix_list_entries %s failed: %s", pl_id, e.response["Error"]["Code"])
            return 0

    def associations(self, profile: str, pl_id: str) -> list[dict[str, str]]:
        ec2 = self.cache.client(profile, "ec2")
        paginator = ec2.get_paginator("get_managed_prefix_list_associations")
        out: list[dict[str, str]] = []
        try:
            with _timed("ec2:GetManagedPrefixListAssociations %s profile=%s", pl_id, profile):
                for page in paginator.paginate(PrefixListId=pl_id):
                    out.extend(page.get("PrefixListAssociations", []))
                    log.debug("   associations page: %d so far", len(out))
        except ClientError as e:
            if is_auth_error(e):
                raise SystemExit(
                    f"Profile {profile} is not authorized for ec2:GetManagedPrefixListAssociations on {pl_id}; "
                    "run with --profile <owner-account profile> that has this permission"
                ) from e
            raise
        return out


def find_owner_profile(resolver: PrefixListResolver, pl_id: str, profiles: list[str]) -> tuple[str, dict[str, Any]]:
    """Locate the profile whose account owns the PL. Shared PLs are visible to
    consumers too, so match OwnerId against the profile's account."""
    cache = resolver.cache
    first_seen: tuple[str, dict[str, Any]] | None = None
    for i, p in enumerate(profiles, 1):
        log.debug("Owner search: profile %d/%d %s", i, len(profiles), p)
        pl = resolver.describe(p, pl_id)  # one ec2 call; creates this profile's session only
        if pl is None:
            continue
        owner = pl.get("OwnerId")
        if owner and cache.account_id(p, allow_network=False) == owner:
            return p, pl
        first_seen = first_seen or (p, pl)
        # We now know the owner account: jump straight to its profile if one exists.
        if owner:
            op = cache.profile_for_account(owner, profiles)
            if op:
                log.debug("Owner account %s -> profile %s", owner, op)
                return op, (resolver.describe(op, pl_id) or pl)
            break  # no profile for owner; fall through to consumer fallback
    if first_seen:
        p, pl = first_seen
        log.warning(
            "No profile for owner account %s of %s; using consumer profile %s "
            "(associations may be incomplete)", pl.get("OwnerId"), pl_id, p,
        )
        return p, pl
    raise SystemExit(f"Prefix list {pl_id} not found in any scanned profile: {profiles}")


# --------------------------------------------------------------------------- #
# Security group analysis
# --------------------------------------------------------------------------- #
FM_NAME_PREFIX = "FMManagedSecurityGroup"


def detect_fm(sg: dict[str, Any]) -> tuple[bool, str | None]:
    """Identify Firewall Manager-managed SGs by tag (FMManaged / FMPolicyId) or name."""
    tags = {t.get("Key"): t.get("Value") for t in sg.get("Tags") or []}
    policy = tags.get("FMPolicyId") or tags.get("fmpolicyid")
    managed = str(tags.get("FMManaged", "")).lower() == "true" or (sg.get("GroupName") or "").startswith(FM_NAME_PREFIX)
    if managed and not policy:
        name = sg.get("GroupName") or ""
        policy = name[len(FM_NAME_PREFIX):] or None if name.startswith(FM_NAME_PREFIX) else None
    return managed or bool(policy), policy


def fetch_security_groups(ec2, group_ids: list[str], disk: DiskCache, region: str) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    misses: list[str] = []
    for gid in group_ids:
        cached = disk.get(f"sg:{region}:{gid}")
        if cached is not None:
            out[gid] = cached
        else:
            misses.append(gid)
    log.debug("SG metadata: %d cached, %d to fetch", len(out), len(misses))
    paginator = ec2.get_paginator("describe_security_groups")
    for i in range(0, len(misses), 100):  # API filter cap
        chunk = misses[i : i + 100]
        try:
            with _timed("ec2:DescribeSecurityGroups %d ids", len(chunk)):
                pages = list(paginator.paginate(GroupIds=chunk))
            for page in pages:
                for sg in page.get("SecurityGroups", []):
                    slim = {k: sg.get(k) for k in ("GroupId", "GroupName", "VpcId", "OwnerId")}
                    slim["FMManaged"], slim["FMPolicyId"] = detect_fm(sg)
                    out[sg["GroupId"]] = slim
                    disk.set(f"sg:{region}:{sg['GroupId']}", slim)
        except ClientError as e:
            if is_auth_error(e):
                raise AccountAccessError(f"ec2:DescribeSecurityGroups denied: {e.response['Error']['Code']}") from e
            log.error("describe_security_groups failed: %s", e.response["Error"]["Message"])
            raise
    return out


def fetch_rules(ec2, group_ids: list[str]) -> dict[str, list[dict[str, Any]]]:
    rules: dict[str, list[dict[str, Any]]] = defaultdict(list)
    paginator = ec2.get_paginator("describe_security_group_rules")
    for i in range(0, len(group_ids), 100):
        chunk = group_ids[i : i + 100]
        try:
            with _timed("ec2:DescribeSecurityGroupRules %d groups", len(chunk)):
                for page in paginator.paginate(Filters=[{"Name": "group-id", "Values": chunk}]):
                    for r in page.get("SecurityGroupRules", []):
                        rules[r["GroupId"]].append(r)
        except ClientError as e:
            if is_auth_error(e):
                raise AccountAccessError(f"ec2:DescribeSecurityGroupRules denied: {e.response['Error']['Code']}") from e
            raise
    log.debug("Fetched %d rules across %d groups", sum(len(v) for v in rules.values()), len(rules))
    return rules


def weigh_direction(
    direction: str,
    rules: list[dict[str, Any]],
    resolver: PrefixListResolver,
    profile: str,
    target_pl: str,
    proposed_length: int,
    limit: int,
) -> DirectionUsage:
    u = DirectionUsage(direction=direction)
    target_weight_now = resolver.max_entries(profile, target_pl)
    for r in rules:
        u.rule_count += 1
        pl_id = r.get("PrefixListId")
        if pl_id:
            u.prefix_lists[pl_id] = u.prefix_lists.get(pl_id, 0) + 1
            if pl_id == target_pl:
                u.target_pl_refs += 1
                u.pl_weights[pl_id] = target_weight_now
                u.current_weight += target_weight_now
                u.proposed_weight += proposed_length
            else:
                w = resolver.max_entries(profile, pl_id)
                u.pl_weights[pl_id] = w
                u.current_weight += w
                u.proposed_weight += w
        else:
            u.current_weight += 1
            u.proposed_weight += 1
    u.exceeds_now = u.current_weight > limit
    u.exceeds_proposed = u.proposed_weight > limit
    u.headroom_proposed = limit - u.proposed_weight
    return u


def analyze_account(
    cache: SessionCache,
    resolver: PrefixListResolver,
    account_id: str,
    profile: str | None,
    group_ids: list[str],
    target_pl: str,
    proposed_length: int,
    limit: int,
) -> list[SecurityGroupReport]:
    reports: list[SecurityGroupReport] = []
    if profile is None:
        for gid in group_ids:
            reports.append(
                SecurityGroupReport(
                    account_id=account_id, profile=None, region=cache.region, group_id=gid,
                    group_name="?", vpc_id=None,
                    ingress=DirectionUsage("ingress"), egress=DirectionUsage("egress"),
                    error="no valid profile for account",
                )
            )
        return reports

    log.info("Analyzing %d security group(s) in account %s via %s", len(group_ids), account_id, profile)
    try:
        ec2 = cache.client(profile, "ec2")
        sgs = fetch_security_groups(ec2, group_ids, cache.disk, cache.region)
        rules = fetch_rules(ec2, group_ids)
    except (AccountAccessError, BotoCoreError, ProfileNotFound, ClientError) as e:
        if isinstance(e, ClientError) and not is_auth_error(e):
            raise
        log.error("Account %s via %s: %s - skipping its %d SG(s)", account_id, profile, e, len(group_ids))
        return [
            SecurityGroupReport(
                account_id=account_id, profile=profile, region=cache.region, group_id=gid,
                group_name="?", vpc_id=None,
                ingress=DirectionUsage("ingress"), egress=DirectionUsage("egress"),
                error=f"{profile}: {e}",
            )
            for gid in group_ids
        ]
    for gid in group_ids:
        sg = sgs.get(gid, {})
        sg_rules = rules.get(gid, [])
        ingress = [r for r in sg_rules if not r.get("IsEgress")]
        egress = [r for r in sg_rules if r.get("IsEgress")]
        log.debug("SG %s (%s): %d ingress, %d egress rules", gid, sg.get("GroupName"), len(ingress), len(egress))
        reports.append(
            SecurityGroupReport(
                account_id=account_id,
                profile=profile,
                region=cache.region,
                group_id=gid,
                group_name=sg.get("GroupName") or "?",
                vpc_id=sg.get("VpcId") or None,
                ingress=weigh_direction("ingress", ingress, resolver, profile, target_pl, proposed_length, limit),
                egress=weigh_direction("egress", egress, resolver, profile, target_pl, proposed_length, limit),
                error=None if sg else "security group not found in account",
                fm_managed=bool(sg.get("FMManaged")),
                fm_policy_id=sg.get("FMPolicyId"),
            )
        )
    return reports


# --------------------------------------------------------------------------- #
# Public entry point (kwargs API)
# --------------------------------------------------------------------------- #
def review_prefix_list(
    *,
    pl: str,
    profile: str | None = None,
    proposed_length: int | None = None,
    limit: int = DEFAULT_LIMIT,
    region: str = "us-east-1",
    profiles: list[str] | None = None,
    cache_path: str | os.PathLike | None = None,
    cache_ttl: int = DEFAULT_CACHE_TTL,
    use_cache: bool = True,
) -> PrefixListReport:
    """Evaluate SGs associated with ``pl`` against ``limit`` at ``proposed_length``.

    Keyword arguments:
        pl: Managed prefix list id (pl-xxxx).
        profile: Profile that owns (or can see) the PL. Auto-discovered when None.
        proposed_length: Proposed MaxEntries for the PL. Defaults to current MaxEntries.
        limit: Per-direction security group rule quota (default 100).
        region: Region of the PL and its associated security groups.
        profiles: Explicit list of profiles to scan; defaults to all valid local profiles.
        cache_path: Optional JSON file to persist the metadata cache across runs.
            None (default) keeps the cache in memory for this process only.
        cache_ttl: Seconds before a cached item is refreshed (0 = never expires).
        use_cache: Set False to bypass and not write the cache.
    """
    now = datetime.now(timezone.utc)
    candidates = profiles if profiles is not None else discover_profiles()
    if profile:
        if not is_valid_profile(profile):
            raise SystemExit(f"Profile {profile!r} violates naming policy ({PROFILE_PREFIX}*, not *-priv/*-cpar)")
        candidates = [profile] + [p for p in candidates if p != profile]
    if not candidates:
        raise SystemExit("No valid profiles found (expect hcli-* excluding -priv/-cpar)")
    log.info("Scanning %d profile(s) in %s", len(candidates), region)

    disk = DiskCache(Path(cache_path) if cache_path else None, cache_ttl, enabled=use_cache)
    log.debug("Cache: %s", "disabled" if not use_cache else (disk.path or "in-memory"))
    cache = SessionCache(region, disk)
    resolver = PrefixListResolver(cache)

    try:
        if profile:
            # Target PL is always fetched fresh: its MaxEntries is the subject of review.
            pl_obj = resolver.describe(profile, pl, use_cache=False)
            if pl_obj is None:
                raise SystemExit(f"Prefix list {pl} not visible via profile {profile}")
            owner_profile = profile
        else:
            owner_profile, pl_obj = find_owner_profile(resolver, pl, candidates)
            pl_obj = resolver.describe(owner_profile, pl, use_cache=False) or pl_obj
        return _review(pl, pl_obj, owner_profile, candidates, cache, resolver, proposed_length, limit, region, now)
    finally:
        disk.save()


def _review(
    pl: str,
    pl_obj: dict[str, Any],
    owner_profile: str,
    candidates: list[str],
    cache: SessionCache,
    resolver: PrefixListResolver,
    proposed_length: int | None,
    limit: int,
    region: str,
    now: datetime,
) -> PrefixListReport:
    """Core analysis once the PL and owner profile are resolved."""
    current_entries = resolver.entry_count(owner_profile, pl)
    if pl_obj.get("MaxEntries") is None:
        log.warning("PL %s reports no MaxEntries (AWS-managed?); using entry count %d", pl, current_entries)
    current_max = int(pl_obj.get("MaxEntries") or current_entries)
    resolver._max_entries[pl] = current_max
    if proposed_length is None:
        proposed_length = current_max
    log.info(
        "PL %s (%s) owner=%s max_entries=%d entries=%d proposed=%d limit=%d",
        pl, pl_obj.get("PrefixListName"), pl_obj.get("OwnerId"), current_max,
        current_entries, proposed_length, limit,
    )

    assocs = resolver.associations(owner_profile, pl)
    log.info("Found %d association(s)", len(assocs))
    by_account: dict[str, list[str]] = defaultdict(list)
    for a in assocs:
        rid = a.get("ResourceId", "")
        if rid.startswith("sg-"):
            by_account[a["ResourceOwner"]].append(rid)
        else:
            log.debug("Skipping non-SG association %s", rid)

    sg_reports: list[SecurityGroupReport] = []
    missing: list[str] = []
    for i, (acct, gids) in enumerate(sorted(by_account.items()), 1):
        log.debug("Account %d/%d: %s (%d SGs) - resolving profile", i, len(by_account), acct, len(gids))
        p = cache.profile_for_account(acct, candidates)
        if p is None:
            log.warning("No valid profile maps to account %s (%d SGs)", acct, len(gids))
            missing.append(acct)
        sg_reports.extend(
            analyze_account(cache, resolver, acct, p, sorted(set(gids)), pl, proposed_length, limit)
        )

    sg_reports.sort(key=lambda s: (not s.at_risk, s.account_id, s.group_id))
    fm_policies: dict[str, dict[str, Any]] = {}
    for sg in sg_reports:
        if not sg.fm_managed:
            continue
        key = sg.fm_policy_id or "unknown"
        roll = fm_policies.setdefault(key, {
            "replicas": 0, "accounts": set(), "at_risk": 0, "errors": 0,
            "max_proposed_ingress": 0, "max_proposed_egress": 0,
        })
        roll["replicas"] += 1
        roll["accounts"].add(sg.account_id)
        roll["at_risk"] += int(sg.at_risk)
        roll["errors"] += int(bool(sg.error))
        roll["max_proposed_ingress"] = max(roll["max_proposed_ingress"], sg.ingress.proposed_weight)
        roll["max_proposed_egress"] = max(roll["max_proposed_egress"], sg.egress.proposed_weight)
    for roll in fm_policies.values():
        roll["accounts"] = sorted(roll["accounts"])
        roll["account_count"] = len(roll["accounts"])
    if fm_policies:
        log.info("Firewall Manager: %d policy(ies) across %d replica SG(s)",
                 len(fm_policies), sum(r["replicas"] for r in fm_policies.values()))
    return PrefixListReport(
        generated_at=now.isoformat(timespec="seconds"),
        date=now.strftime("%Y-%m-%d"),
        prefix_list_id=pl,
        prefix_list_name=pl_obj.get("PrefixListName"),
        owner_account=pl_obj.get("OwnerId", "?"),
        owner_profile=owner_profile,
        region=region,
        current_max_entries=current_max,
        current_entry_count=current_entries,
        proposed_length=proposed_length,
        limit=limit,
        profiles_scanned=candidates,
        accounts_without_profile=missing,
        security_groups=sg_reports,
        at_risk_count=sum(1 for s in sg_reports if s.at_risk),
        error_count=sum(1 for s in sg_reports if s.error),
        fm_policies=fm_policies,
    )


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
REPORT_FORMATS = ("json", "md", "csv", "html")
CSV_COLUMNS = (
    "date", "prefix_list_id", "account_id", "profile", "region", "group_id", "group_name", "vpc_id",
    "fm_managed", "fm_policy_id",
    "direction", "rule_count", "target_pl_refs", "current_weight", "proposed_weight",
    "headroom_proposed", "exceeds_now", "exceeds_proposed", "status", "error",
)


def _s(v: Any, default: str = "") -> str:
    """Stringify for report cells; None -> default."""
    return default if v is None else str(v)


def _status(u: DirectionUsage) -> str:
    return "EXCEEDS" if u.exceeds_proposed else ("OVER NOW" if u.exceeds_now else "ok")


def report_rows(report: PrefixListReport) -> list[dict[str, Any]]:
    """Flatten report to one row per SG per direction (error SGs = one row)."""
    rows: list[dict[str, Any]] = []
    base = {"date": report.date, "prefix_list_id": report.prefix_list_id}
    for sg in report.security_groups:
        common = {
            **base, "account_id": _s(sg.account_id, "?"), "profile": _s(sg.profile), "region": _s(sg.region),
            "group_id": _s(sg.group_id, "?"), "group_name": _s(sg.group_name, "?"), "vpc_id": _s(sg.vpc_id),
            "fm_managed": sg.fm_managed, "fm_policy_id": _s(sg.fm_policy_id),
        }
        if sg.error:
            rows.append({**common, "direction": "", "rule_count": "", "target_pl_refs": "",
                         "current_weight": "", "proposed_weight": "", "headroom_proposed": "",
                         "exceeds_now": "", "exceeds_proposed": "", "status": "ERROR", "error": _s(sg.error, "unknown error")})
            continue
        for u in (sg.ingress, sg.egress):
            rows.append({
                **common, "direction": u.direction, "rule_count": u.rule_count,
                "target_pl_refs": u.target_pl_refs, "current_weight": u.current_weight,
                "proposed_weight": u.proposed_weight, "headroom_proposed": u.headroom_proposed,
                "exceeds_now": u.exceeds_now, "exceeds_proposed": u.exceeds_proposed,
                "status": _status(u), "error": "",
            })
    return rows


def render_json(report: PrefixListReport) -> str:
    return json.dumps(report.to_dict(), indent=2, default=str)


def render_csv(report: PrefixListReport) -> str:
    import io

    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_COLUMNS, lineterminator="\n")
    w.writeheader()
    for row in report_rows(report):
        w.writerow(row)
    return buf.getvalue()


def render_markdown(report: PrefixListReport) -> str:
    lines = [
        f"# Prefix list review: {report.prefix_list_id} ({_s(report.prefix_list_name, 'unnamed')})",
        "",
        f"- **Date:** {report.date} (generated {report.generated_at})",
        f"- **Owner account:** {_s(report.owner_account, '?')} via `{_s(report.owner_profile, '?')}`",
        f"- **Region:** {report.region}",
        f"- **Current MaxEntries / entries:** {report.current_max_entries} / {report.current_entry_count}",
        f"- **Proposed length:** {report.proposed_length}",
        f"- **Limit per direction:** {report.limit}",
        f"- **Security groups:** {len(report.security_groups)}  **At risk:** {report.at_risk_count}  **Not evaluated:** {report.error_count}",
        f"- **Profiles scanned:** {', '.join(_s(x) for x in report.profiles_scanned or [])}",
    ]
    if report.accounts_without_profile:
        lines.append(f"- **Accounts without a valid profile:** {', '.join(_s(x) for x in report.accounts_without_profile)}")
    if report.fm_policies:
        lines += ["", "## Firewall Manager policies", "",
                  "| Policy | Replicas | Accounts | At risk | Not evaluated | Max proposed ingress | Max proposed egress |",
                  "|---|---:|---:|---:|---:|---:|---:|"]
        for pid, roll in sorted(report.fm_policies.items()):
            lines.append(f"| {pid} | {roll['replicas']} | {roll['account_count']} | {roll['at_risk']} | {roll['errors']} | "
                         f"{roll['max_proposed_ingress']} | {roll['max_proposed_egress']} |")
    lines += [
        "",
        "## Security groups",
        "",
        "| Account | SG | Name | VPC | FM policy | Dir | Rules | Now | Proposed | Headroom | Status |",
        "|---|---|---|---|---|---|---:|---:|---:|---:|---|",
    ]
    for raw in report_rows(report):
        r = {k: _s(v).replace("|", "\\|") for k, v in raw.items()}
        if r["status"] == "ERROR":
            lines.append(f"| {r['account_id']} | {r['group_id']} | {r['group_name']} | | {r['fm_policy_id']} | | | | | | ERROR: {r['error']} |")
        else:
            lines.append(
                f"| {r['account_id']} | {r['group_id']} | {r['group_name']} | {r['vpc_id']} | {r['fm_policy_id']} | {r['direction']} | "
                f"{r['rule_count']} | {r['current_weight']} | {r['proposed_weight']} | {r['headroom_proposed']} | "
                f"{'**' + r['status'] + '**' if r['status'] != 'ok' else r['status']} |"
            )
    lines.append("")
    lines.append("Weights expand each referenced prefix list to its MaxEntries; CIDR and SG references count 1.")
    return "\n".join(lines) + "\n"


def render_html_report(report: PrefixListReport, theme: str = "dark") -> str:
    return render_html(json.loads(render_json(report)), theme=theme)


RENDERERS = {"json": render_json, "md": render_markdown, "csv": render_csv, "html": render_html_report}


def write_report(report: PrefixListReport, out_dir: Path, formats: Iterable[str] = REPORT_FORMATS,
                 theme: str = "dark") -> list[Path]:
    """Write <out_dir>/<YYYY-MM-DD>/<pl>_<HHMMSS>.{json,md,csv,html}; return paths."""
    ts = datetime.fromisoformat(report.generated_at)
    day_dir = out_dir / report.date
    day_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{report.prefix_list_id}_{ts.strftime('%H%M%S')}"
    paths: list[Path] = []
    for fmt in formats:
        if fmt not in RENDERERS:
            raise SystemExit(f"Unknown report format {fmt!r}; choose from {', '.join(REPORT_FORMATS)}")
        path = day_dir / f"{stem}.{fmt}"
        text = render_html_report(report, theme) if fmt == "html" else RENDERERS[fmt](report)
        path.write_text(text, encoding="utf-8")
        paths.append(path)
    return paths


def print_summary(report: PrefixListReport) -> None:
    print(f"\n=== {report.date}  Prefix list review: {report.prefix_list_id} ({_s(report.prefix_list_name, 'unnamed')}) ===")
    print(
        f"owner={report.owner_account} via {report.owner_profile}  region={report.region}  "
        f"max_entries={report.current_max_entries} entries={report.current_entry_count}  "
        f"proposed={report.proposed_length}  limit/direction={report.limit}"
    )
    print(f"security groups: {len(report.security_groups)}  at risk: {report.at_risk_count}  not evaluated: {report.error_count}")
    if report.accounts_without_profile:
        print(f"accounts without a valid profile: {', '.join(report.accounts_without_profile)}")
    if report.fm_policies:
        print("firewall manager policies:")
        for pid, roll in sorted(report.fm_policies.items()):
            print(f"  {pid}: {roll['replicas']} replicas / {roll['account_count']} accounts, "
                  f"at risk {roll['at_risk']}, not evaluated {roll['errors']}, "
                  f"max proposed in/out {roll['max_proposed_ingress']}/{roll['max_proposed_egress']}")
    hdr = f"{'ACCOUNT':<14} {'SG':<22} {'NAME':<28} {'DIR':<8} {'RULES':>5} {'NOW':>5} {'PROP':>5} {'ROOM':>5}  STATUS"
    print(hdr)
    print("-" * len(hdr))
    for sg in report.security_groups:
        acct, gid = _s(sg.account_id, "?"), _s(sg.group_id, "?")
        name = (("[FM] " if sg.fm_managed else "") + _s(sg.group_name, "?"))[:28]
        if sg.error:
            print(f"{acct:<14} {gid:<22} {name:<28} {'-':<8} {'':>5} {'':>5} {'':>5} {'':>5}  ERROR: {sg.error}")
            continue
        for u in (sg.ingress, sg.egress):
            status = _status(u)
            print(
                f"{acct:<14} {gid:<22} {name:<28} {u.direction:<8} "
                f"{u.rule_count:>5} {u.current_weight:>5} {u.proposed_weight:>5} {u.headroom_proposed:>5}  {status}"
            )
    print()


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--pl", required=True, help="Managed prefix list id (pl-xxxx)")
    p.add_argument("--profile", default=os.getenv("AWS_PROFILE"), help="Profile owning/seeing the PL (auto-discover if omitted)")
    p.add_argument("--proposed-length", type=int, default=_env_int("PL_REVIEW_PROPOSED_LENGTH"), help="Proposed MaxEntries (default: current)")
    p.add_argument("--limit", type=int, default=_env_int("PL_REVIEW_LIMIT", DEFAULT_LIMIT), help=f"SG rules-per-direction quota (default {DEFAULT_LIMIT})")
    p.add_argument("--region", default=os.getenv("AWS_REGION", "us-east-1"))
    p.add_argument("--profiles", nargs="*", help="Explicit profiles to scan (default: all valid local profiles)")
    p.add_argument("--out-dir", default=os.getenv("PL_REVIEW_OUT_DIR", "reports"), help="Report root; files land in <out-dir>/<date>/")
    p.add_argument("--formats", default=os.getenv("PL_REVIEW_FORMATS", ",".join(REPORT_FORMATS)),
                   help="Comma-separated report formats to write (default: json,md,csv,html)")
    p.add_argument("--theme", choices=THEMES, default=os.getenv("PL_REVIEW_THEME", "dark"),
                   help="HTML report theme: dark (default), light, or auto (follow OS); toggle in-page")
    p.add_argument("--json", action="store_true", help="Print JSON report to stdout instead of table")
    p.add_argument("--no-write", action="store_true", help="Do not write report file")
    p.add_argument("--cache-path", default=DEFAULT_CACHE_PATH, help="Persist metadata cache to this JSON file (default: in-memory only)")
    p.add_argument("--cache-ttl", type=int, default=DEFAULT_CACHE_TTL, help="Cache TTL seconds (0 = never expire)")
    p.add_argument("--no-cache", action="store_true", help="Bypass and do not write the cache")
    p.add_argument("-v", "--verbose", "--debug", action="store_true", help="Debug logging: every API call with timing")
    p.add_argument("-q", "--quiet", action="store_true")
    return p.parse_args(argv)


def _env_int(name: str, default: int | None = None) -> int | None:
    v = os.getenv(name)
    return int(v) if v else default


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("botocore").setLevel(logging.INFO)  # shows SSO token loads/refreshes
    elif args.quiet:
        logging.getLogger().setLevel(logging.WARNING)
    log.debug("Using profile=%s region=%s", args.profile or "auto", args.region)

    try:
        report = review_prefix_list(
            pl=args.pl,
            profile=args.profile,
            proposed_length=args.proposed_length,
            limit=args.limit,
            region=args.region,
            profiles=args.profiles,
            cache_path=args.cache_path,
            cache_ttl=args.cache_ttl,
            use_cache=not args.no_cache,
        )
    except ClientError as e:
        log.error("AWS error %s: %s", e.response["Error"]["Code"], e.response["Error"]["Message"])
        return 2

    if not args.no_write:
        formats = [f.strip().lower() for f in args.formats.split(",") if f.strip()]
        for path in write_report(report, Path(args.out_dir), formats, args.theme):
            log.info("Report written to %s", path)
    if args.json:
        print(render_json(report))
    else:
        print_summary(report)
    if report.error_count:
        log.warning("%d security group(s) could not be evaluated; see error rows", report.error_count)
    return 1 if report.at_risk_count else (3 if report.error_count else 0)


if __name__ == "__main__":
    sys.exit(main())
