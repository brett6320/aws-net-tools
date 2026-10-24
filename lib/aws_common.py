"""Shared helpers for the aws-vpce-tools suite.

Covers: PKI truststore setup, logging, multi-account session handling,
VPC ID/ARN parsing, hosted-zone ID normalisation, tag filters and output
rendering. Import this module before creating any boto3 clients.
"""
from __future__ import annotations

import argparse
import csv
import fnmatch
import io
import json
import logging
import os
import re
import ssl
import sys
from dataclasses import asdict, dataclass, is_dataclass
from typing import Any, Iterable, Sequence

log = logging.getLogger("aws_vpce_tools")


def _inject_truststore() -> None:
    """Use the OS certificate store; on Linux fall back to certifi if no CA bundle."""
    if "urllib3" in sys.modules:
        # Injecting after urllib3 has captured ssl.SSLContext causes infinite recursion
        # in SSLContext.options; only possible when this module is imported late.
        log.warning("urllib3 already imported; skipping truststore injection (import lib.aws_common first)")
        return
    if sys.platform.startswith("linux"):
        paths = ssl.get_default_verify_paths()
        has_bundle = any(p and os.path.exists(p) for p in (paths.cafile, paths.capath))
        if not has_bundle:
            log.warning("System CA bundle not found; falling back to certifi (install ca-certificates)")
            return
    try:
        import truststore

        truststore.inject_into_ssl()
    except ImportError:  # pragma: no cover - dependency is in requirements.txt
        log.warning("truststore not installed; using default certificate bundle")


_inject_truststore()

import boto3  # noqa: E402  (must follow truststore injection)
from botocore.config import Config  # noqa: E402
from botocore.exceptions import ClientError  # noqa: E402

from lib.aws_profiles import derive_profile  # noqa: E402

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover
    pass

BOTO_CONFIG = Config(retries={"max_attempts": 5, "mode": "adaptive"})
DEFAULT_REGION = "us-east-1"


# --------------------------------------------------------------------------- logging


def configure_logging(verbose: bool = False, quiet: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.WARNING if quiet else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stderr,
    )
    logging.getLogger().setLevel(level)
    if not verbose:
        for noisy in ("botocore", "boto3", "urllib3"):
            logging.getLogger(noisy).setLevel(logging.WARNING)


def log_client_error(e: ClientError, context: str = "") -> None:
    err = e.response.get("Error", {})
    log.error("AWS error %s%s: %s", err.get("Code"), f" ({context})" if context else "", err.get("Message"))


# --------------------------------------------------------------------------- argparse


def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--profile", default=os.getenv("AWS_PROFILE"), help="AWS profile (default: AWS_PROFILE / default chain)")
    parser.add_argument("--region", default=os.getenv("AWS_REGION", DEFAULT_REGION), help="AWS region (default: AWS_REGION or us-east-1)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    parser.add_argument("-q", "--quiet", action="store_true", help="Warnings/errors only")


def add_account_args(parser: argparse.ArgumentParser) -> None:
    g = parser.add_argument_group(
        "accounts",
        "--account applies to both the VPC and PHZ side. --vpc-account / --phz-account override it per side. "
        "Credentials: --vpc-profile / --phz-profile if given; else with --role-name, assume "
        "arn:aws:iam::<account>:role/<role-name> from --profile; else a profile derived from the account ID in "
        "~/.aws/config (sso_account_id / aws_account_id / role_arn; names ending -priv or -cpar are skipped, "
        "-ro preferred on ties); else --profile / default chain.",
    )
    g.add_argument("--account", default=os.getenv("VPCE_ACCOUNT"), help="Account ID used for both VPCs and PHZs")
    g.add_argument("--vpc-account", default=os.getenv("VPCE_VPC_ACCOUNT"), help="Account ID that owns the VPC(s)")
    g.add_argument("--phz-account", default=os.getenv("VPCE_PHZ_ACCOUNT"), help="Account ID that owns the PHZ(s)")
    g.add_argument("--vpc-profile", default=os.getenv("VPCE_VPC_PROFILE"), help="AWS profile for the VPC account")
    g.add_argument("--phz-profile", default=os.getenv("VPCE_PHZ_PROFILE"), help="AWS profile for the PHZ account")
    g.add_argument("--role-name", default=os.getenv("VPCE_ROLE_NAME"), help="Role to assume in target accounts")
    g.add_argument("--external-id", default=os.getenv("VPCE_EXTERNAL_ID"), help="ExternalId for --role-name")


def add_output_args(parser: argparse.ArgumentParser, default: str = "table") -> None:
    parser.add_argument("--output", "-o", choices=("table", "json", "csv"), default=default, help=f"Output format (default: {default})")
    parser.add_argument("--json", dest="output", action="store_const", const="json", help="Shortcut for --output json")


# --------------------------------------------------------------------------- sessions


ACCOUNT_RE = re.compile(r"^\d{12}$")


def validate_account(value: str | None, flag: str) -> str | None:
    if value is None or value == "":
        return None
    value = value.strip()
    if not ACCOUNT_RE.match(value):
        raise ValueError(f"{flag}: '{value}' is not a 12-digit AWS account ID")
    return value


class AccountSessions:
    """Hands out boto3 sessions for a given account.

    Credential resolution for an account, in order:

    1. ``profile`` given explicitly for this side (--vpc-profile / --phz-profile)
    2. ``role_name`` set: assume arn:aws:iam::<account>:role/<role_name> from the base
       credentials (``fallback_profile``) whenever the caller isn't already in the account
    3. otherwise a profile derived from the account ID (see lib.aws_profiles)
    4. otherwise ``fallback_profile`` (--profile / AWS_PROFILE / default chain)

    The account behind the chosen credentials is always checked; a mismatch is an
    error — we fail closed rather than query the wrong account.
    """

    def __init__(
        self,
        profile: str | None,
        region: str,
        role_name: str | None = None,
        external_id: str | None = None,
        label: str = "",
        account: str | None = None,
        fallback_profile: str | None = None,
    ) -> None:
        self.region = region
        self.role_name = role_name
        self.external_id = external_id
        self.label = label
        self.explicit_profile = profile
        self.fallback_profile = fallback_profile
        self.profile = profile or self._derive(account) or fallback_profile
        if self.profile and self.profile != profile and self.profile != fallback_profile:
            log.info("%s: using profile %s for account %s", label or "Session", self.profile, account)
        self._base = boto3.Session(profile_name=self.profile, region_name=region)
        self._caller: str | None = None
        self._cache: dict[str, boto3.Session] = {}

    def _derive(self, account: str | None) -> str | None:
        if self.role_name:
            return None
        return derive_profile(account, preferred=self.fallback_profile)

    @property
    def caller_account(self) -> str:
        if self._caller is None:
            ident = self._base.client("sts", config=BOTO_CONFIG).get_caller_identity()
            self._caller = ident["Account"]
            log.debug("%s credentials: profile=%s account=%s arn=%s", self.label or "base", self.profile or "default", self._caller, ident["Arn"])
        return self._caller

    def for_account(self, account: str | None) -> boto3.Session:
        if account is None or account == self.caller_account:
            return self._base
        if account in self._cache:
            return self._cache[account]
        if self.role_name:
            sess = self._assume(account)
        else:
            derived = self._derive(account)
            if not derived:
                raise PermissionError(
                    f"{self.label or 'Session'} credentials (profile={self.profile or 'default'}) are for account "
                    f"{self.caller_account}, but account {account} was requested and no profile maps to it. "
                    "Use a matching profile or --role-name."
                )
            log.info("%s: using profile %s for account %s", self.label or "Session", derived, account)
            sess = boto3.Session(profile_name=derived, region_name=self.region)
            actual = sess.client("sts", config=BOTO_CONFIG).get_caller_identity()["Account"]
            if actual != account:
                raise PermissionError(f"Profile {derived} is configured for {account} but authenticates as {actual}")
        self._cache[account] = sess
        return sess

    def _assume(self, account: str) -> boto3.Session:
        role_arn = f"arn:{self.partition}:iam::{account}:role/{self.role_name}"
        log.debug("Assuming %s", role_arn)
        params: dict[str, Any] = {"RoleArn": role_arn, "RoleSessionName": "aws-vpce-tools"}
        if self.external_id:
            params["ExternalId"] = self.external_id
        creds = self._base.client("sts", config=BOTO_CONFIG).assume_role(**params)["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=self.region,
        )

    @property
    def partition(self) -> str:
        return self._base.get_partition_for_region(self.region)

    def client(self, service: str, account: str | None = None, region: str | None = None):
        return self.for_account(account).client(service, region_name=region or self.region, config=BOTO_CONFIG)


@dataclass
class AccountContext:
    vpc_account: str | None
    phz_account: str | None
    vpc_profile: str | None  # explicit --vpc-profile only
    phz_profile: str | None  # explicit --phz-profile only
    profile: str | None  # --profile / AWS_PROFILE fallback
    role_name: str | None
    external_id: str | None
    region: str

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> "AccountContext":
        shared = validate_account(args.account, "--account")
        vpc_acct = validate_account(args.vpc_account, "--vpc-account") or shared
        phz_acct = validate_account(args.phz_account, "--phz-account") or shared
        return cls(
            vpc_account=vpc_acct,
            phz_account=phz_acct,
            vpc_profile=args.vpc_profile,
            phz_profile=args.phz_profile,
            profile=args.profile,
            role_name=args.role_name,
            external_id=args.external_id,
            region=args.region,
        )

    def vpc_sessions(self) -> AccountSessions:
        return AccountSessions(
            self.vpc_profile, self.region, self.role_name, self.external_id,
            label="VPC-side", account=self.vpc_account, fallback_profile=self.profile,
        )

    def phz_sessions(self) -> AccountSessions:
        return AccountSessions(
            self.phz_profile, self.region, self.role_name, self.external_id,
            label="PHZ-side", account=self.phz_account, fallback_profile=self.profile,
        )


# --------------------------------------------------------------------------- VPC refs

VPC_ID_RE = re.compile(r"^vpc-(?:[0-9a-f]{8}|[0-9a-f]{17})$")
VPC_ARN_RE = re.compile(r"^arn:(aws|aws-cn|aws-us-gov|aws-iso[a-z-]*):ec2:([a-z0-9-]+):(\d{12}):vpc/(vpc-[0-9a-f]+)$")


@dataclass(frozen=True)
class VpcRef:
    vpc_id: str
    region: str | None = None
    account: str | None = None

    def with_defaults(self, region: str | None, account: str | None) -> "VpcRef":
        return VpcRef(self.vpc_id, self.region or region, self.account or account)

    def __str__(self) -> str:
        return f"{self.vpc_id} ({self.account or '?'}/{self.region or '?'})"


def parse_vpc_ref(value: str, default_region: str | None = None, default_account: str | None = None) -> VpcRef:
    """Parse a VPC given as an ID (vpc-0abc...) or ARN (arn:aws:ec2:<region>:<acct>:vpc/vpc-...).

    ARN-supplied region/account win over defaults, but an ARN account that conflicts
    with an explicitly-supplied VPC account is rejected.
    """
    value = value.strip()
    m = VPC_ARN_RE.match(value)
    if m:
        _, region, account, vpc_id = m.groups()
        if not VPC_ID_RE.match(vpc_id):
            raise ValueError(f"Invalid VPC ID in ARN: {value}")
        if default_account and account != default_account:
            raise ValueError(f"VPC ARN {value} is in account {account}, but VPC account {default_account} was specified")
        return VpcRef(vpc_id, region, account)
    if VPC_ID_RE.match(value):
        return VpcRef(value, default_region, default_account)
    raise ValueError(f"'{value}' is not a VPC ID (vpc-xxxxxxxx) or VPC ARN")


def parse_vpc_refs(values: Iterable[str], default_region: str | None, default_account: str | None) -> list[VpcRef]:
    refs: list[VpcRef] = []
    for raw in values:
        for item in split_csv(raw):
            ref = parse_vpc_ref(item, default_region, default_account)
            if ref not in refs:
                refs.append(ref)
    return refs


def split_csv(value: str) -> list[str]:
    return [p.strip() for p in value.split(",") if p.strip()]


# --------------------------------------------------------------------------- hosted zones

ZONE_ID_RE = re.compile(r"^[0-9A-Z]{1,32}$")  # real IDs start with Z; kept loose for emulators


def normalize_zone_id(value: str) -> str:
    """Accept Z123, /hostedzone/Z123 or arn:aws:route53:::hostedzone/Z123."""
    v = value.strip()
    if v.startswith("arn:"):
        v = v.split(":", 5)[-1]
    v = v.rsplit("/", 1)[-1]
    if not ZONE_ID_RE.match(v):
        raise ValueError(f"'{value}' is not a Route 53 hosted zone ID or ARN")
    return v


def zone_name(name: str) -> str:
    return name.rstrip(".").lower()


# --------------------------------------------------------------------------- tag filters


@dataclass(frozen=True)
class TagFilter:
    """Key=V1,V2 (any of the values; '*' and '?' wildcards allowed) or Key (key present)."""

    key: str
    values: tuple[str, ...] | None = None

    def matches(self, tags: dict[str, str]) -> bool:
        if self.key not in tags:
            return False
        if self.values is None:
            return True
        return any(fnmatch.fnmatchcase(tags[self.key], v) for v in self.values)

    def to_ec2_filter(self) -> dict[str, Any]:
        if self.values is None:
            return {"Name": "tag-key", "Values": [self.key]}
        return {"Name": f"tag:{self.key}", "Values": list(self.values)}


def parse_tag_filters(values: Sequence[str] | None) -> list[TagFilter]:
    filters = []
    for raw in values or []:
        if "=" in raw:
            k, v = raw.split("=", 1)
            vals = tuple(split_csv(v))
            if not k or not vals:
                raise ValueError(f"Invalid tag filter '{raw}' (expected Key=Value[,Value2] or Key)")
            filters.append(TagFilter(k.strip(), vals))
        else:
            if not raw.strip():
                raise ValueError("Empty tag filter")
            filters.append(TagFilter(raw.strip()))
    return filters


def tags_to_dict(tags: list[dict[str, str]] | None) -> dict[str, str]:
    return {t["Key"]: t["Value"] for t in (tags or [])}


def tags_match(tags: dict[str, str], include: Sequence[TagFilter], exclude: Sequence[TagFilter] = ()) -> bool:
    return all(f.matches(tags) for f in include) and not any(f.matches(tags) for f in exclude)


# --------------------------------------------------------------------------- output


def _plain(obj: Any) -> Any:
    if is_dataclass(obj) and not isinstance(obj, type):
        return asdict(obj)
    return obj


def _cell(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, (list, tuple)):
        return ",".join(_cell(x) for x in v)
    if isinstance(v, dict):
        return ",".join(f"{k}={_cell(x)}" for k, x in v.items())
    return str(v)


def render(rows: Sequence[Any], columns: Sequence[str], fmt: str, stream=None) -> None:
    """Render rows (dicts/dataclasses) as table, csv or json to stdout."""
    stream = stream or sys.stdout
    data = [_plain(r) for r in rows]
    if fmt == "json":
        json.dump(data, stream, indent=2, default=str)
        stream.write("\n")
        return
    if fmt == "csv":
        w = csv.writer(stream)
        w.writerow(columns)
        for r in data:
            w.writerow([_cell(r.get(c)) for c in columns])
        return
    table = [[_cell(r.get(c)) for c in columns] for r in data]
    widths = [max([len(c)] + [len(row[i]) for row in table]) for i, c in enumerate(columns)]
    buf = io.StringIO()
    buf.write("  ".join(c.upper().ljust(widths[i]) for i, c in enumerate(columns)).rstrip() + "\n")
    buf.write("  ".join("-" * w for w in widths) + "\n")
    for row in table:
        buf.write("  ".join(v.ljust(widths[i]) for i, v in enumerate(row)).rstrip() + "\n")
    stream.write(buf.getvalue())
    if not data:
        stream.write("(no results)\n")
