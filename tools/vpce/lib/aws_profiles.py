"""Derive an AWS profile name from an account ID using ~/.aws/config and ~/.aws/credentials.

A profile maps to an account through ``sso_account_id``, ``aws_account_id`` or the
account in ``role_arn``. Profiles ending in an excluded suffix (default ``-priv``,
``-cpar``) are never picked. When several remain, read-only profiles (``-ro`` etc.)
win; anything still ambiguous is an error rather than a guess.
"""
from __future__ import annotations

import logging
import os
import re
from functools import lru_cache

import botocore.session

log = logging.getLogger("aws_vpce_tools.profiles")

DEFAULT_EXCLUDE_SUFFIXES = ("-priv", "-cpar")
READ_ONLY_SUFFIXES = ("-ro", "-readonly", "-read-only")
_ROLE_ARN_ACCOUNT = re.compile(r"^arn:[^:]+:iam::(\d{12}):")


class AmbiguousProfileError(ValueError):
    pass


def exclude_suffixes() -> tuple[str, ...]:
    raw = os.getenv("VPCE_PROFILE_EXCLUDE_SUFFIXES")
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
    """Profile name -> account ID, for profiles whose account is statically known."""
    profiles = botocore.session.Session().full_config.get("profiles", {})
    out = {}
    for name, cfg in profiles.items():
        acct = profile_account(cfg)
        if acct:
            out[name] = acct
    log.debug("Profiles with a known account: %d of %d", len(out), len(profiles))
    return out


def candidate_profiles(account: str) -> list[str]:
    excluded = exclude_suffixes()
    return sorted(
        name for name, acct in profile_accounts().items() if acct == account and not name.endswith(excluded)
    )


def derive_profile(account: str | None, preferred: str | None = None) -> str | None:
    """Pick the profile for ``account``; None if no profile maps to it.

    ``preferred`` (e.g. --profile / AWS_PROFILE) is kept if it maps to the account.
    """
    if not account:
        return None
    cands = candidate_profiles(account)
    if not cands:
        log.debug("No profile maps to account %s", account)
        return None
    if preferred in cands:
        return preferred
    if len(cands) > 1:
        ro = [c for c in cands if c.endswith(READ_ONLY_SUFFIXES)]
        if len(ro) == 1:
            cands = ro
    if len(cands) > 1:
        raise AmbiguousProfileError(
            f"Several profiles map to account {account}: {', '.join(cands)}. "
            "Pass --vpc-profile / --phz-profile (or --profile) to choose."
        )
    log.debug("Derived profile %s for account %s", cands[0], account)
    return cands[0]
