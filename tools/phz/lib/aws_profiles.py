"""Derive an AWS profile name from an account ID using ~/.aws/config and ~/.aws/credentials.

A profile maps to an account through ``sso_account_id``, ``aws_account_id`` or the
account in ``role_arn``. Profiles ending in an excluded suffix (``-priv``, ``-adm``, ``-cpar``,
``-ro``, plus any added with ``VPCE_PROFILE_EXCLUDE_SUFFIXES``) are never picked. When several remain, read-only profiles (``-readonly`` etc.)
win; anything still ambiguous is an error rather than a guess.

Commands that change something (the migration planner's script) use the account's
``-adm`` profile instead; see ``priv_profile``.
"""
from __future__ import annotations

import logging
import os
import re
import sys
from functools import lru_cache
from pathlib import Path

import botocore.session

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "common"))
import profile_guard  # noqa: E402

log = logging.getLogger("aws_vpce_tools.profiles")

EXCLUDE_SUFFIXES_ENV = "VPCE_PROFILE_EXCLUDE_SUFFIXES"  # may only add to profile_guard.STRICT_EXCLUDE_SUFFIXES
DEFAULT_PRIV_SUFFIX = "-adm"
READ_ONLY_SUFFIXES = ("-ro", "-readonly", "-read-only")
_ROLE_ARN_ACCOUNT = re.compile(r"^arn:[^:]+:iam::(\d{12}):")


class AmbiguousProfileError(ValueError):
    pass


def is_excluded(name: str) -> bool:
    """True for a profile the tools never pick automatically (the shared guard plus VPCE_PROFILE_EXCLUDE_SUFFIXES)."""
    return profile_guard.is_excluded(name, EXCLUDE_SUFFIXES_ENV)


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
    return sorted(name for name, acct in profile_accounts().items() if acct == account and not is_excluded(name))


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


def priv_suffix() -> str:
    return os.getenv("VPCE_PRIV_PROFILE_SUFFIX") or DEFAULT_PRIV_SUFFIX


def priv_profile(account: str | None, suffix: str | None = None) -> str | None:
    """The profile ending in ``suffix`` (default: env ``VPCE_PRIV_PROFILE_SUFFIX`` or ``-adm``) for ``account``,
    for commands that change something. None when no such profile maps to the account, or several do."""
    if not account:
        return None
    suffix = suffix or priv_suffix()
    cands = sorted(n for n, a in profile_accounts().items() if a == account and n.endswith(suffix))
    if len(cands) > 1:
        log.warning("Several %s profiles map to account %s (%s); not choosing one", suffix, account, ", ".join(cands))
        return None
    return cands[0] if cands else None


def priv_profiles(accounts) -> dict[str, str]:
    """Account -> its ``-adm`` profile, for the accounts that have exactly one."""
    return {a: p for a in sorted(set(accounts)) if (p := priv_profile(a))}
