"""The one profile guard shared by every tool that picks an AWS profile on its own.

Tools that look inside member accounts choose a local profile by account ID. They must never choose a
privileged or personal one, so every tool asks this module instead of keeping its own suffix list.

Rules:

* ``STRICT_EXCLUDE_SUFFIXES`` always applies. Nothing in this module can remove a suffix from it.
* An environment variable or command-line option can only ADD suffixes (``excluded_suffixes``).
  An empty or blank value adds nothing and is reported with a warning; it never disables the guard.
* Matching is on the end of the profile name, ignoring case.

The guard covers automatic selection. An explicit choice (``--profile``, ``--account-profile``) is
the caller's own decision and each tool keeps whatever semantics it had for that.

The tools are standalone scripts, so they reach this module the way they reach each other's helpers:
by putting ``tools/common`` on ``sys.path`` and importing it by name.
"""
from __future__ import annotations

import logging
import os
from typing import Iterable

log = logging.getLogger("profile_guard")

STRICT_EXCLUDE_SUFFIXES: tuple[str, ...] = ("-priv", "-adm", "-cpar", "-ro")
_warned: set[str] = set()


def parse_suffixes(raw: str | Iterable[str] | None) -> tuple[str, ...]:
    """Normalised (stripped, lower-case, non-empty, unique) suffixes from a comma-separated string or an
    iterable of such strings."""
    if raw is None:
        return ()
    items = raw.split(",") if isinstance(raw, str) else [p for chunk in raw for p in str(chunk).split(",")]
    out: list[str] = []
    for item in items:
        s = item.strip().lower()
        if s and s not in out:
            out.append(s)
    return tuple(out)


def excluded_suffixes(env_var: str | None = None, extra: str | Iterable[str] | None = None) -> tuple[str, ...]:
    """The strict suffixes plus any additions from the environment variable ``env_var`` and ``extra``.

    A set-but-empty ``env_var`` (or ``extra``) is ignored with a warning: it can't turn the guard off.
    """
    added: list[str] = []
    for source, raw in ((f"${env_var}" if env_var else "", os.getenv(env_var) if env_var else None),
                        ("the exclude-suffix option", extra)):
        if raw is None:
            continue
        parsed = parse_suffixes(raw)
        if not parsed and (isinstance(raw, str) or raw):
            if source not in _warned:  # once per source, not once per profile checked
                _warned.add(source)
                log.warning("Ignoring empty %s: the profile guard (%s) always applies", source,
                            ", ".join(STRICT_EXCLUDE_SUFFIXES))
        added.extend(parsed)
    return tuple(dict.fromkeys(STRICT_EXCLUDE_SUFFIXES + tuple(added)))


def is_excluded(profile: str, env_var: str | None = None, extra: str | Iterable[str] | None = None) -> bool:
    """True when ``profile`` ends (ignoring case) in a suffix that must never be picked automatically."""
    return profile.lower().endswith(excluded_suffixes(env_var, extra))


def filter_profiles(names: Iterable[str], env_var: str | None = None,
                    extra: str | Iterable[str] | None = None) -> list[str]:
    """``names`` without the excluded profiles, order kept."""
    suffixes = excluded_suffixes(env_var, extra)
    return [n for n in names if not n.lower().endswith(suffixes)]
