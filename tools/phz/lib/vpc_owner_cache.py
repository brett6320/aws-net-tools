"""Local map of VPC -> owner account, kept between runs so owners are only looked up once.

A VPC never changes owner, so entries don't expire. The file lives in the user's cache
directory (not the repository) unless a path is given, and is written owner-only (0600).
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import os
from pathlib import Path

log = logging.getLogger("aws_vpce_tools.owner_cache")

FILENAME = "vpc-owners.json"


def default_path() -> Path:
    if os.name == "nt" and os.getenv("LOCALAPPDATA"):
        base = Path(os.environ["LOCALAPPDATA"])
    else:
        base = Path(os.getenv("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / "aws-net-tools" / FILENAME


class VpcOwnerCache:
    """``{"<region>/<vpc-id>": {"account", "source", "seen"}}`` in a JSON file; ``path=None`` keeps it in memory."""

    def __init__(self, path: Path | None):
        self.path = path
        self._data: dict[str, dict[str, str]] = {}
        self._dirty = False
        if path is not None and path.exists():
            try:
                self._data = json.loads(path.read_text())
                log.debug("Loaded %d VPC owner(s) from %s", len(self._data), path)
            except (OSError, ValueError) as e:
                log.warning("Ignoring unreadable VPC owner map %s: %s", path, e)

    @staticmethod
    def key(region: str, vpc_id: str) -> str:
        return f"{region}/{vpc_id}"

    def __len__(self) -> int:
        return len(self._data)

    def get(self, region: str, vpc_id: str) -> str | None:
        item = self._data.get(self.key(region, vpc_id))
        return item["account"] if item else None

    def put(self, region: str, vpc_id: str, account: str, source: str) -> None:
        k = self.key(region, vpc_id)
        if self._data.get(k, {}).get("account") == account:
            return
        self._data[k] = {"account": account, "source": source, "seen": dt.date.today().isoformat()}
        self._dirty = True

    def save(self) -> None:
        if self.path is None or not self._dirty:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(self._data, f, indent=1, sort_keys=True)
            tmp.replace(self.path)
            log.info("VPC owner map: %d VPC(s) in %s", len(self._data), self.path)
        except OSError as e:
            log.warning("Could not write VPC owner map %s: %s", self.path, e)
        self._dirty = False
