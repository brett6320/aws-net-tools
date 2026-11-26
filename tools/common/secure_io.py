"""Private output for backups, reports and generated plans.

Backups (topology, account IDs, VIF details) and reports describe a network, so they must not be
readable by other local users whatever the umask is. Every tool that writes one goes through this module:

* directories it creates are mode 0700, files 0600 (0700 for a generated script that must stay executable);
* a file that already exists is tightened to the same mode, not just rewritten (``os.fchmod``);
* a directory that already exists is left alone, unless it lies at or below ``owned_root``: the output root
  the tool manages itself (for example ``reports/``). The directories you point a tool at (the current
  directory, your home, ``--output some/dir``) are never chmod-ed.

POSIX only has these permission bits. On Windows the modes are skipped (the mkdir mode is ignored, there is no
``fchmod``) and the files are written exactly as before.

Standalone tools reach this module by putting ``tools/common`` on ``sys.path`` (see ``profile_guard``).
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import IO

log = logging.getLogger("secure_io")

DIR_MODE = 0o700
FILE_MODE = 0o600
EXEC_MODE = 0o700

_POSIX = os.name == "posix"


def _own(st: os.stat_result) -> bool:
    return not _POSIX or st.st_uid == os.geteuid()


def _tighten_dir(path: str) -> None:
    """chmod 0700 a directory we may change: not a symlink, owned by us."""
    try:
        st = os.lstat(path)
        if os.path.islink(path) or not _own(st) or (st.st_mode & 0o777) == DIR_MODE:
            return
        os.chmod(path, DIR_MODE)
    except OSError as e:
        log.warning("Could not restrict %s to 0700: %s", path, e)


def ensure_private_dir(path: str | os.PathLike, owned_root: str | os.PathLike | None = None) -> Path:
    """Create ``path`` (and missing parents) as 0700 directories; return it.

    Existing directories are not touched, except those at or below ``owned_root`` which are set to 0700 when
    we own them. Raises like ``Path.mkdir`` when ``path`` exists and is not a directory.
    """
    target = os.path.abspath(os.fspath(path))
    if os.path.lexists(target) and not os.path.isdir(target):
        raise FileExistsError(f"{path} exists and is not a directory")
    missing: list[str] = []
    cur = target
    while not os.path.lexists(cur):
        missing.append(cur)
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    for d in reversed(missing):
        try:
            os.mkdir(d, DIR_MODE)
        except FileExistsError:
            continue                         # created by someone else since the check
        if _POSIX:
            _tighten_dir(d)                  # mkdir's mode is masked by the umask; this makes it exact
    if _POSIX and owned_root is not None:
        root = os.path.abspath(os.fspath(owned_root))
        try:
            rel = os.path.relpath(target, root)
        except ValueError:                   # different drives
            rel = os.pardir
        if rel != os.pardir and not rel.startswith(os.pardir + os.sep):
            d = root
            _tighten_dir(d)
            for part in ([] if rel == os.curdir else rel.split(os.sep)):
                d = os.path.join(d, part)
                _tighten_dir(d)
    return Path(target)


def open_private(path: str | os.PathLike, mode: str = "w", *, encoding: str | None = None,
                 newline: str | None = None, executable: bool = False,
                 owned_root: str | os.PathLike | None = None) -> IO:
    """Open ``path`` for writing as a private file, creating its parent directories (0700).

    ``mode`` is "w" or "wb". The file is created 0600 (0700 with ``executable``), truncated if it exists, and
    its mode is set explicitly so an existing file with looser permissions is tightened too.
    """
    if mode not in ("w", "wb"):
        raise ValueError(f"open_private writes only ('w' or 'wb'), not {mode!r}")
    ensure_private_dir(os.path.dirname(os.path.abspath(os.fspath(path))), owned_root)
    file_mode = EXEC_MODE if executable else FILE_MODE
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, file_mode)
    try:
        if _POSIX:
            try:
                os.fchmod(fd, file_mode)
            except PermissionError as e:     # a file we can write but don't own
                log.warning("Could not restrict %s to %04o: %s", path, file_mode, e)
        return os.fdopen(fd, mode, encoding=None if mode == "wb" else (encoding or "utf-8"),
                         newline=None if mode == "wb" else newline)
    except BaseException:
        os.close(fd)
        raise


def write_private_text(path: str | os.PathLike, text: str, *, encoding: str = "utf-8", executable: bool = False,
                       owned_root: str | os.PathLike | None = None) -> Path:
    with open_private(path, "w", encoding=encoding, executable=executable, owned_root=owned_root) as fh:
        fh.write(text)
    return Path(path)


def write_private_bytes(path: str | os.PathLike, data: bytes, *, executable: bool = False,
                        owned_root: str | os.PathLike | None = None) -> Path:
    with open_private(path, "wb", executable=executable, owned_root=owned_root) as fh:
        fh.write(data)
    return Path(path)
