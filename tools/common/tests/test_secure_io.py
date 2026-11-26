import os
import stat
import sys

import pytest

import secure_io

posix = pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")


def mode(p) -> int:
    return stat.S_IMODE(os.stat(p).st_mode)


@pytest.fixture(autouse=True)
def _loose_umask():
    old = os.umask(0o022)
    yield
    os.umask(old)


@posix
def test_write_text_creates_0600_file_and_0700_dirs(tmp_path):
    p = tmp_path / "a" / "b" / "out.txt"
    secure_io.write_private_text(p, "hi")
    assert p.read_text() == "hi"
    assert mode(p) == 0o600
    assert mode(p.parent) == 0o700 and mode(p.parent.parent) == 0o700


@posix
def test_umask_zero_still_private(tmp_path):
    os.umask(0)
    p = tmp_path / "d" / "f.json"
    secure_io.write_private_bytes(p, b"{}")
    assert (mode(p), mode(p.parent)) == (0o600, 0o700)


@posix
def test_existing_looser_file_is_tightened_and_truncated(tmp_path):
    p = tmp_path / "f.txt"
    p.write_text("old old old")
    os.chmod(p, 0o644)
    secure_io.write_private_text(p, "new")
    assert p.read_text() == "new"
    assert mode(p) == 0o600


@posix
def test_preexisting_parent_is_not_chmodded(tmp_path):
    user_dir = tmp_path / "home"
    user_dir.mkdir()
    os.chmod(user_dir, 0o755)
    secure_io.write_private_text(user_dir / "f.txt", "x")
    secure_io.ensure_private_dir(user_dir)
    assert mode(user_dir) == 0o755


@posix
def test_owned_root_subtree_is_tightened_but_not_its_parent(tmp_path):
    top = tmp_path / "reports"
    sub = top / "2026-01-01" / "acct"
    sub.mkdir(parents=True)
    for d in (top, top / "2026-01-01", sub):
        os.chmod(d, 0o755)
    secure_io.write_private_text(sub / "r.html", "x", owned_root=top / "2026-01-01")
    assert mode(sub) == 0o700 and mode(top / "2026-01-01") == 0o700
    assert mode(top) == 0o755


@posix
def test_executable_is_0700(tmp_path):
    p = tmp_path / "restore.plan.sh"
    secure_io.write_private_text(p, "#!/bin/sh\n", executable=True)
    assert mode(p) == 0o700
    secure_io.write_private_text(p, "#!/bin/sh\n")          # rewriting non-executable tightens again
    assert mode(p) == 0o600


@posix
def test_symlinked_dir_is_not_chmodded(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    os.chmod(real, 0o755)
    link = tmp_path / "link"
    link.symlink_to(real)
    secure_io.ensure_private_dir(link, owned_root=link)
    assert mode(real) == 0o755


def test_ensure_dir_on_a_file_raises(tmp_path):
    f = tmp_path / "f"
    f.write_text("x")
    with pytest.raises(FileExistsError):
        secure_io.ensure_private_dir(f)


def test_open_private_rejects_other_modes(tmp_path):
    with pytest.raises(ValueError):
        secure_io.open_private(tmp_path / "x", "a")


def test_csv_newline_and_text_roundtrip(tmp_path):
    p = tmp_path / "x.csv"
    with secure_io.open_private(p, "w", newline="") as fh:
        fh.write("a,b\r\n1,2\r\n")
    assert p.read_bytes() == b"a,b\r\n1,2\r\n"


def test_relative_path_in_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    secure_io.write_private_text("rel.txt", "x")
    assert (tmp_path / "rel.txt").read_text() == "x"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
def test_windows_writes_without_modes(tmp_path):
    p = tmp_path / "w" / "f.txt"
    secure_io.write_private_text(p, "x")
    assert p.read_text() == "x"
