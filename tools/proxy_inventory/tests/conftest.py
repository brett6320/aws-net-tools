import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def aws_env(monkeypatch, tmp_path):
    # Never read the developer's real AWS config/credentials or their VPC owner map.
    cfg = tmp_path / "aws_config"
    cfg.write_text("")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(cfg))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "aws_credentials"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "cache"))
    for k in ("AWS_PROFILE", "PROXY_INV_CACHE", "OU_VPCS_CACHE", "PROXY_INV_OU", "PROXY_INV_REGIONS",
              "PROXY_INV_KEY_TAG", "PROXY_INV_WORKERS", "PROXY_INV_REPORTS_DIR", "PROXY_INV_PROFILE_EXCLUDE_SUFFIXES"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    import pi_core

    pi_core.profile_accounts.cache_clear()
    yield
    pi_core.profile_accounts.cache_clear()


@pytest.fixture
def aws_config(tmp_path):
    """Write ~/.aws/config profiles: {name: account}."""

    def write(profiles: dict[str, str]) -> None:
        import pi_core

        lines = []
        for name, acct in profiles.items():
            lines += [f"[profile {name}]", f"sso_account_id = {acct}", "region = us-east-1", ""]
        (tmp_path / "aws_config").write_text("\n".join(lines))
        pi_core.profile_accounts.cache_clear()

    return write
