import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def load_tool(name: str):
    path = ROOT / "tools" / name / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(autouse=True)
def aws_env(monkeypatch, tmp_path):
    # Never read the developer's real AWS config/credentials.
    cfg = tmp_path / "aws_config"
    cfg.write_text("")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(cfg))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "aws_credentials"))
    monkeypatch.delenv("VPCE_PROFILE_EXCLUDE_SUFFIXES", raising=False)
    from lib.aws_profiles import profile_accounts

    profile_accounts.cache_clear()
    for k in ("AWS_PROFILE", "VPCE_ACCOUNT", "VPCE_VPC_ACCOUNT", "VPCE_PHZ_ACCOUNT", "VPCE_ROLE_NAME", "VPCE_VPC_PROFILE", "VPCE_PHZ_PROFILE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
