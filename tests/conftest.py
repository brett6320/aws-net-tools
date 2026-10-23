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
def aws_env(monkeypatch):
    for k in ("AWS_PROFILE", "VPCE_ACCOUNT", "VPCE_VPC_ACCOUNT", "VPCE_PHZ_ACCOUNT", "VPCE_ROLE_NAME"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
