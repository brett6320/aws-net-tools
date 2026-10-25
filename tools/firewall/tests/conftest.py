import importlib.util
import sys
from pathlib import Path

import pytest
import truststore

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# The tools call truststore.inject_into_ssl() on import, which must happen before boto3/urllib3 are
# imported; inside a test session boto3 is already loaded, and tests never open real TLS connections
# (moto or fakes only), so the injection is disabled here. The --help smoke tests run the real scripts.
truststore.inject_into_ssl = lambda: None

TOOLS = ["fmm_compliance", "fmm_nacl_audit", "fmm_policy_snapshot", "fmm_rule_parity", "nacl_shadow",
         "prefix_list_audit", "sg_access_gap", "sg_migration_check", "sg_quota_audit", "sg_rule_inventory"]

# fmm_rule_parity.py nests same-quote f-strings (PEP 701), a SyntaxError before Python 3.12.
PY312 = sys.version_info >= (3, 12)


def load_tool(name: str):
    """Import a top-level tool script (e.g. sg_quota_audit.py) as a module."""
    if name in sys.modules:
        return sys.modules[name]
    path = ROOT / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    try:
        spec.loader.exec_module(mod)
    except BaseException:
        del sys.modules[name]
        raise
    return mod


ENV_CLEAR = ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN",
             "FMM_REPORT_DIR", "FMM_ADMIN_ACCOUNT", "FMM_SNAPSHOT_DIR", "FMM_NACL_LIMIT", "FMM_NACL_HEADROOM",
             "SG_RULE_LIMIT", "SG_PER_ENI_LIMIT", "SG_RULE_HEADROOM", "SG_ENI_HEADROOM", "PL_HEADROOM",
             "PL_FULL_PCT")


@pytest.fixture(autouse=True)
def aws_env(monkeypatch, tmp_path):
    # Never read the developer's real AWS config/credentials, and keep stray reports in tmp_path.
    cfg = tmp_path / "aws_config"
    cfg.write_text("")
    creds = tmp_path / "aws_credentials"
    creds.write_text("")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(cfg))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(creds))
    for k in ENV_CLEAR:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.chdir(tmp_path)


@pytest.fixture
def aws_profiles(tmp_path):
    """Write profiles into the isolated AWS config (and static test keys into the credentials file).

    profiles: {name: {key: value}}; every profile also gets region us-east-1.
    """
    def write(profiles: dict[str, dict[str, str]]):
        cfg = "".join(f"[profile {n}]\nregion = us-east-1\n" + "".join(f"{k} = {v}\n" for k, v in kv.items())
                      for n, kv in profiles.items())
        (tmp_path / "aws_config").write_text(cfg)
        (tmp_path / "aws_credentials").write_text("".join(
            f"[{n}]\naws_access_key_id = testing\naws_secret_access_key = testing\n" for n in profiles))
    return write


def run_main(mod, monkeypatch, argv: list[str]) -> int:
    """Run a tool's main() (which reads sys.argv) with the given arguments."""
    monkeypatch.setattr(sys, "argv", [f"{mod.__name__}.py", *argv])
    return mod.main()
