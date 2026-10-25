import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

PROFILES_CONFIG = """
[profile hcli-net-ro]
region = us-east-1
role_arn = arn:aws:iam::123456789012:role/ReadOnly
source_profile = hcli-app-ro
[profile hcli-app-ro]
region = us-east-1
[profile zz-sso-test]
sso_account_id = 999888777666
sso_role_name = ReadOnly
sso_start_url = https://example.awsapps.com/start
sso_region = us-east-1
[profile hcli-app-priv]
region = us-east-1
[profile hcli-x-cpar]
region = us-east-1
[profile bmeier-prd-ro]
region = us-east-1
"""
CREDENTIAL_PROFILES = ["hcli-net-ro", "hcli-app-ro", "hcli-app-priv", "hcli-x-cpar", "bmeier-prd-ro"]


@pytest.fixture(scope="session", autouse=True)
def aws_env(tmp_path_factory):
    """Point boto3 at a throwaway AWS config/credentials pair for the whole run.

    Session-scoped and autouse so it is in place before any test (or the
    ``pl_review`` fixture) imports pl_review or creates a boto3 session; the
    developer's real ~/.aws files are never read.
    """
    import boto3

    d = tmp_path_factory.mktemp("aws")
    cfg = d / "config"
    cfg.write_text(PROFILES_CONFIG)
    cred = d / "credentials"
    cred.write_text("".join(
        f"[{n}]\naws_access_key_id = testing\naws_secret_access_key = testing\n" for n in CREDENTIAL_PROFILES))
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("AWS_CONFIG_FILE", str(cfg))
        mp.setenv("AWS_SHARED_CREDENTIALS_FILE", str(cred))
        mp.setenv("PL_REVIEW_NO_TRUSTSTORE", "1")
        mp.setenv("AWS_ACCESS_KEY_ID", "testing")
        mp.setenv("AWS_SECRET_ACCESS_KEY", "testing")
        for k in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_SESSION_TOKEN", "PL_REVIEW_CACHE_PATH"):
            mp.delenv(k, raising=False)
        # Drop any default session built before the env was isolated.
        mp.setattr(boto3, "DEFAULT_SESSION", None)
        yield d


@pytest.fixture(scope="session")
def pl_review(aws_env):
    """Import pl_review only after the AWS env is isolated (it reads env at import)."""
    import pl_review as mod

    return mod
