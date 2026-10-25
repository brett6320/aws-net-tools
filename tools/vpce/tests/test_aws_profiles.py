import pytest

from lib import aws_profiles as ap

CONFIG = """
[profile net-ro]
sso_account_id = 111111111111
[profile net-adm]
sso_account_id = 111111111111
[profile net-priv]
sso_account_id = 111111111111
[profile dns-adm]
sso_account_id = 222222222222
[profile dns-cpar]
sso_account_id = 222222222222
[profile hub-role]
role_arn = arn:aws:iam::333333333333:role/Net
source_profile = net-ro
[profile static]
aws_account_id = 444444444444
[profile two-a]
aws_account_id = 555555555555
[profile two-b]
aws_account_id = 555555555555
[profile only-priv-priv]
sso_account_id = 666666666666
[profile nothing]
region = us-east-1
"""


@pytest.fixture
def config(tmp_path, monkeypatch):
    cfg = tmp_path / "config"
    cfg.write_text(CONFIG)
    monkeypatch.setenv("AWS_CONFIG_FILE", str(cfg))
    ap.profile_accounts.cache_clear()


def test_account_sources(config):
    assert ap.profile_accounts()["hub-role"] == "333333333333"
    assert ap.profile_accounts()["static"] == "444444444444"
    assert "nothing" not in ap.profile_accounts()


def test_excludes_priv_and_cpar(config):
    assert ap.candidate_profiles("111111111111") == ["net-adm", "net-ro"]
    assert ap.derive_profile("222222222222") == "dns-adm"
    assert ap.derive_profile("666666666666") is None


def test_read_only_preferred_on_tie(config):
    assert ap.derive_profile("111111111111") == "net-ro"


def test_preferred_kept_if_it_matches(config):
    assert ap.derive_profile("111111111111", preferred="net-adm") == "net-adm"
    assert ap.derive_profile("111111111111", preferred="dns-adm") == "net-ro"


def test_ambiguous_is_error(config):
    with pytest.raises(ap.AmbiguousProfileError, match="two-a, two-b"):
        ap.derive_profile("555555555555")


def test_no_match_or_no_account(config):
    assert ap.derive_profile("999999999999") is None
    assert ap.derive_profile(None) is None


def test_exclude_suffixes_override(config, monkeypatch):
    monkeypatch.setenv("VPCE_PROFILE_EXCLUDE_SUFFIXES", "-ro,-adm")
    assert ap.derive_profile("111111111111") == "net-priv"


def test_session_uses_derived_profile(config):
    from lib.aws_common import AccountSessions

    assert AccountSessions(None, "us-east-1", account="111111111111").profile == "net-ro"
    # explicit side profile wins; --role-name disables derivation
    assert AccountSessions("dns-adm", "us-east-1", account="111111111111").profile == "dns-adm"
    assert AccountSessions(None, "us-east-1", role_name="R", account="111111111111", fallback_profile="static").profile == "static"
