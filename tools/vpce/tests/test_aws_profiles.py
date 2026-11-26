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
[profile tenant-readonly]
sso_account_id = 777777777777
[profile tenant-other]
sso_account_id = 777777777777
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


def test_excludes_priv_adm_cpar_ro(config):
    assert ap.candidate_profiles("111111111111") == []      # net-ro, net-adm, net-priv
    assert ap.derive_profile("222222222222") is None         # dns-adm, dns-cpar
    assert ap.derive_profile("666666666666") is None
    assert ap.derive_profile("333333333333") == "hub-role"


def test_read_only_preferred_on_tie(config):
    # -ro itself is excluded; the other read-only spellings still win a tie
    assert ap.derive_profile("777777777777") == "tenant-readonly"


def test_preferred_kept_only_if_it_is_a_candidate(config):
    assert ap.derive_profile("555555555555", preferred="two-b") == "two-b"
    # an excluded profile is never kept just because it was preferred
    assert ap.derive_profile("111111111111", preferred="net-adm") is None
    assert ap.derive_profile("222222222222", preferred="dns-adm") is None


def test_ambiguous_is_error(config):
    with pytest.raises(ap.AmbiguousProfileError, match="two-a, two-b"):
        ap.derive_profile("555555555555")


def test_no_match_or_no_account(config):
    assert ap.derive_profile("999999999999") is None
    assert ap.derive_profile(None) is None


def test_exclude_suffixes_override_only_adds(config, monkeypatch):
    monkeypatch.setenv("VPCE_PROFILE_EXCLUDE_SUFFIXES", "-ROLE")
    assert ap.derive_profile("333333333333") is None
    assert ap.derive_profile("444444444444") == "static"


@pytest.mark.parametrize("value", ["", "  ", "-priv", "-ro,-adm"])
def test_exclude_suffixes_override_never_removes_or_disables(config, monkeypatch, value):
    monkeypatch.setenv("VPCE_PROFILE_EXCLUDE_SUFFIXES", value)
    assert ap.candidate_profiles("111111111111") == []
    assert ap.derive_profile("222222222222") is None
    assert ap.derive_profile("666666666666") is None


def test_session_uses_derived_profile(config):
    from lib.aws_common import AccountSessions

    assert AccountSessions(None, "us-east-1", account="444444444444").profile == "static"
    # explicit side profile wins; --role-name disables derivation
    assert AccountSessions("dns-adm", "us-east-1", account="111111111111").profile == "dns-adm"
    assert AccountSessions(None, "us-east-1", role_name="R", account="111111111111", fallback_profile="static").profile == "static"
