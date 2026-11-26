import logging

import pytest

import profile_guard as pg

ENV = "SOME_TOOL_PROFILE_EXCLUDE_SUFFIXES"


@pytest.fixture(autouse=True)
def _no_env(monkeypatch):
    monkeypatch.delenv(ENV, raising=False)


def test_strict_list_is_the_four_privileged_suffixes():
    assert pg.STRICT_EXCLUDE_SUFFIXES == ("-priv", "-adm", "-cpar", "-ro")
    assert pg.excluded_suffixes() == pg.STRICT_EXCLUDE_SUFFIXES


@pytest.mark.parametrize("name", ["acct-priv", "acct-adm", "acct-cpar", "acct-ro"])
def test_each_strict_suffix_is_excluded(name):
    assert pg.is_excluded(name)


@pytest.mark.parametrize("name", ["acct", "acct-net", "acct-readonly", "adm-acct", "acct-ro-x", "-ro-acct"])
def test_other_names_are_allowed(name):
    assert not pg.is_excluded(name)


@pytest.mark.parametrize("name", ["acct-PRIV", "Acct-Adm", "ACCT-CPAR", "acct-Ro"])
def test_matching_ignores_case(name):
    assert pg.is_excluded(name)


def test_env_override_only_adds(monkeypatch):
    monkeypatch.setenv(ENV, "-net, -Audit")
    assert pg.excluded_suffixes(ENV) == (*pg.STRICT_EXCLUDE_SUFFIXES, "-net", "-audit")
    assert pg.is_excluded("a-NET", ENV) and pg.is_excluded("a-audit", ENV)
    assert pg.is_excluded("a-priv", ENV)
    assert not pg.is_excluded("a-net")           # without the variable named, nothing is added


def test_env_override_naming_strict_suffixes_does_not_duplicate_or_remove(monkeypatch):
    monkeypatch.setenv(ENV, "-priv")             # an operator "narrowing" the list to one suffix
    assert pg.excluded_suffixes(ENV) == pg.STRICT_EXCLUDE_SUFFIXES
    assert pg.is_excluded("a-adm", ENV) and pg.is_excluded("a-ro", ENV) and pg.is_excluded("a-cpar", ENV)


@pytest.mark.parametrize("raw", ["", "   ", ",", " , ,"])
def test_empty_env_override_never_disables_the_guard(monkeypatch, caplog, raw):
    monkeypatch.setenv(ENV, raw)
    with caplog.at_level(logging.WARNING, logger="profile_guard"):
        assert pg.excluded_suffixes(ENV) == pg.STRICT_EXCLUDE_SUFFIXES
        assert pg.is_excluded("a-priv", ENV)
    assert any("Ignoring empty" in r.message for r in caplog.records)


def test_empty_override_warns_once_not_per_profile(monkeypatch, caplog):
    monkeypatch.setenv(ENV, "")
    with caplog.at_level(logging.WARNING, logger="profile_guard"):
        for n in ("a", "b", "c"):
            pg.is_excluded(n, ENV)
    assert len([r for r in caplog.records if "Ignoring empty" in r.message]) == 1


def test_unset_env_does_not_warn(caplog):
    with caplog.at_level(logging.WARNING, logger="profile_guard"):
        pg.excluded_suffixes(ENV)
    assert not caplog.records


def test_extra_option_adds_and_empty_extra_is_ignored(caplog):
    assert pg.is_excluded("a-lab", extra="-lab,-sandbox") and pg.is_excluded("a-sandbox", extra=["-lab", "-sandbox"])
    assert pg.is_excluded("a-ro", extra="-lab")
    with caplog.at_level(logging.WARNING, logger="profile_guard"):
        assert pg.excluded_suffixes(extra="") == pg.STRICT_EXCLUDE_SUFFIXES
    assert caplog.records
    assert pg.excluded_suffixes(extra=None) == pg.STRICT_EXCLUDE_SUFFIXES
    assert pg.excluded_suffixes(extra=[]) == pg.STRICT_EXCLUDE_SUFFIXES


def test_env_and_extra_combine(monkeypatch):
    monkeypatch.setenv(ENV, "-a")
    assert pg.excluded_suffixes(ENV, "-b") == (*pg.STRICT_EXCLUDE_SUFFIXES, "-a", "-b")


def test_filter_profiles_keeps_order_and_drops_excluded():
    names = ["z-net", "a-PRIV", "m-readonly", "b-ro", "c-adm", "d-cpar", "e"]
    assert pg.filter_profiles(names) == ["z-net", "m-readonly", "e"]
    assert pg.filter_profiles(names, extra="-net") == ["m-readonly", "e"]
