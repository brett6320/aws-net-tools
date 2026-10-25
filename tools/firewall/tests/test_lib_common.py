import argparse
import csv
import datetime as dt
import json
import re
from types import SimpleNamespace

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from lib import accounts as acc
from lib import output
from lib.aws_common import _g, err_text, get_client, get_policy, list_policies, normalize_proto, resolve_regions


# --------------------------------------------------------------------------- #
# aws_common
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("raw,norm", [(None, "any"), ("-1", "any"), ("ALL", "any"), (" ip ", "any"), ("any", "any"),
                                      ("6", "tcp"), (17, "udp"), ("1", "icmp"), ("58", "icmpv6"), ("TCP", "tcp"),
                                      ("50", "50"), ("gre", "gre")])
def test_normalize_proto(raw, norm):
    assert normalize_proto(raw) == norm


def test_g_treats_null_and_missing_as_default():
    assert _g(None, "k", []) == []
    assert _g({}, "k", "d") == "d"
    assert _g({"k": None}, "k", "d") == "d"
    assert _g({"k": 0}, "k", "d") == 0
    assert _g({"k": []}, "k", "d") == []


def test_err_text():
    e = ClientError({"Error": {"Code": "AccessDenied", "Message": "nope"}}, "GetThing")
    assert err_text(e) == "AccessDenied: nope"
    assert err_text(ValueError("bad")) == "ValueError: bad"


def test_resolve_regions_args_and_env(monkeypatch):
    assert resolve_regions(None, ["us-east-1, eu-west-1", "us-east-1", " ", "ca-central-1"], False) == \
        ["us-east-1", "eu-west-1", "ca-central-1"]
    monkeypatch.setenv("AWS_REGION", "us-west-2, ap-south-1")
    assert resolve_regions(None, None, False) == ["us-west-2", "ap-south-1"]
    monkeypatch.delenv("AWS_REGION")
    assert resolve_regions(None, [], False) == ["us-east-1"]


def test_resolve_regions_all_regions_moto():
    with mock_aws():
        regions = resolve_regions(None, ["ignored-1"], True, service="ec2")
    assert "us-east-1" in regions and regions == sorted(regions) and "ignored-1" not in regions


class FakeFms:
    def __init__(self, pages, policies=None):
        self.pages, self.policies = pages, policies or {}

    def get_paginator(self, op):
        assert op == "list_policies"
        return SimpleNamespace(paginate=lambda: iter(self.pages))

    def get_policy(self, PolicyId):
        return {"Policy": self.policies[PolicyId]}


def test_list_and_get_policy():
    fms = FakeFms([{"PolicyList": [{"PolicyId": "p1"}]}, {"PolicyList": None}, {}, {"PolicyList": [{"PolicyId": "p2"}]}],
                  {"p1": {"PolicyId": "p1", "PolicyName": "one"}})
    assert [p["PolicyId"] for p in list_policies(fms)] == ["p1", "p2"]
    assert get_policy(fms, "p1") == {"PolicyId": "p1", "PolicyName": "one"}


def test_get_client_uses_adaptive_retries():
    c = get_client("ec2", boto3.Session(region_name="eu-west-1"))
    assert c.meta.region_name == "eu-west-1"
    assert c.meta.config.retries["mode"] == "adaptive"
    assert c.meta.config.retries["total_max_attempts"] == 6   # max_attempts=5 retries + the first call


# --------------------------------------------------------------------------- #
# output
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("text,slug", [("prod / acct:1", "prod_acct_1"), ("", "all"), ("///", "all"),
                                       ("a.b-c_d", "a.b-c_d"), ("x" * 100, "x" * 60)])
def test_slugify(text, slug):
    assert output.slugify(text) == slug


def test_slugify_limit():
    assert output.slugify("abcdef", limit=3) == "abc"


def out_args(tmp_path, **kw):
    return argparse.Namespace(**{"no_save": False, "out_dir": str(tmp_path / "reports"), "json_out": None,
                                 "csv_out": None, "html_out": None, **kw})


def test_report_paths_auto(tmp_path):
    paths = output.report_paths(out_args(tmp_path), "sg_quota_audit", "sgquota 1/2")
    day = dt.datetime.now().strftime("%Y-%m-%d")
    for ext in ("json", "csv", "html"):
        assert re.fullmatch(rf"{re.escape(str(tmp_path))}/reports/sg_quota_audit/{day}/\d{{6}}_sgquota_1_2\.{ext}",
                            paths[ext]), paths[ext]


def test_report_paths_explicit_and_no_save(tmp_path):
    paths = output.report_paths(out_args(tmp_path, no_save=True, csv_out="x.csv"), "t", "s")
    assert paths == {"json": None, "csv": "x.csv", "html": None}
    paths = output.report_paths(out_args(tmp_path, html_out="r.html"), "t", "s")
    assert paths["html"] == "r.html" and paths["json"].endswith("_s.json")


def test_write_csv_and_json(tmp_path):
    p = tmp_path / "deep" / "dir" / "out.csv"
    output.write_csv(p, [{"a": 1, "b": ["x", 2], "extra": "ignored"}, {"a": "", "b": []}], ["a", "b"])
    with open(p, newline="", encoding="utf-8") as fh:
        assert list(csv.reader(fh)) == [["a", "b"], ["1", "x; 2"], ["", ""]]
    j = tmp_path / "j" / "out.json"
    output.write_json(j, {"when": dt.date(2026, 1, 2), "n": 1})
    assert json.loads(j.read_text()) == {"when": "2026-01-02", "n": 1}
    t = tmp_path / "t" / "r.html"
    output.write_text(t, "<p>hi</p>")
    assert t.read_text() == "<p>hi</p>"


def test_exit_code():
    F = lambda s: SimpleNamespace(severity=s)  # noqa: E731
    assert output.exit_code([]) == 0
    assert output.exit_code([F("info"), F("info")]) == 0
    assert output.exit_code([F("info"), F("warn")]) == 1
    assert output.exit_code([F("error")]) == 1
    assert output.exit_code([object()]) == 0


def test_print_saved(capsys):
    output.print_saved({"html": "a.html", "csv": None, "json": "a.json"})
    assert capsys.readouterr().out == "\nSaved:\n  a.html\n  a.json\n"
    output.print_saved({"html": None, "csv": None, "json": None})
    assert capsys.readouterr().out == ""


def test_add_output_args_defaults(monkeypatch):
    monkeypatch.setenv("FMM_REPORT_DIR", "/tmp/elsewhere")
    p = argparse.ArgumentParser()
    output.add_output_args(p)
    a = p.parse_args(["--json", "-q"])
    assert (a.json, a.quiet, a.verbose, a.no_save, a.out_dir) == (True, True, False, False, "/tmp/elsewhere")


def test_setup_logging():
    import logging
    root = logging.getLogger()
    old = root.level
    try:
        output.setup_logging(SimpleNamespace(verbose=True, quiet=False))
        assert root.level == logging.DEBUG
        output.setup_logging(SimpleNamespace(verbose=False, quiet=True))
        assert root.level == logging.WARNING
    finally:
        root.setLevel(old)


# --------------------------------------------------------------------------- #
# accounts
# --------------------------------------------------------------------------- #
PROFILES = {
    "a-ro": {"sso_account_id": "111111111111"},
    "a-admin": {"sso_account_id": "111111111111"},
    "a-priv": {"sso_account_id": "111111111111"},
    "b-CPAR": {"aws_account_id": "222222222222"},
    "b-ro": {"aws_account_id": "222222222222"},
    "c-role": {"role_arn": "arn:aws:iam::333333333333:role/ReadOnly", "source_profile": "a-ro"},
    "gov-role": {"role_arn": "arn:aws-us-gov:iam::444444444444:role/ReadOnly", "source_profile": "a-ro"},
    "bad-role": {"role_arn": "not-an-arn", "source_profile": "a-ro"},
    "no-account": {},
}


def test_profile_account_map_excludes_suffixes(aws_profiles):
    aws_profiles(PROFILES)
    assert acc.profile_account_map(["-priv", "-cpar"]) == {
        "111111111111": ["a-admin", "a-ro"],
        "222222222222": ["b-ro"],
        "333333333333": ["c-role"],
        "444444444444": ["gov-role"],
    }
    assert "a-priv" in acc.profile_account_map([""])["111111111111"]   # blank suffixes exclude nothing


def test_pick_profile():
    pmap = {"1": ["x"], "2": ["y", "z"]}
    assert acc.pick_profile("1", pmap, {}) == ("x", "")
    profile, note = acc.pick_profile("2", pmap, {})
    assert profile == "y" and "multiple profiles" in note
    assert acc.pick_profile("2", pmap, {"2": "forced"}) == ("forced", "override")
    assert acc.pick_profile("3", pmap, {}) == (None, "no local profile")


def acct_args(**kw):
    return argparse.Namespace(**{"profile": None, "account": None, "all_accounts": False, "account_profile": None,
                                 "exclude_profile_suffix": "-priv,-cpar", "admin_account": None, **kw})


def test_profile_lookup(aws_profiles):
    aws_profiles({"a-ro": {"sso_account_id": "111111111111"}})
    pmap, overrides = acc.profile_lookup(acct_args(account_profile=["9=p=q"]))
    assert pmap == {"111111111111": ["a-ro"]} and overrides == {"9": "p=q"}


@pytest.fixture
def fake_caller(monkeypatch):
    who = {None: "000000000000", "a-ro": "111111111111", "a-admin": "111111111111", "b-ro": "222222222222",
           "c-role": "999999999999", "gov-role": "444444444444"}

    def caller(profile):
        if profile == "broken":
            raise ClientError({"Error": {"Code": "ExpiredToken", "Message": "expired"}}, "GetCallerIdentity")
        return who[profile]
    monkeypatch.setattr(acc, "caller_account", caller)


def test_select_accounts(aws_profiles, fake_caller):
    aws_profiles(PROFILES)
    targets = acc.select_accounts(acct_args(account=["111111111111,333333333333", "555555555555"],
                                            account_profile=["666666666666=broken"]))
    got = {t.account: (t.profile, t.ok, t.note) for t in targets}
    assert got["111111111111"] == ("a-admin", True, "")
    assert got["333333333333"] == ("c-role", False, "profile c-role resolves to 999999999999")
    assert got["555555555555"] == (None, False, "no local profile")
    assert "666666666666" not in got


def test_select_accounts_all_and_override(aws_profiles, fake_caller):
    aws_profiles(PROFILES)
    targets = acc.select_accounts(acct_args(all_accounts=True, account_profile=["666666666666=broken"]))
    got = {t.account: t for t in targets}
    assert set(got) == {"111111111111", "222222222222", "333333333333", "444444444444", "666666666666"}
    assert got["666666666666"].ok is False and "ExpiredToken" in got["666666666666"].note
    assert got["222222222222"].ok and got["222222222222"].label == "b-ro"


def test_select_accounts_default(fake_caller):
    [t] = acc.select_accounts(acct_args())
    assert (t.account, t.profile, t.ok, t.label) == ("000000000000", None, True, "default")


def test_resolve_admin_profile(aws_profiles, fake_caller, monkeypatch):
    aws_profiles(PROFILES)
    assert acc.resolve_admin_profile(acct_args(profile="x", admin_account="1")) == "x"
    assert acc.resolve_admin_profile(acct_args()) is None
    monkeypatch.setenv("AWS_PROFILE", "env-prof")
    assert acc.resolve_admin_profile(acct_args()) == "env-prof"
    assert acc.resolve_admin_profile(acct_args(admin_account="222222222222")) == "b-ro"
    with pytest.raises(ValueError, match="no local AWS profile"):
        acc.resolve_admin_profile(acct_args(admin_account="777777777777"))
    with pytest.raises(ValueError, match="resolves to 999999999999"):
        acc.resolve_admin_profile(acct_args(admin_account="333333333333"))


def test_caller_account_moto(aws_profiles):
    with mock_aws():
        assert acc.caller_account(None) == "123456789012"


def test_profile_arg_helpers():
    p = argparse.ArgumentParser()
    acc.add_account_args(p)
    a = p.parse_args(["--account", "1,2", "--account-profile", "1=x"])
    acc.check_profile_args(p, a)
    assert a.exclude_profile_suffix == acc.DEFAULT_EXCLUDE_SUFFIXES
    with pytest.raises(SystemExit):
        acc.check_profile_args(p, p.parse_args(["--account-profile", "no-equals"]))
    q = argparse.ArgumentParser()
    acc.add_profile_args(q, admin=True)
    assert q.parse_args(["--admin-account", "1"]).admin_account == "1"
