"""OU -> accounts (Organizations, via moto), account -> profile, profile -> VPCs (fakes), and the owner map."""
import json

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

import ou_vpcs
import ov_core as core
from ov_cache import VpcOwnerCache, default_path

A, B, C = "222222222222", "333333333333", "444444444444"


# --------------------------------------------------------------------------- organizations


@pytest.fixture
def org():
    """Root / Prod (account app) / Prod/Web (account web); Dev (account dev)."""
    with mock_aws():
        o = boto3.client("organizations", region_name="us-east-1")
        o.create_organization(FeatureSet="ALL")
        root = o.list_roots()["Roots"][0]["Id"]
        prod = o.create_organizational_unit(ParentId=root, Name="Prod")["OrganizationalUnit"]["Id"]
        web = o.create_organizational_unit(ParentId=prod, Name="Web")["OrganizationalUnit"]["Id"]
        dev = o.create_organizational_unit(ParentId=root, Name="Dev")["OrganizationalUnit"]["Id"]
        ids = {}
        for name, ou in (("app", prod), ("web", web), ("dev", dev)):
            acct = o.create_account(Email=f"{name}@example.com", AccountName=name)["CreateAccountStatus"]["AccountId"]
            o.move_account(AccountId=acct, SourceParentId=root, DestinationParentId=ou)
            ids[name] = acct
        yield o, {"root": root, "prod": prod, "web": web, "dev": dev}, ids


def test_ou_resolves_to_accounts_in_it_and_below(org):
    o, ous, ids = org
    accts = core.accounts_in_ous(o, [ous["prod"]])
    assert [(a.id, a.name, a.ou_path) for a in accts] == [
        (ids["app"], "app", "Root/Prod"), (ids["web"], "web", "Root/Prod/Web")]
    assert accts[1].ou_id == ous["web"]
    assert [a.id for a in core.accounts_in_ous(o, [ous["prod"]], recurse=False)] == [ids["app"]]
    assert core.ou_path(o, ous["web"]) == "Root/Prod/Web"


def test_overlapping_ous_list_each_account_once(org):
    o, ous, ids = org
    accts = core.accounts_in_ous(o, [ous["prod"], ous["web"], ous["dev"]])
    assert sorted(a.name for a in accts) == ["app", "dev", "web"]
    assert {a.name for a in core.accounts_in_ous(o, [ous["root"]])} >= {"app", "dev", "web"}


def test_inactive_accounts_are_skipped():
    class Org:
        def get_paginator(self, op):
            class P:
                def paginate(self, **kw):
                    if op == "list_accounts_for_parent":
                        yield {"Accounts": [{"Id": A, "Name": "a", "State": "ACTIVE"},
                                            {"Id": B, "Name": "b", "State": "SUSPENDED"}]}
                    else:
                        yield {"OrganizationalUnits": []}
            return P()

    assert [a.id for a in core.accounts_in_ous(Org(), ["r-ab12"])] == [A]


@pytest.mark.parametrize("bad", ["ou-1", "123456789012", "OU-ABCD-12345678", ""])
def test_ou_ids_are_validated(bad):
    with pytest.raises(ValueError):
        core.parse_ou_ids([bad])


def test_input_parsing():
    assert core.parse_ou_ids(["ou-ab12-11111111,r-ab12", "ou-ab12-11111111"]) == ["ou-ab12-11111111", "r-ab12"]
    assert core.parse_regions(None) == ["us-east-1", "ca-central-1"]
    assert core.parse_regions(["eu-west-1, us-west-2"]) == ["eu-west-1", "us-west-2"]
    with pytest.raises(ValueError):
        core.parse_regions(["us-east"])
    assert core.parse_account_profiles([f"{A}=x,{B}=y"]) == {A: "x", B: "y"}
    with pytest.raises(ValueError):
        core.parse_account_profiles(["12=x"])


# --------------------------------------------------------------------------- profiles


def test_profile_by_account_never_priv_or_cpar(aws_config):
    aws_config({"a-ro": A, "a-priv": A, "a-admin": A, "b-priv": B, "b-cpar": B, "c1": C, "c2": C})
    assert core.resolve_profile(A) == "a-ro"  # single read-only one wins over a-admin
    with pytest.raises(LookupError, match="no profile"):
        core.resolve_profile(B)  # only -priv / -cpar map to it
    with pytest.raises(LookupError, match="several profiles"):
        core.resolve_profile(C)
    assert core.resolve_profile(C, preferred="c2") == "c2"
    assert core.resolve_profile(C, overrides={C: "c1"}) == "c1"


# --------------------------------------------------------------------------- VPC scan


def vpc(vpc_id, cidr="10.0.0.0/16", name=None, default=False, extra=()):
    v = {"VpcId": vpc_id, "CidrBlock": cidr, "IsDefault": default, "State": "available",
         "CidrBlockAssociationSet": [{"CidrBlock": c, "CidrBlockState": {"State": "associated"}} for c in (cidr, *extra)]}
    if name:
        v["Tags"] = [{"Key": "Name", "Value": name}]
    return v


class FakeSession:
    """sts / ec2 for one account: ``vpcs`` is {region: [vpc, ...]}, ``deny`` the Regions that refuse."""

    def __init__(self, account, vpcs=None, deny=(), calls=None):
        self.account, self.vpcs, self.deny = account, vpcs or {}, set(deny)
        self.calls = calls if calls is not None else []

    def client(self, service, region_name=None, config=None):
        sess = self

        class Client:
            def get_caller_identity(self):
                return {"Account": sess.account}

            def get_paginator(self, op):
                class P:
                    def paginate(self, **kw):
                        sess.calls.append((sess.account, region_name, kw))
                        if region_name in sess.deny:
                            raise ClientError({"Error": {"Code": "AuthFailure", "Message": "not enabled"}}, "DescribeVpcs")
                        yield {"Vpcs": sess.vpcs.get(region_name, [])}
                return P()

        return Client()


def acct(account, name="n", ou="ou-ab12-11111111", path="Root/Prod"):
    return core.OrgAccount(account, name, ou, path)


def test_scan_one_call_per_account_and_region_owned_vpcs_only(aws_config):
    aws_config({"a-ro": A, "b": B})
    calls = []
    sessions = {
        "a-ro": FakeSession(A, {"us-east-1": [vpc("vpc-a1", name="hub", extra=("100.64.0.0/16",))],
                                "ca-central-1": [vpc("vpc-a2", default=True)]}, calls=calls),
        "b": FakeSession(B, {"us-east-1": [vpc("vpc-b1")]}, calls=calls),
    }
    scan = core.scan_accounts([acct(A, "app"), acct(B, "web", path="Root/Prod/Web")],
                              ["us-east-1", "ca-central-1"], sessions.__getitem__)
    assert scan.skipped == []
    assert [(r["account"], r["region"], r["vpc_id"]) for r in scan.rows] == [
        (A, "ca-central-1", "vpc-a2"), (A, "us-east-1", "vpc-a1"), (B, "us-east-1", "vpc-b1")]
    hub = scan.rows[1]
    assert hub["name"] == "hub" and hub["cidrs"] == ["10.0.0.0/16", "100.64.0.0/16"] and hub["account_name"] == "app"
    assert scan.rows[0]["is_default"] is True
    assert len(calls) == 4
    assert all(kw["Filters"] == [{"Name": "owner-id", "Values": [a]}] for a, _, kw in calls)


def test_scan_skips_unreachable_accounts_and_regions_and_carries_on(aws_config):
    aws_config({"a": A, "b-priv": B, "c": C})
    sessions = {
        "a": FakeSession(A, {"us-east-1": [vpc("vpc-a1")]}, deny={"ca-central-1"}),
        "c": FakeSession("999999999999"),  # profile c authenticates as the wrong account
    }
    scan = core.scan_accounts([acct(A), acct(B), acct(C)], ["us-east-1", "ca-central-1"], sessions.__getitem__)
    assert [r["vpc_id"] for r in scan.rows] == ["vpc-a1"]
    assert [(s.account, s.region) for s in scan.skipped] == [(A, "ca-central-1"), (B, ""), (C, "")]
    assert "AuthFailure" in scan.skipped[0].reason
    assert "no profile" in scan.skipped[1].reason
    assert "authenticates as 999999999999" in scan.skipped[2].reason


# --------------------------------------------------------------------------- owner map


def test_store_enriches_the_shared_owner_map(tmp_path):
    path = tmp_path / "owners.json"
    path.write_text(json.dumps({"us-east-1/vpc-old": {"account": C, "source": "ipam", "seen": "2026-01-01"}}))
    rows = [core.vpc_row(acct(A, "app"), "us-east-1", vpc("vpc-a1", name="hub"))]
    cache = VpcOwnerCache(path)
    assert core.store(cache, rows) == 1
    cache.save()
    data = json.loads(path.read_text())
    assert data["us-east-1/vpc-old"]["account"] == C  # existing phz_review entries kept
    e = data["us-east-1/vpc-a1"]
    assert {k: e[k] for k in ("account", "source", "account_name", "ou_id", "ou_path", "name", "cidrs")} == {
        "account": A, "source": "ou_vpcs", "account_name": "app", "ou_id": "ou-ab12-11111111",
        "ou_path": "Root/Prod", "name": "hub", "cidrs": ["10.0.0.0/16"]}
    assert path.stat().st_mode & 0o777 == 0o600
    assert core.store(VpcOwnerCache(path), rows) == 0  # unchanged: nothing to rewrite


def test_owner_map_defaults_to_the_phz_review_file(tmp_path):
    assert default_path() == tmp_path / "cache" / "aws-net-tools" / "vpc-owners.json"


def test_unreadable_map_is_ignored(tmp_path):
    path = tmp_path / "owners.json"
    path.write_text("{not json")
    assert len(VpcOwnerCache(path)) == 0


# --------------------------------------------------------------------------- CLI


def run(org, aws_config, capsys, *argv, member_sessions=None):
    o, ous, ids = org
    aws_config({"app-ro": ids["app"], "web": ids["web"], "web-priv": ids["web"]})
    member_sessions = member_sessions or {
        "app-ro": FakeSession(ids["app"], {"us-east-1": [vpc("vpc-app1", name="app")]}),
        "web": FakeSession(ids["web"], {"ca-central-1": [vpc("vpc-web1")]}),
    }

    def session_for(profile):
        return member_sessions[profile] if profile in member_sessions else boto3.Session()

    rc = ou_vpcs.main(list(argv), session_for=session_for)
    return rc, capsys.readouterr().out


def test_cli_lists_vpcs_and_fills_the_owner_map(org, aws_config, capsys, tmp_path):
    _, ous, ids = org
    rc, out = run(org, aws_config, capsys, "--ou", ous["prod"], "--json")
    assert rc == 0
    rows = json.loads(out)
    assert [(r["account"], r["region"], r["vpc_id"], r["ou_path"]) for r in rows] == [
        (ids["app"], "us-east-1", "vpc-app1", "Root/Prod"), (ids["web"], "ca-central-1", "vpc-web1", "Root/Prod/Web")]
    owners = json.loads(default_path().read_text())
    assert owners["ca-central-1/vpc-web1"]["account"] == ids["web"]
    assert owners["us-east-1/vpc-app1"]["account_name"] == "app"


def test_cli_partial_scan_exits_3_and_no_cache_writes_nothing(org, aws_config, capsys):
    _, ous, _ = org
    rc, out = run(org, aws_config, capsys, "--ou", f"{ous['prod']},{ous['dev']}", "--no-cache", "-o", "csv")
    assert rc == 3  # the dev account has no profile
    assert out.splitlines()[0] == ",".join(ou_vpcs.COLUMNS)
    assert len(out.splitlines()) == 3
    assert not default_path().exists()


def test_cli_table_regions_and_env_defaults(org, aws_config, capsys, monkeypatch):
    _, ous, _ = org
    monkeypatch.setenv("OU_VPCS_OU", ous["web"])
    monkeypatch.setenv("OU_VPCS_REGIONS", "us-east-1")
    rc, out = run(org, aws_config, capsys, "--no-cache")
    assert rc == 0 and "(no results)" in out  # web's only VPC is in ca-central-1
    rc, out = run(org, aws_config, capsys, "--no-cache", "--regions", "ca-central-1")
    assert rc == 0 and "vpc-web1" in out and "ROOT/PROD/WEB" not in out and "Root/Prod/Web" in out


def test_cli_bad_input_and_org_errors(org, aws_config, capsys):
    assert ou_vpcs.main(["--ou", "nope"]) == 2
    assert ou_vpcs.main(["--ou", "ou-ab12-11111111", "--account-profile", "x"]) == 2

    class Denied:
        def client(self, *a, **k):
            raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "no"}}, "ListParents")

    assert ou_vpcs.main(["--ou", "ou-ab12-11111111", "--no-cache"], session_for=lambda p: Denied()) == 1


# --------------------------------------------------------------------------- idempotency


def test_rerun_gives_the_same_output_and_never_rewrites_the_map(org, aws_config, capsys):
    _, ous, _ = org
    rc1, out1 = run(org, aws_config, capsys, "--ou", ous["prod"], "--json")
    path = default_path()
    before = (path.read_bytes(), path.stat().st_mtime_ns)
    rc2, out2 = run(org, aws_config, capsys, "--ou", ous["prod"], "--json")
    assert (rc1, out1) == (rc2, out2)
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before  # second run wrote nothing
    assert not path.with_suffix(".tmp").exists()


def test_secondary_cidr_order_does_not_change_the_entry(tmp_path):
    a = vpc("vpc-a1", extra=("100.64.0.0/16", "10.9.0.0/16"))
    b = dict(a, CidrBlockAssociationSet=[a["CidrBlockAssociationSet"][0], *reversed(a["CidrBlockAssociationSet"][1:])])
    row_a, row_b = (core.vpc_row(acct(A), "us-east-1", v) for v in (a, b))
    assert row_a["cidrs"] == row_b["cidrs"] == ["10.0.0.0/16", "10.9.0.0/16", "100.64.0.0/16"]  # primary first
    cache = VpcOwnerCache(tmp_path / "owners.json")
    assert core.store(cache, [row_a]) == 1 and core.store(cache, [row_b]) == 0


def test_phz_review_owner_only_entry_is_enriched_once(tmp_path):
    path = tmp_path / "owners.json"
    path.write_text(json.dumps({"us-east-1/vpc-a1": {"account": A, "source": "ipam", "seen": "2026-01-01"}}))
    rows = [core.vpc_row(acct(A), "us-east-1", vpc("vpc-a1"))]
    cache = VpcOwnerCache(path)
    assert core.store(cache, rows) == 1
    cache.save()
    assert core.store(VpcOwnerCache(path), rows) == 0


# --------------------------------------------------------------------------- organization ID


def test_org_id_means_the_root_and_is_checked(org):
    o, ous, ids = org
    org_id = o.describe_organization()["Organization"]["Id"]
    assert core.parse_ou_ids([org_id]) == [org_id]
    assert core.resolve_org_ids(o, [org_id, ous["root"], ous["prod"]]) == [ous["root"], ous["prod"]]
    by_org = core.accounts_in_ous(o, [org_id])
    assert by_org == core.accounts_in_ous(o, [ous["root"]])
    assert {ids["app"], ids["web"], ids["dev"]} <= {a.id for a in by_org}
    with pytest.raises(ValueError, match="Organizations profile is in"):
        core.resolve_org_ids(o, ["o-zzzzzzzzzz"])
    with pytest.raises(ValueError):
        core.parse_ou_ids(["o-short"])


def test_cli_accepts_org_id_and_rejects_another_org(org, aws_config, capsys):
    o, _, ids = org
    org_id = o.describe_organization()["Organization"]["Id"]
    rc, out = run(org, aws_config, capsys, "--ou", org_id, "--no-cache", "--json")
    assert rc == 3  # the management and dev accounts have no profile
    assert {r["account"] for r in json.loads(out)} == {ids["app"], ids["web"]}
    rc, out = run(org, aws_config, capsys, "--ou", "o-zzzzzzzzzz", "--no-cache")
    assert rc == 2 and out == ""
