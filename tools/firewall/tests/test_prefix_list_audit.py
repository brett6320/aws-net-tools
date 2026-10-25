import argparse
import json

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from conftest import load_tool, run_main
from lib.accounts import Target

pla = load_tool("prefix_list_audit")


def pl(n_entries=0, max_entries=10, *, cidrs=None, pid="pl-1", name="corp", account="1", region="r",
       ownership="owned", state="create-complete", associations=None, read_error=""):
    cidrs = cidrs if cidrs is not None else [f"10.{i}.0.0/16" for i in range(n_entries)]
    return pla.PrefixList(account=account, profile="p", region=region, prefix_list_id=pid, name=name, family="IPv4",
                          owner=account if ownership == "owned" else "AWS" if ownership == "aws" else "9",
                          ownership=ownership, state=state, version=1, max_entries=max_entries,
                          entries=[{"cidr": c, "description": ""} for c in cidrs],
                          associations=[{"ResourceId": "sg-1"}] if associations is None else associations,
                          read_error=read_error)


def codes(p, headroom=2, full_pct=90):
    return [f.code for f in pla.check_list(p, headroom, full_pct)]


def test_helpers():
    assert pla._norm_cidr(" 10.1.2.3/8 ") == "10.0.0.0/8"
    assert pla._norm_cidr("nonsense") == "nonsense"
    assert [pla.ownership_of(o, "1") for o in ("AWS", "1", "2")] == ["aws", "owned", "shared"]
    p = pl(3, 8)
    assert p.utilisation == 37.5 and p.cidrs == ["10.0.0.0/16", "10.1.0.0/16", "10.2.0.0/16"]
    assert pl(1, None).utilisation is None
    assert pl(1, associations=[{"ResourceId": "sg-1"}, {}]).resources() == ["sg-1", "?"]


def test_capacity_thresholds():
    assert codes(pl(10, 10)) == ["PL_FULL"]
    assert codes(pl(8, 10)) == ["PL_NEAR_FULL"]          # within headroom 2
    assert codes(pl(7, 10)) == []
    assert codes(pl(7, 10), full_pct=70) == ["PL_NEAR_FULL"]
    assert codes(pl(7, 10), headroom=0, full_pct=71) == []


def test_near_full_detail():
    [f] = pla.check_list(pl(9, 10), 2, 90)
    assert (f.severity, f.detail, f.entries, f.max_entries, f.associations) == \
        ("warn", "9/10 entries (90.0%); 1 slot(s) left", 9, 10, 1)


def test_empty_unused_oversized():
    assert codes(pl(0, 10, associations=[])) == ["PL_EMPTY", "PL_UNUSED"]
    [f] = pla.check_list(pl(2, 20, associations=[{"ResourceId": "sg-a"}, {"ResourceId": "rtb-1"}]), 2, 90)
    assert f.code == "PL_OVERSIZED" and f.severity == "info"
    assert f.detail.endswith("counts 20 rules against the rules-per-group quota; referenced by 1 security group(s): sg-a")
    assert codes(pl(5, 14)) == []                         # 2x but fewer than 10 spare slots
    assert codes(pl(1, 20, ownership="shared", associations=None)) == ["PL_OVERSIZED"]


def test_unknown_associations_never_unused():
    p = pl(1, 10, associations=None)
    p.associations = None
    assert codes(p) == []


def test_state_read_error_and_aws_managed():
    assert codes(pl(1, 10, state="modify-in-progress")) == ["PL_NOT_ACTIVE"]
    assert codes(pl(10, 10, read_error="entries: AccessDenied: x")) == ["ACCOUNT_ERROR"]
    assert codes(pl(0, None, ownership="aws", associations=[])) == []
    assert codes(pl(0, None, ownership="aws", state="delete-failed")) == ["PL_NOT_ACTIVE"]


def test_overlapping_entries():
    assert pla.overlapping_pairs(["10.0.0.0/8", "10.1.0.0/16", "10.1.0.0/16", "2001:db8::/32", "2001:db8:1::/48",
                                  "bad"]) == [("10.1.0.0/16", "10.0.0.0/8"), ("10.1.0.0/16", "10.0.0.0/8"),
                                              ("10.1.0.0/16", "10.1.0.0/16"), ("2001:db8:1::/48", "2001:db8::/32")]
    fs = pla.check_list(pl(cidrs=["10.0.0.0/8", "10.1.0.0/16"], max_entries=3), 0, 100)
    assert [f.code for f in fs] == ["PL_OVERLAPPING_ENTRIES"]
    assert fs[0].detail == "1 entry already covered by another entry (redundant slots): 10.1.0.0/16 inside 10.0.0.0/8"
    dup = pla.check_list(pl(cidrs=["10.0.0.0/8", "10.0.0.0/8"], max_entries=3), 0, 100)[0]
    assert "10.0.0.0/8 duplicates 10.0.0.0/8" in dup.detail


def test_name_drift():
    a = pl(cidrs=["10.0.0.0/8", "10.1.0.0/16"], pid="pl-a", account="1")
    b = pl(cidrs=["10.0.0.0/8", "10.1.0.0/16"], pid="pl-b", account="2")
    c = pl(cidrs=["10.0.0.0/8", "10.9.0.0/16"], pid="pl-c", account="3")
    [f] = pla.check_name_drift([c, b, a])
    assert (f.code, f.prefix_list_id, f.account) == ("PL_NAME_DRIFT", "pl-c", "3")
    assert f.detail == ("differs from the most common 'corp' (2 entries, in 1/r pl-a; 2/r pl-b): "
                        "extra: 10.9.0.0/16; missing: 10.1.0.0/16")


def test_name_drift_tie_goes_to_first_copy_and_ignores_shared():
    a = pl(cidrs=["10.0.0.0/8"], pid="pl-a", account="1")
    b = pl(cidrs=["10.1.0.0/16"], pid="pl-b", account="2")
    [f] = pla.check_name_drift([b, a])
    assert f.prefix_list_id == "pl-b"
    shared = pl(cidrs=["10.1.0.0/16"], pid="pl-a", account="2", ownership="shared")
    assert pla.check_name_drift([a, shared]) == []
    same_place = pl(cidrs=["10.1.0.0/16"], pid="pl-z", account="1")       # two lists in one account/region
    assert pla.check_name_drift([a, same_place]) == []
    assert pla.check_name_drift([a, pl(cidrs=["10.0.0.0/8"], pid="pl-b", account="2")]) == []


def test_dedupe_shared_prefers_owner_view():
    owned = pl(1, pid="pl-x", account="1")
    seen = pl(1, pid="pl-x", account="2", ownership="shared")
    other = pl(1, pid="pl-y", account="2", ownership="shared")
    out = pla.dedupe_shared([seen, owned, other])
    assert sorted((p.prefix_list_id, p.account) for p in out) == [("pl-x", "1"), ("pl-y", "2")]


def args(**kw):
    return argparse.Namespace(**{"include_shared": False, "include_aws": False, "name": None, "headroom": 2,
                                 "full_pct": 90.0, **kw})


@pytest.mark.xfail(strict=True, reason="prefix_list_audit.run labels every unscannable account with a profile as "
                                       "PROFILE_ACCOUNT_MISMATCH, even when the profile failed for another reason "
                                       "(sg_quota_audit/nacl_shadow report ACCOUNT_ERROR)")
def test_run_unscannable_account_codes():
    _, findings, _ = pla.run(args(), ["r"], [Target("1", "p", False, "profile p: ExpiredToken")])
    assert [f.code for f in findings] == ["ACCOUNT_ERROR"]


def test_run_aggregates(monkeypatch):
    lists = {"1": [pl(10, 10, pid="pl-a", account="1")], "2": [pl(10, 10, pid="pl-a", account="2", ownership="shared")]}
    monkeypatch.setattr(pla, "collect_region", lambda t, region, a: lists[t.account])
    found, findings, stats = pla.run(args(), ["r"], [Target("1", "p1"), Target("2", "p2"),
                                                     Target("3", None, False, "no local profile")])
    # the list shared into account 2 is checked once, from its owner's view
    assert [(f.account, f.code) for f in findings] == [("1", "PL_FULL"), ("3", "NO_PROFILE")]
    assert stats == {"accounts": 2, "accounts_skipped": 1, "regions": 1, "prefix_lists": 1,
                     "by_code": {"NO_PROFILE": 1, "PL_FULL": 1}}


# --------------------------------------------------------------------------- #
# moto end to end (associations faked: moto does not implement them)
# --------------------------------------------------------------------------- #
class AssocProxy:
    """Real moto EC2 client, except get_managed_prefix_list_associations."""
    def __init__(self, real, assoc):
        self.real, self.assoc = real, assoc

    def get_paginator(self, op):
        if op != "get_managed_prefix_list_associations":
            return self.real.get_paginator(op)
        assoc = self.assoc

        class P:
            def paginate(self, PrefixListId):
                if assoc.get(PrefixListId) == "denied":
                    raise ClientError({"Error": {"Code": "AccessDenied", "Message": "x"}}, op)
                return [{"PrefixListAssociations": [{"ResourceId": r} for r in assoc.get(PrefixListId, [])]}]
        return P()


def test_main_moto(monkeypatch, capsys, tmp_path):
    with mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        mk = lambda name, mx, cidrs: ec2.create_managed_prefix_list(  # noqa: E731
            PrefixListName=name, AddressFamily="IPv4", MaxEntries=mx,
            Entries=[{"Cidr": c} for c in cidrs])["PrefixList"]["PrefixListId"]
        full = mk("corp-full", 2, ["10.0.0.0/8", "10.1.0.0/16"])
        unused = mk("corp-unused", 5, ["192.168.0.0/24"])
        mk("other", 5, ["172.16.0.0/12"])
        assoc = {full: ["sg-1"], unused: []}
        real_get_client = pla.get_client
        monkeypatch.setattr(pla, "get_client", lambda svc, s: AssocProxy(real_get_client(svc, s), assoc))
        html = tmp_path / "p.html"
        rc = run_main(pla, monkeypatch, ["--region", "us-east-1", "--name", "corp-*", "--json", "--no-save",
                                         "--html-out", str(html), "-q"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert sorted(x["name"] for x in data["lists"]) == ["corp-full", "corp-unused"]
    got = sorted((f["prefix_list_name"], f["code"]) for f in data["findings"])
    assert got == [("corp-full", "PL_FULL"), ("corp-full", "PL_OVERLAPPING_ENTRIES"), ("corp-unused", "PL_UNUSED")]
    assert data["stats"]["prefix_lists"] == 2
    assert "Prefix list audit" in html.read_text()
