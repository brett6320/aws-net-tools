import datetime as dt
import json

import pytest
from botocore.exceptions import ClientError

from conftest import load_tool, run_main

snap = load_tool("fmm_policy_snapshot")
ABSENT = snap.ABSENT


def pol(pid="p1", name="base", region="us-east-1", accounts=("1", "2"), remediation=True, msd=None, **extra):
    return {"PolicyId": pid, "PolicyName": name, "PolicyUpdateToken": "tok-" + pid, "RemediationEnabled": remediation,
            "IncludeMap": {"ACCOUNT": list(accounts)},
            "PolicyArn": f"arn:aws:fms:{region}:111122223333:policy/{pid}",
            "SecurityServicePolicyData": {"Type": "SECURITY_GROUPS_COMMON", "ManagedServiceData": json.dumps(
                msd or {"type": "SECURITY_GROUPS_COMMON", "securityGroups": [{"id": "sg-1"}],
                        "logBucket": f"logs-{region}"})}, **extra}


def rec(region="us-east-1", **kw):
    p = pol(region=region, **kw)
    return snap.Record(region=region, policy=p, arn=p["PolicyArn"], tags={"Family": p["PolicyName"]})


# --------------------------------------------------------------------------- #
# diffing
# --------------------------------------------------------------------------- #
def test_diff_values():
    a = {"x": 1, "gone": True, "nested": {"y": [1, 2, 3]}, "objs": [{"k": 1}, {"k": 2}]}
    b = {"x": 2, "new": "v", "nested": {"y": [3, 2, 4]}, "objs": [{"k": 1}]}
    assert snap.diff_values(a, b) == [
        ("gone", True, ABSENT), ("nested.y", [1], [4]), ("new", ABSENT, "v"), ("objs[1]", {"k": 2}, ABSENT),
        ("x", 1, 2)]
    assert snap.diff_values([1, 2], [2, 1]) == []                 # scalar lists compare as sets
    assert snap.diff_values([1, 2], [1]) == [("", [2], ABSENT)]
    assert snap.diff_values({"a": [1]}, {"a": {"b": 1}}) == [("a", [1], {"b": 1})]
    assert snap.diff_values([{"a": 1}], [{"a": 1}, {"a": 2}]) == [("[1]", ABSENT, {"a": 2})]


def test_normalise():
    p = pol(region="eu-west-1")
    n = snap.normalise(p)
    assert "PolicyUpdateToken" not in n and n["SecurityServicePolicyData"]["ManagedServiceData"]["logBucket"] == "logs-eu-west-1"
    assert p["PolicyUpdateToken"] == "tok-p1"                      # input untouched
    r = snap.normalise(p, "eu-west-1", {"PolicyId"})
    assert "PolicyId" not in r and r["PolicyArn"] == "arn:aws:fms:{region}:111122223333:policy/p1"
    assert r["SecurityServicePolicyData"]["ManagedServiceData"]["logBucket"] == "logs-{region}"
    bad = pol()
    bad["SecurityServicePolicyData"]["ManagedServiceData"] = "{oops"
    assert snap.normalise(bad)["SecurityServicePolicyData"]["ManagedServiceData"] == "{oops"


def test_render_value():
    assert snap.render_value(ABSENT) == ABSENT
    assert snap.render_value("s") == "s"
    assert snap.render_value({"b": 1, "a": [1]}) == '{"a":[1],"b":1}'
    long = snap.render_value("x" * 500)
    assert len(long) == snap.MAX_VALUE and long.endswith("...")


def test_diff_snapshots():
    old = [rec(pid="p1"), rec(pid="p2", name="gone")]
    new = [rec(pid="p1", name="renamed", accounts=("1", "3")), rec(pid="p3", name="added")]
    fs = snap.sort_findings(snap.diff_snapshots(old, new, "a", "b"))
    got = [(f.code, f.policy_id, f.severity, f.path, f.old, f.new) for f in fs]
    assert got == [
        ("POLICY_ADDED", "p3", "warn", "", "", ""),
        ("POLICY_REMOVED", "p2", "warn", "", "", ""),
        ("POLICY_CHANGED", "p1", "warn", "IncludeMap.ACCOUNT", '["2"]', '["3"]'),
        ("POLICY_CHANGED", "p1", "info", "PolicyName", "base", "renamed"),
    ]
    assert fs[0].detail == "in b, not in a"
    assert snap.diff_snapshots(old, old, "a", "a") == []


def test_compare_regions_ignores_region_names_and_ids():
    recs = [rec("us-east-1", pid="e1"), rec("ca-central-1", pid="c1"),
            rec("eu-west-1", pid="w1", remediation=False), rec("eu-west-1", pid="w2", name="extra")]
    fs = snap.compare_regions(recs, "us-east-1", ["us-east-1", "ca-central-1", "eu-west-1"], None)
    assert [(f.code, f.region, f.policy_name, f.path, f.other) for f in fs] == [
        ("DIFFERS", "eu-west-1", "base", "RemediationEnabled", "us-east-1"),
        ("MISSING_IN_REGION", "us-east-1", "extra", "", "eu-west-1"),
    ]


def test_compare_regions_by_tag_and_duplicates():
    a, b = rec("us-east-1", name="x-east"), rec("eu-west-1", name="x-west")
    a.tags = b.tags = {"Family": "x"}
    untagged = rec("eu-west-1", pid="u", name="u")
    untagged.tags = None
    dup = rec("eu-west-1", pid="d", name="x-west-2")
    dup.tags = {"Family": "x"}
    fs = snap.compare_regions([a, b, untagged, dup], "us-east-1", ["us-east-1", "eu-west-1"], "Family")
    assert [(f.code, f.path, f.severity) for f in fs] == [("DIFFERS", "PolicyName", "info")]
    assert snap.match_key(untagged, "Family") is None and snap.match_key(untagged, None) == "u"


# --------------------------------------------------------------------------- #
# snapshots on disk
# --------------------------------------------------------------------------- #
def test_save_load_resolve(tmp_path):
    d = tmp_path / "snaps"
    r1 = snap.save_snapshot([rec(pid="p1", name="a/b c")], str(d), "111122223333", ["us-east-1"],
                            now=dt.datetime(2026, 1, 1, 0, 0, 0))
    r2 = snap.save_snapshot([rec(pid="p1"), rec("eu-west-1", pid="p9")], str(d), "111122223333",
                            ["us-east-1", "eu-west-1"], now=dt.datetime(2026, 1, 2, 0, 0, 0))
    assert (r1.name, r2.name) == ("2026-01-01_000000", "2026-01-02_000000")
    assert (r1 / "us-east-1" / "a_b_c__p1.json").exists()
    index = json.loads((r2 / "index.json").read_text())
    assert index["admin_account"] == "111122223333" and len(index["policies"]) == 2
    (d / "not-a-snapshot").mkdir()
    assert snap.list_snapshots(str(d)) == [r1, r2]
    assert snap.resolve_snapshot("latest", str(d)) == r2
    assert snap.resolve_snapshot("previous", str(d)) == r1
    assert snap.resolve_snapshot("2026-01-01_000000", str(d)) == r1
    assert snap.resolve_snapshot(str(r2), "elsewhere") == r2
    with pytest.raises(ValueError, match="not found"):
        snap.resolve_snapshot("nope", str(d))
    with pytest.raises(ValueError, match="already exists"):
        snap.save_snapshot([], str(d), "1", [], now=dt.datetime(2026, 1, 1, 0, 0, 0))
    loaded = snap.load_snapshot(r2)
    assert sorted((r.region, r.policy_id, r.tags["Family"]) for r in loaded) == \
        [("eu-west-1", "p9", "base"), ("us-east-1", "p1", "base")]
    assert snap.list_snapshots(str(tmp_path / "missing")) == []
    with pytest.raises(ValueError, match="needs at least 2"):
        snap.resolve_snapshot("previous", str(tmp_path / "missing"))


def test_load_snapshot_skips_non_policy_files(tmp_path):
    (tmp_path / "us-east-1").mkdir()
    (tmp_path / "us-east-1" / "junk.json").write_text("{}")
    with pytest.raises(ValueError, match="no policy files"):
        snap.load_snapshot(tmp_path)


def test_main_diff_offline(monkeypatch, capsys, tmp_path):
    d = tmp_path / "snaps"
    snap.save_snapshot([rec(pid="p1"), rec("eu-west-1", pid="p2")], str(d), "1", ["us-east-1", "eu-west-1"],
                       now=dt.datetime(2026, 1, 1))
    snap.save_snapshot([rec(pid="p1", remediation=False)], str(d), "1", ["us-east-1"], now=dt.datetime(2026, 1, 2))
    html = tmp_path / "d.html"
    rc = run_main(snap, monkeypatch, ["diff", "previous", "latest", "--snapshot-dir", str(d), "--json", "--no-save",
                                      "--html-out", str(html), "-q"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 1
    # eu-west-1 is only in the older snapshot: not reported as removed
    assert [(f["code"], f["path"]) for f in out["findings"]] == [("POLICY_CHANGED", "RemediationEnabled")]
    assert out["compared"] == 1 and "FMS policy diff" in html.read_text()
    assert run_main(snap, monkeypatch, ["diff", "latest", "latest", "--snapshot-dir", str(d), "--no-save", "-q"]) == 0
    assert run_main(snap, monkeypatch, ["diff", "nope", "latest", "--snapshot-dir", str(d), "--no-save", "-q"]) == 2
    capsys.readouterr()


def test_main_compare_regions_offline(monkeypatch, capsys, tmp_path):
    d = tmp_path / "snaps"
    snap.save_snapshot([rec(pid="p1"), rec("eu-west-1", pid="p2")], str(d), "1", ["us-east-1", "eu-west-1"],
                       now=dt.datetime(2026, 1, 1))
    assert run_main(snap, monkeypatch, ["compare-regions", "--source", "latest", "--snapshot-dir", str(d),
                                        "--no-save", "--json", "-q"]) == 0
    assert json.loads(capsys.readouterr().out)["findings"] == []
    assert run_main(snap, monkeypatch, ["compare-regions", "--source", "latest", "--region", "us-east-1",
                                        "--snapshot-dir", str(d), "--no-save", "-q"]) == 2   # one region only


class FakeFms:
    def __init__(self, policies, fail_get=False, fail_tags=False):
        self.policies, self.fail_get, self.fail_tags = policies, fail_get, fail_tags

    def get_paginator(self, op):
        return type("P", (), {"paginate": lambda s: [{"PolicyList": [
            {"PolicyId": p["PolicyId"], "PolicyName": p["PolicyName"], "SecurityServiceType": "SECURITY_GROUPS_COMMON"}
            for p in self.policies]}]})()

    def get_policy(self, PolicyId):
        if self.fail_get:
            raise ClientError({"Error": {"Code": "ResourceNotFoundException", "Message": "x"}}, "GetPolicy")
        p = next(p for p in self.policies if p["PolicyId"] == PolicyId)
        return {"Policy": p, "PolicyArn": p["PolicyArn"]}

    def list_tags_for_resource(self, ResourceArn):
        if self.fail_tags:
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "x"}}, "ListTagsForResource")
        return {"TagList": [{"Key": "Family", "Value": "f"}]}


def test_fetch_live(monkeypatch):
    fms = FakeFms([pol(pid="p1"), pol(pid="p2", name="other")])
    monkeypatch.setattr(snap, "get_client", lambda svc, s: fms)
    recs = snap.fetch_live(None, ["us-east-1", "eu-west-1"], policy_filter="p1")
    assert [(r.region, r.policy_id, r.tags) for r in recs] == [("us-east-1", "p1", {"Family": "f"}),
                                                               ("eu-west-1", "p1", {"Family": "f"})]
    assert snap.fetch_live(None, ["us-east-1"], types={"NETWORK_FIREWALL"}) == []
    fms.fail_tags = True
    assert snap.fetch_live(None, ["us-east-1"], "p2")[0].tags is None
    fms.fail_get = True
    with pytest.raises(RuntimeError, match="get_policy p1 failed: ResourceNotFoundException"):
        snap.fetch_live(None, ["us-east-1"])
