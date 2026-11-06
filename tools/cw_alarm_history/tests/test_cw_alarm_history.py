import csv
import io
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import cw_alarm_history as cwah  # noqa: E402
import cwah_export  # noqa: E402
from fake_cloudwatch import ACCOUNT, HISTORY, NOW, T0, FakeCloudWatch, _state_item  # noqa: E402

H = timedelta(hours=1)
REAL_COLLECT = cwah.collect_alarm_history
NAMES = ["net-dx-bgp-down", "net-tgw-packet-drops", "net-vpn-tunnel-status", "net-quiet", "net-deleted"]


def collect(**kw):
    args = dict(alarms=NAMES, start=T0, end=NOW, cw=FakeCloudWatch(), account=ACCOUNT, now=NOW)
    args.update(kw)
    return cwah.collect_alarm_history(**args)


# --------------------------------------------------------------------------- #
# time parsing
# --------------------------------------------------------------------------- #
def test_parse_duration():
    assert cwah.parse_duration("30m") == timedelta(minutes=30)
    assert cwah.parse_duration("6h") == timedelta(hours=6)
    assert cwah.parse_duration("7d") == timedelta(days=7)
    assert cwah.parse_duration("2w") == timedelta(weeks=2)
    assert cwah.parse_duration("1.5h") == timedelta(minutes=90)
    with pytest.raises(ValueError):
        cwah.parse_duration("yesterday")


def test_parse_when_forms():
    assert cwah.parse_when("now", now=NOW) == NOW
    assert cwah.parse_when("-24h", now=NOW) == NOW - timedelta(hours=24)
    assert cwah.parse_when("24h", now=NOW) == NOW - timedelta(hours=24)
    assert cwah.parse_when("2026-11-01T14:30Z") == datetime(2026, 11, 1, 14, 30, tzinfo=timezone.utc)
    assert cwah.parse_when("2026-11-01T14:30+02:00") == datetime(2026, 11, 1, 12, 30, tzinfo=timezone.utc)
    naive = cwah.parse_when("2026-11-01T14:30")
    assert naive.tzinfo is timezone.utc  # local time, converted
    with pytest.raises(ValueError):
        cwah.parse_when("not a date")


def test_resolve_period_defaults_and_errors():
    s, e = cwah.resolve_period(None, "2030-01-01T00:00Z", None, now=NOW)
    assert e == NOW  # a future end is capped at now
    s, e = cwah.resolve_period(None, None, None, now=NOW)
    assert e == NOW and s == NOW - timedelta(days=7)
    s, e = cwah.resolve_period("2026-11-01", "2026-11-02T00:00Z", None, now=NOW)
    assert e == datetime(2026, 11, 2, tzinfo=timezone.utc)
    s, e = cwah.resolve_period(None, "1d", "6h", now=NOW)
    assert e == NOW - timedelta(days=1) and s == e - timedelta(hours=6)
    with pytest.raises(ValueError):
        cwah.resolve_period("1h", None, "2h", now=NOW)
    with pytest.raises(ValueError):
        cwah.resolve_period("now", "1h", None, now=NOW)


def test_fmt_duration():
    assert cwah.fmt_duration(None) == "-"
    assert cwah.fmt_duration(5) == "5s"
    assert cwah.fmt_duration(90) == "1m 30s"
    assert cwah.fmt_duration(3600 * 25 + 120) == "1d 1h"


# --------------------------------------------------------------------------- #
# collection
# --------------------------------------------------------------------------- #
def test_transitions_and_durations():
    r = collect()
    by = {a.alarm: a for a in r.alarms}
    assert set(by) == set(NAMES)
    assert r.alarms_not_found == ["net-deleted"]
    assert not by["net-deleted"].exists and by["net-deleted"].transitions == 1
    assert by["net-deleted"].state_at_start == "ALARM" and by["net-deleted"].seconds_in_alarm == 5 * 3600

    dx = by["net-dx-bgp-down"]
    assert (dx.transitions, dx.into_alarm, dx.state_at_start, dx.current_state) == (4, 2, "OK", "OK")
    assert dx.seconds_in_alarm == 15 * 60 + 3600

    tgw = by["net-tgw-packet-drops"]
    assert tgw.into_alarm == 1
    assert tgw.seconds_in_alarm == (NOW - (T0 + 100 * H)).total_seconds()
    last = [t for t in r.transitions if t.alarm == "net-tgw-packet-drops"][-1]
    assert last.ongoing and last.to_state == "ALARM"

    quiet = by["net-quiet"]
    assert quiet.transitions == 0 and quiet.state_at_start == "OK" and quiet.seconds_in_alarm == 0
    assert quiet.state_transitioned == "2026-10-30T18:00:00.000Z"

    assert all(t.history_type == "StateUpdate" for t in r.transitions)
    assert r.transitions == sorted(r.transitions, key=lambda t: (t.timestamp, t.alarm))
    assert all(t.timestamp.endswith("Z") for t in r.transitions)
    # item before the period is excluded
    assert not any(t.timestamp < "2026-11-01" for t in r.transitions)
    assert r.transitions[0].reason_data["threshold"] == 5.0


def test_alarm_in_alarm_all_period_without_transitions():
    r = collect(alarms=["net-stuck-alarm"])
    a = r.alarms[0]
    assert a.transitions == 0 and a.state_at_start == "ALARM"
    assert a.seconds_in_alarm == (NOW - T0).total_seconds()
    assert r.to_dict()["time_in_alarm"] == "5d 12h"


def test_state_at_start_unknown_when_current_state_began_after_period():
    # period ends before net-tgw-packet-drops went to ALARM; nothing in the period says what it was
    r = collect(alarms=["net-tgw-packet-drops"], end=T0 + 50 * H)
    a = r.alarms[0]
    assert a.transitions == 0 and a.state_at_start is None and a.seconds_in_alarm == 0


def test_future_end_is_capped_and_bad_period_rejected():
    r = collect(alarms=["net-tgw-packet-drops"], end=NOW + timedelta(days=30))
    assert r.end == cwah._iso(NOW)
    assert r.alarms[0].seconds_in_alarm == (NOW - (T0 + 100 * H)).total_seconds()
    with pytest.raises(ValueError):
        collect(alarms=["net-quiet"], start=NOW + H, end=NOW + 2 * H)


def test_millisecond_timestamps_sort_correctly():
    t = T0 + 3 * H
    hist = [_state_item("ms", "MetricAlarm", t + timedelta(milliseconds=250), "ALARM", "OK"),
            _state_item("ms", "MetricAlarm", t, "OK", "ALARM")]
    r = collect(alarms=["ms"], cw=FakeCloudWatch(history=hist, alarms={}))
    ts = [x.to_state for x in r.transitions]
    assert ts == ["ALARM", "OK"]
    assert r.transitions[0].timestamp == "2026-11-01T03:00:00.000Z"
    assert r.transitions[1].timestamp == "2026-11-01T03:00:00.250Z"
    assert r.transitions[0].duration_s == 0.25


def test_prefix_and_alarm_types():
    cw = FakeCloudWatch()
    r = collect(alarms=[], prefixes=["net-"], cw=cw)
    assert {a.alarm for a in r.alarms} == {"net-dx-bgp-down", "net-tgw-packet-drops", "net-vpn-tunnel-status",
                                           "net-quiet", "net-stuck-alarm"}
    r = collect(alarms=[], prefixes=["net-"], alarm_types=["MetricAlarm"], cw=cw)
    assert "net-vpn-tunnel-status" not in {a.alarm for a in r.alarms}


def test_history_types_all_and_validation():
    r = collect(history_types=cwah.HISTORY_TYPES)
    kinds = {t.history_type for t in r.transitions}
    assert kinds == {"StateUpdate", "Action", "ConfigurationUpdate"}
    non = [t for t in r.transitions if t.history_type != "StateUpdate"]
    assert all(t.from_state is None and t.duration_s is None for t in non)
    # durations ignore non-state items
    dx = next(a for a in r.alarms if a.alarm == "net-dx-bgp-down")
    assert dx.transitions == 4 and dx.seconds_in_alarm == 15 * 60 + 3600
    with pytest.raises(ValueError):
        collect(history_types=["Bogus"])
    with pytest.raises(ValueError):
        collect(alarms=[], prefixes=[])
    with pytest.raises(ValueError):
        collect(alarm_types=["metric"])
    # case-insensitive, duplicates dropped
    r = collect(history_types=["stateupdate", "StateUpdate"], alarm_types=["METRICALARM"])
    assert r.history_types == ["StateUpdate"]


def test_multiple_history_types_use_one_unfiltered_pass():
    cw = FakeCloudWatch()
    collect(alarms=["net-dx-bgp-down"], history_types=["StateUpdate", "Action"], cw=cw)
    hist = [kw for op, kw in cw.calls if op == "describe_alarm_history"]
    assert len(hist) == 1 and "HistoryItemType" not in hist[0]


def test_access_denied_is_per_alarm():
    r = collect(cw=FakeCloudWatch(deny={"net-quiet"}))
    bad = next(a for a in r.alarms if a.alarm == "net-quiet")
    assert bad.error and "AccessDenied" in bad.error
    assert len(r.errors) == 1
    assert next(a for a in r.alarms if a.alarm == "net-dx-bgp-down").transitions == 4


def test_pagination_and_api_args():
    cw = FakeCloudWatch(page_size=1)
    r = collect(cw=cw)
    assert sum(a.transitions for a in r.alarms) == 8
    hist = [kw for op, kw in cw.calls if op == "describe_alarm_history"]
    assert all(kw["ScanBy"] == "TimestampAscending" and kw["StartDate"] == T0 and kw["EndDate"] == NOW for kw in hist)
    assert {kw["HistoryItemType"] for kw in hist} == {"StateUpdate"}


def test_retention_warning(caplog):
    collect(start=NOW - timedelta(days=45))
    assert any("30 days" in m for m in caplog.messages)


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #
def test_json_roundtrip_and_csv():
    r = collect()
    d = json.loads(cwah.render_json(r))
    assert d["transition_count"] == 8 and d["into_alarm_count"] == 3
    assert d["time_in_alarm"] == cwah.fmt_duration(d["seconds_in_alarm"])
    rows = list(csv.DictReader(io.StringIO(cwah.render_csv(r))))
    assert len(rows) == 8 and list(rows[0]) == list(cwah.CSV_COLUMNS)
    assert all(x["timestamp_utc"].endswith("Z") and "." in x["timestamp_utc"] for x in rows)
    ongoing = [x for x in rows if x["ongoing"] == "yes"]
    assert len(ongoing) == 4  # every alarm's last transition is still in effect at the period end
    assert [x["alarm"] for x in ongoing if x["to_state"] == "ALARM"] == ["net-tgw-packet-drops"]
    assert rows[0]["account"] == ACCOUNT and rows[0]["region"] == "us-east-1"


def test_html_embeds_data_and_filters():
    r = collect()
    page = cwah.render_html_report(r)
    assert 'data-theme="dark"' in page
    assert "window.DATA=" in page and "Export CSV" in page
    m = page.split("window.DATA=")[1].split(";</script>")[0]
    embedded = json.loads(m)
    assert embedded["transition_count"] == 8
    assert all(t["timestamp"].endswith("Z") for t in embedded["transitions"])
    for s in ("name=\"fs\"", "name=\"ts\"", 'id="wfrom"', 'id="local"', 'id="meta"', 'id="almenu"'):
        assert s in page
    assert '<th>History</th>' not in page  # single history type: no column
    assert "net-deleted" in page and "deleted</span>" in page
    assert "Not found" in page
    assert cwah_export.render_html(r.to_dict(), theme="auto").count('<html lang="en" data-theme="auto">') == 1
    with pytest.raises(ValueError):
        cwah_export.render_html(r.to_dict(), theme="sepia")


def test_html_multi_history_column_and_escaping():
    r = collect(history_types=cwah.HISTORY_TYPES)
    r.transitions[0].reason = "<!--<script>alert(1)</script>&amp;"
    page = cwah.render_html_report(r)
    assert "<th>History</th>" in page
    assert "<script>alert(1)" not in page and "<!--<script" not in page
    assert "\\u003c!--\\u003cscript\\u003e" in page  # escaped inside the embedded JSON
    assert "&lt;!--&lt;script&gt;" in page  # escaped in the raw JSON block


def test_csv_formula_injection_neutralised():
    hist = [_state_item("=HYPERLINK(\"x\")", "MetricAlarm", T0 + H, "OK", "ALARM")]
    r = collect(alarms=["=HYPERLINK(\"x\")"], cw=FakeCloudWatch(history=hist, alarms={}))
    rows = list(csv.DictReader(io.StringIO(cwah.render_csv(r))))
    assert rows[0]["alarm"].startswith("'=")
    assert cwah.csv_safe("+1") == "'+1" and cwah.csv_safe("ok") == "ok" and cwah.csv_safe(None) == ""


def test_write_report_paths(tmp_path):
    r = collect()
    paths = cwah.write_report(r, tmp_path, ["html", "csv", "json"])
    assert [p.suffix for p in paths] == [".html", ".csv", ".json"]
    assert paths[0].parent == tmp_path / "2026-11-06" / ACCOUNT
    assert paths[0].name.startswith("alarm_history_120000")
    with pytest.raises(SystemExit):
        cwah.write_report(r, tmp_path, ["xml"])


def test_print_summary(capsys):
    cwah.print_summary(collect(history_types=cwah.HISTORY_TYPES))
    out = capsys.readouterr().out
    assert "net-tgw-packet-drops" in out and "into ALARM: 3" in out and "not found: net-deleted" in out
    assert "ConfigurationUpdate" in out


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def test_read_alarms_file(tmp_path):
    f = tmp_path / "alarms.txt"
    f.write_text("# comment\nnet-a\n\n  net-b  \n")
    assert cwah.read_alarms_file(f) == ["net-a", "net-b"]


@pytest.fixture
def clean_env(monkeypatch):
    for k in ("CWAH_ALARMS", "CWAH_ALARMS_FILE", "CWAH_START", "CWAH_END", "CWAH_LAST", "CWAH_HISTORY_TYPES",
              "CWAH_ALARM_TYPES", "CWAH_OUT_DIR", "CWAH_FORMATS", "CWAH_THEME", "AWS_PROFILE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(cwah, "collect_alarm_history", lambda **kw: (_ for _ in ()).throw(AssertionError("AWS call")))


def test_main_with_injected_client(monkeypatch, tmp_path, capsys, clean_env):
    f = tmp_path / "alarms.txt"
    f.write_text("net-tgw-packet-drops\n")
    captured = {}

    orig = REAL_COLLECT

    def fake_collect(**kw):
        captured.update(kw)
        kw.update(cw=FakeCloudWatch(), account=ACCOUNT, now=NOW, start=T0, end=NOW)
        return orig(**kw)

    monkeypatch.setattr(cwah, "collect_alarm_history", fake_collect)
    rc = cwah.main(["--alarm", "net-dx-bgp-down,net-quiet", "--alarms-file", str(f), "--last", "3d",
                    "--history-types", "all", "--out-dir", str(tmp_path), "--formats", "html,csv", "--json",
                    "--profile", "hcli-net-ro", "--region", "us-west-2"])
    assert rc == 0
    assert captured["alarms"] == ["net-dx-bgp-down", "net-quiet", "net-tgw-packet-drops"]
    assert captured["history_types"] == list(cwah.HISTORY_TYPES)
    assert captured["profile"] == "hcli-net-ro" and captured["region"] == "us-west-2"
    assert (captured["end"] - captured["start"]) == timedelta(days=3)
    out = json.loads(capsys.readouterr().out)
    assert out["alarm_count"] == 3
    written = list(tmp_path.rglob("alarm_history_*"))
    assert {p.suffix for p in written} == {".html", ".csv"}


def test_main_bad_inputs_exit_2(tmp_path, clean_env):
    assert cwah.main(["--alarm", "x", "--start", "now", "--end", "1h", "--no-write"]) == 2
    assert cwah.main(["--alarm", "x", "--alarms-file", str(tmp_path / "nope"), "--no-write"]) == 2
    assert cwah.main(["--alarm", "x", "--start", "1h", "--last", "2h", "--no-write"]) == 2
    assert cwah.main(["--alarm", "x", "--formats", "html,xml"]) == 2
    assert cwah.main(["--alarm", "x", "--theme", "sepia"]) == 2
    assert cwah.main(["--alarm", "x", "--history-types", "Bogus", "--no-write"]) == 2
    assert cwah.main(["--alarm", "x", "--alarm-types", "metric", "--no-write"]) == 2
    assert cwah.main(["--no-write"]) == 2


def test_main_env_period_overridden_by_cli(monkeypatch, clean_env):
    captured = {}
    monkeypatch.setattr(cwah, "collect_alarm_history", lambda **kw: captured.update(kw) or (_ for _ in ()).throw(ValueError("stop")))
    monkeypatch.setenv("CWAH_LAST", "7d")
    assert cwah.main(["--alarm", "x", "--start", "2026-11-01T00:00Z", "--end", "2026-11-02T00:00Z", "--no-write"]) == 2
    assert captured["end"] - captured["start"] == timedelta(days=1)  # CLI --start wins over CWAH_LAST
    monkeypatch.setenv("CWAH_START", "2026-11-01T00:00Z")
    assert cwah.main(["--alarm", "x", "--last", "2h", "--end", "2026-11-02T00:00Z", "--no-write"]) == 2
    assert captured["end"] - captured["start"] == timedelta(hours=2)  # CLI --last wins over CWAH_START
    assert cwah.main(["--alarm", "x", "--end", "2026-11-03T00:00Z", "--no-write"]) == 2
    assert captured["start"] == datetime(2026, 11, 1, tzinfo=timezone.utc)  # env START wins over env LAST


def test_main_error_exit(monkeypatch, clean_env):
    orig = REAL_COLLECT
    monkeypatch.setattr(cwah, "collect_alarm_history",
                        lambda **kw: orig(**{**kw, "cw": FakeCloudWatch(deny={"net-quiet"}),
                                             "account": ACCOUNT, "now": NOW}))
    assert cwah.main(["--alarm", "net-quiet", "--no-write", "-q"]) == 1


# --------------------------------------------------------------------------- #
# concurrent ALARM intervals
# --------------------------------------------------------------------------- #
FIVE = ["net-dx-bgp-down", "net-tgw-packet-drops", "net-vpn-tunnel-status", "net-quiet", "net-stuck-alarm"]


def test_alarm_segments():
    r = collect(alarms=FIVE)
    segs = cwah.alarm_segments(r)
    assert segs["net-stuck-alarm"] == [(T0, NOW)]  # in ALARM all period, no transitions
    assert segs["net-dx-bgp-down"] == [(T0 + 2 * H, T0 + 2 * H + timedelta(minutes=15)), (T0 + 30 * H, T0 + 31 * H)]
    assert segs["net-tgw-packet-drops"] == [(T0 + 100 * H, NOW)]
    assert segs["net-quiet"] == [] and segs["net-vpn-tunnel-status"] == []
    # in ALARM at period start, clears at its first transition
    r2 = collect(alarms=["net-deleted"])
    assert cwah.alarm_segments(r2)["net-deleted"] == [(T0, T0 + 5 * H)]


def test_overlap_intervals_thresholds():
    r = collect(alarms=FIVE)
    assert cwah.overlap_intervals(r, threshold="all") == []
    assert cwah.overlap_intervals(r, threshold=3) == []
    two = cwah.overlap_intervals(r, threshold=2)
    assert [(i["start"][:16], i["end"][5:16], i["peak"], i["alarms"]) for i in two] == [
        ("2026-11-01T02:00", "11-01T02:15", 2, ["net-dx-bgp-down", "net-stuck-alarm"]),
        ("2026-11-02T06:00", "11-02T07:00", 2, ["net-dx-bgp-down", "net-stuck-alarm"]),
        ("2026-11-05T04:00", "11-06T12:00", 2, ["net-stuck-alarm", "net-tgw-packet-drops"]),
    ]
    assert two[0]["duration_s"] == 900 and two[0]["duration"] == "15m" and two[0]["threshold"] == 2 and two[0]["selected"] == 5
    one = cwah.overlap_intervals(r, threshold=1)
    assert len(one) == 1 and one[0]["start"] == r.start and one[0]["end"] == r.end and one[0]["peak"] == 2
    assert set(one[0]["alarms"]) == {"net-dx-bgp-down", "net-stuck-alarm", "net-tgw-packet-drops"}
    # selection restricts the alarms considered; "all" means all selected
    sel = cwah.overlap_intervals(r, alarms=["net-dx-bgp-down", "net-stuck-alarm"], threshold="all")
    assert [i["duration"] for i in sel] == ["15m", "1h"]
    assert cwah.overlap_intervals(r, alarms=["net-quiet"], threshold=1) == []
    assert cwah.overlap_intervals(r, threshold=0) == [] and cwah.overlap_intervals(r, threshold=9) == []


def test_overlap_back_to_back_does_not_overlap():
    t = T0 + H
    hist = [_state_item("a", "MetricAlarm", t, "OK", "ALARM"), _state_item("a", "MetricAlarm", t + H, "ALARM", "OK"),
            _state_item("b", "MetricAlarm", t + H, "OK", "ALARM"), _state_item("b", "MetricAlarm", t + 2 * H, "ALARM", "OK")]
    r = collect(alarms=["a", "b"], cw=FakeCloudWatch(history=hist, alarms={}))
    assert cwah.overlap_intervals(r, threshold=2) == []
    # adjacent intervals are reported separately, not merged
    assert [i["duration"] for i in cwah.overlap_intervals(r, threshold=1)] == ["1h", "1h"]


def test_overlap_in_json_and_summary(capsys):
    r = collect(alarms=FIVE)
    assert r.to_dict()["overlap"] == [] and r.to_dict()["overlap_threshold"] is None
    r.overlap_threshold = 2
    d = json.loads(cwah.render_json(r))
    assert len(d["overlap"]) == 3 and d["overlap_threshold"] == 2
    cwah.print_summary(r)
    out = capsys.readouterr().out
    assert "at least 2 of 5 alarms in ALARM: 3" in out and "peak 2" in out
    page = cwah.render_html_report(r)
    assert 'id="ovmenu"' in page and 'id="ovn"' in page and "Export intervals CSV" in page


def test_main_overlap_option_and_report_paths(monkeypatch, tmp_path, capsys, clean_env):
    monkeypatch.setattr(cwah, "collect_alarm_history",
                        lambda **kw: REAL_COLLECT(**{**kw, "cw": FakeCloudWatch(), "account": ACCOUNT, "now": NOW,
                                                     "start": T0, "end": NOW}))
    assert cwah.main(["--alarm", ",".join(FIVE), "--overlap", "2", "--out-dir", str(tmp_path), "--formats", "html,csv"]) == 0
    out = capsys.readouterr().out
    assert "in ALARM: 3" in out
    assert out.count("Report: ") == 2 and str(tmp_path) in out  # file names printed at the end
    assert cwah.main(["--alarm", "x", "--overlap", "0", "--no-write"]) == 2
    assert cwah.main(["--alarm", "x", "--overlap", "lots", "--no-write"]) == 2
