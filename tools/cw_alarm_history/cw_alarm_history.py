#!/usr/bin/env python3
"""Capture CloudWatch alarm state transitions for a list of alarms over a time period.

For every alarm named (or matching a name prefix), the tool reads the alarm's
``StateUpdate`` history between ``--start`` and ``--end`` (or the ``--last``
window) and writes one row per transition: when it happened, the state it left,
the state it entered, the reason CloudWatch gave, and how long the alarm then
stayed in the new state. The HTML report has in-page filters (alarm, from/to
state, text, time window) and a CSV export that honours those filters.

CloudWatch keeps alarm history for 30 days, including for deleted alarms, so
periods older than that come back empty. Read-only: no mutating API calls.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import logging
import os
import re
import ssl
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

if os.getenv("CWAH_NO_TRUSTSTORE") != "1":
    import truststore

    if ssl.SSLContext is not truststore.SSLContext:  # guard against double injection
        truststore.inject_into_ssl()

import boto3  # noqa: E402
from botocore.config import Config  # noqa: E402
from botocore.exceptions import BotoCoreError, ClientError  # noqa: E402
from dotenv import load_dotenv  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cwah_export import THEMES, render_html  # noqa: E402


def _find_dotenv() -> Path | None:
    """``.env`` next to the tool, else the nearest one in a parent of the tool directory."""
    here = Path(__file__).resolve().parent
    for d in (here, *here.parents):
        p = d / ".env"
        if p.is_file():
            return p
    return None


if (_p := _find_dotenv()) is not None:
    load_dotenv(_p)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("cw_alarm_history")
for _noisy in ("botocore", "boto3", "urllib3"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)

BOTO_CONFIG = Config(retries={"max_attempts": 8, "mode": "adaptive"})
ALARM_TYPES = ("MetricAlarm", "CompositeAlarm")
HISTORY_TYPES = ("StateUpdate", "ConfigurationUpdate", "Action")
REPORT_FORMATS = ("html", "csv", "json")
DEFAULT_LAST = "7d"
HISTORY_RETENTION_DAYS = 30
CSV_COLUMNS = (
    "alarm", "alarm_type", "timestamp_utc", "from_state", "to_state", "duration_s", "duration",
    "ongoing", "reason", "account", "region", "history_type", "summary",
)

_REL_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([smhdw])\s*$")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


# --------------------------------------------------------------------------- #
# Time helpers
# --------------------------------------------------------------------------- #
def parse_duration(text: str) -> timedelta:
    """``30m``, ``6h``, ``7d``, ``2w`` (also ``90s``, fractions allowed) to a timedelta."""
    m = _REL_RE.match(text or "")
    if not m:
        raise ValueError(f"not a duration: {text!r} (use e.g. 30m, 6h, 7d, 2w)")
    return timedelta(seconds=float(m.group(1)) * _UNIT_SECONDS[m.group(2).lower()])


def parse_when(text: str, *, now: datetime | None = None) -> datetime:
    """ISO 8601 (``2026-11-01``, ``2026-11-01T14:30``, ``...Z``, ``...+02:00``), ``now``, or a
    duration (``24h``, ``-24h``) meaning that long before now. Naive values are local time."""
    now = now or datetime.now(timezone.utc)
    t = (text or "").strip()
    if not t or t.lower() == "now":
        return now
    rel = t[1:] if t.startswith("-") else t
    if _REL_RE.match(rel):
        return now - parse_duration(rel)
    s = t[:-1] + "+00:00" if t.endswith(("Z", "z")) else t
    try:
        dt = datetime.fromisoformat(s)
    except ValueError as e:
        raise ValueError(f"not a date/time: {text!r} (use ISO 8601 such as 2026-11-01T14:30Z, or 24h for 24 hours ago)") from e
    if dt.tzinfo is None:
        dt = dt.astimezone()  # interpret as local time
    return dt.astimezone(timezone.utc)


def resolve_period(start: str | None, end: str | None, last: str | None,
                   now: datetime | None = None) -> tuple[datetime, datetime]:
    """Resolve ``--start/--end/--last`` into a UTC (start, end) pair."""
    now = now or datetime.now(timezone.utc)
    end_dt = parse_when(end, now=now) if end else now
    if end_dt > now:
        log.info("End %s is in the future; using now", _iso(end_dt))
        end_dt = now
    if start and last:
        raise ValueError("--start and --last are mutually exclusive")
    if start:
        start_dt = parse_when(start, now=now)
    else:
        start_dt = end_dt - parse_duration(last or DEFAULT_LAST)
    if start_dt >= end_dt:
        raise ValueError(f"start ({start_dt.isoformat()}) must be before end ({end_dt.isoformat()})")
    return start_dt, end_dt


def fmt_duration(seconds: float | None) -> str:
    """``1d 2h 3m 4s`` style, the two most significant units; ``-`` for None."""
    if seconds is None:
        return "-"
    s = int(round(seconds))
    if s < 60:
        return f"{s}s"
    parts = []
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60), ("s", 1)):
        if s >= size:
            parts.append(f"{s // size}{unit}")
            s %= size
    return " ".join(parts[:2])


def _iso(dt: datetime | None) -> str | None:
    """UTC ISO 8601 with a fixed millisecond precision, so string order is time order."""
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z") if dt else None


def _from_iso(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Transition:
    alarm: str
    alarm_type: str
    timestamp: str  # ISO 8601 UTC
    from_state: str | None
    to_state: str | None
    reason: str | None
    history_type: str
    summary: str | None
    duration_s: float | None = None  # seconds spent in to_state (until the next transition or period end)
    ongoing: bool = False  # True when the alarm was still in to_state at the end of the period
    reason_data: dict | None = None  # parsed newState.stateReasonData, when present

    @property
    def duration(self) -> str:
        return fmt_duration(self.duration_s)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["duration"] = self.duration
        return d


@dataclass
class AlarmSummary:
    alarm: str
    alarm_type: str | None
    exists: bool
    current_state: str | None
    state_updated: str | None
    state_at_start: str | None
    state_transitioned: str | None = None  # when the current state began
    transitions: int = 0
    into_alarm: int = 0
    seconds_in_alarm: float = 0.0
    error: str | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["time_in_alarm"] = fmt_duration(self.seconds_in_alarm)
        return d


@dataclass
class HistoryReport:
    generated_at: str
    account: str | None
    region: str
    start: str
    end: str
    history_types: list[str]
    alarms: list[AlarmSummary]
    transitions: list[Transition]
    alarms_not_found: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def date(self) -> str:
        return self.generated_at[:10]

    @property
    def state_transitions(self) -> list[Transition]:
        return [t for t in self.transitions if t.history_type == "StateUpdate"]

    def to_dict(self) -> dict:
        return {
            "generated_at": self.generated_at,
            "account": self.account,
            "region": self.region,
            "start": self.start,
            "end": self.end,
            "history_types": list(self.history_types),
            "retention_days": HISTORY_RETENTION_DAYS,
            "alarm_count": len(self.alarms),
            "transition_count": len(self.state_transitions),
            "into_alarm_count": sum(1 for t in self.state_transitions if t.to_state == "ALARM"),
            "seconds_in_alarm": sum(a.seconds_in_alarm for a in self.alarms),
            "time_in_alarm": fmt_duration(sum(a.seconds_in_alarm for a in self.alarms)),
            "alarms": [a.to_dict() for a in self.alarms],
            "transitions": [t.to_dict() for t in self.transitions],
            "alarms_not_found": list(self.alarms_not_found),
            "errors": list(self.errors),
        }


# --------------------------------------------------------------------------- #
# AWS access
# --------------------------------------------------------------------------- #
def get_session(profile: str | None, region: str | None) -> boto3.Session:
    return boto3.Session(profile_name=profile or None, region_name=region or None)


def get_client(service: str, session: boto3.Session, region: str | None = None):
    return session.client(service, region_name=region, config=BOTO_CONFIG)


def _paginate(client, op: str, key: str, **kwargs) -> Iterable[dict]:
    """Iterate every item of a paginated CloudWatch operation."""
    for page in client.get_paginator(op).paginate(**kwargs):
        yield from page.get(key, [])


def _chunks(seq: list, n: int) -> Iterable[list]:
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def describe_alarms(cw, names: list[str], prefixes: list[str], alarm_types: Iterable[str] = ALARM_TYPES) -> dict[str, dict]:
    """Current state and type of the named alarms plus every alarm matching a prefix, by name."""
    found: dict[str, dict] = {}
    types = list(alarm_types)
    for chunk in _chunks(sorted(set(names)), 100):
        for page in cw.get_paginator("describe_alarms").paginate(AlarmNames=chunk, AlarmTypes=types):
            for a in page.get("MetricAlarms", []):
                found[a["AlarmName"]] = {**a, "_type": "MetricAlarm"}
            for a in page.get("CompositeAlarms", []):
                found[a["AlarmName"]] = {**a, "_type": "CompositeAlarm"}
    for prefix in prefixes:
        n = 0
        for page in cw.get_paginator("describe_alarms").paginate(AlarmNamePrefix=prefix, AlarmTypes=types):
            for a in page.get("MetricAlarms", []):
                found[a["AlarmName"]] = {**a, "_type": "MetricAlarm"}
                n += 1
            for a in page.get("CompositeAlarms", []):
                found[a["AlarmName"]] = {**a, "_type": "CompositeAlarm"}
                n += 1
        log.info("Prefix %r matched %d alarm(s)", prefix, n)
    return found


def _parse_history_data(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        d = json.loads(raw)
        return d if isinstance(d, dict) else {}
    except (TypeError, ValueError):
        return {}


def _state_block(d: dict, key: str) -> dict:
    v = d.get(key)
    return v if isinstance(v, dict) else {}


def fetch_history(cw, alarm: str, start: datetime, end: datetime, history_types: Iterable[str],
                  alarm_types: Iterable[str] = ALARM_TYPES) -> list[Transition]:
    """Every history item for one alarm in [start, end], oldest first.

    One API call series per alarm: a single history type is passed to the API, several are
    read in one unfiltered pass and filtered here.
    """
    wanted = list(history_types)
    items: list[Transition] = []
    kwargs: dict[str, Any] = dict(AlarmName=alarm, StartDate=start, EndDate=end,
                                  ScanBy="TimestampAscending", AlarmTypes=list(alarm_types))
    if len(wanted) == 1:
        kwargs["HistoryItemType"] = wanted[0]
    for it in _paginate(cw, "describe_alarm_history", "AlarmHistoryItems", **kwargs):
        htype = it.get("HistoryItemType") or (wanted[0] if len(wanted) == 1 else "")
        if htype in wanted:
            data = _parse_history_data(it.get("HistoryData"))
            old, new = _state_block(data, "oldState"), _state_block(data, "newState")
            ts = it.get("Timestamp")
            items.append(Transition(
                alarm=it.get("AlarmName") or alarm,
                alarm_type=it.get("AlarmType") or "",
                timestamp=_iso(ts) if isinstance(ts, datetime) else _iso(_from_iso(str(ts))),
                from_state=old.get("stateValue") if htype == "StateUpdate" else None,
                to_state=new.get("stateValue") if htype == "StateUpdate" else None,
                reason=new.get("stateReason") if htype == "StateUpdate" else None,
                history_type=htype,
                summary=it.get("HistorySummary"),
                reason_data=new.get("stateReasonData") if isinstance(new.get("stateReasonData"), dict) else None,
            ))
    items.sort(key=lambda t: _from_iso(t.timestamp))
    return items


def _fill_durations(items: list[Transition], end: datetime) -> None:
    """Set each StateUpdate's time in its new state: until the next StateUpdate, else the period end."""
    updates = [t for t in items if t.history_type == "StateUpdate"]
    for cur, nxt in zip(updates, updates[1:] + [None]):
        t0 = _from_iso(cur.timestamp)
        if nxt is None:
            cur.ongoing = True
            t1 = end
        else:
            t1 = _from_iso(nxt.timestamp)
        cur.duration_s = max(0.0, (t1 - t0).total_seconds())


def _canon(values: Iterable[str], allowed: tuple[str, ...], what: str) -> list[str]:
    """Case-insensitive match against ``allowed``; duplicates dropped; errors name the choices."""
    out: list[str] = []
    for v in values:
        hit = next((a for a in allowed if a.lower() == str(v).strip().lower()), None)
        if hit is None:
            raise ValueError(f"unknown {what} {v!r}; choose from {', '.join(allowed)}")
        if hit not in out:
            out.append(hit)
    if not out:
        raise ValueError(f"no {what} given; choose from {', '.join(allowed)}")
    return out


def csv_safe(v: Any) -> str:
    """Neutralise spreadsheet formula injection: cells starting with = + - @ get a leading quote."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


# --------------------------------------------------------------------------- #
# Public entry point (kwargs API)
# --------------------------------------------------------------------------- #
def collect_alarm_history(
    *,
    alarms: Iterable[str] = (),
    prefixes: Iterable[str] = (),
    start: datetime,
    end: datetime,
    history_types: Iterable[str] = ("StateUpdate",),
    alarm_types: Iterable[str] = ALARM_TYPES,
    region: str = "us-east-1",
    profile: str | None = None,
    cw=None,
    account: str | None = None,
    now: datetime | None = None,
) -> HistoryReport:
    """Read the history of every alarm (named, or matching a prefix) between ``start`` and ``end``.

    ``cw`` and ``account`` let callers (and tests) inject a CloudWatch client and skip STS.
    """
    now = now or datetime.now(timezone.utc)
    names = sorted({a.strip() for a in alarms if a and a.strip()})
    prefixes = [p for p in prefixes if p]
    if not names and not prefixes:
        raise ValueError("no alarms given: pass --alarm, --alarms-file or --alarm-prefix")
    history_types = _canon(history_types, HISTORY_TYPES, "history type")
    alarm_types = _canon(alarm_types, ALARM_TYPES, "alarm type")
    if end > now:
        log.info("End %s is in the future; using now", _iso(end))
        end = now
    if start >= end:
        raise ValueError(f"start ({_iso(start)}) must be before end ({_iso(end)})")

    if cw is None:
        session = get_session(profile, region)
        cw = get_client("cloudwatch", session, region)
        if account is None:
            try:
                account = get_client("sts", session).get_caller_identity()["Account"]
            except (ClientError, BotoCoreError, KeyError) as e:
                log.warning("Could not resolve the account ID: %s", e)

    if (now - start).days > HISTORY_RETENTION_DAYS:
        log.warning("Start is more than %d days ago; CloudWatch only keeps alarm history for %d days",
                    HISTORY_RETENTION_DAYS, HISTORY_RETENTION_DAYS)
    log.info("Alarm history %s → %s in %s (%s)", _iso(start), _iso(end), region, ", ".join(history_types))

    current = describe_alarms(cw, names, prefixes, alarm_types)
    targets = sorted(set(names) | set(current))
    not_found = [n for n in names if n not in current]
    for n in not_found:
        log.warning("Alarm %r not found (deleted alarms still have history for %d days)", n, HISTORY_RETENTION_DAYS)

    summaries: list[AlarmSummary] = []
    transitions: list[Transition] = []
    errors: list[str] = []
    for name in targets:
        cur = current.get(name)
        cur = cur or {}
        transitioned = cur.get("StateTransitionedTimestamp") or cur.get("StateUpdatedTimestamp")
        base = dict(alarm=name, alarm_type=cur.get("_type"), exists=bool(cur), current_state=cur.get("StateValue"),
                    state_updated=_iso(cur.get("StateUpdatedTimestamp")), state_transitioned=_iso(transitioned))
        try:
            items = fetch_history(cw, name, start, end, history_types, alarm_types)
        except ClientError as e:
            msg = f"{name}: {e.response.get('Error', {}).get('Code')}: {e.response.get('Error', {}).get('Message')}"
            log.error("AWS error reading history for %s: %s", name, msg)
            errors.append(msg)
            summaries.append(AlarmSummary(**base, state_at_start=None, error=msg))
            continue
        _fill_durations(items, end)
        updates = [t for t in items if t.history_type == "StateUpdate"]
        base["alarm_type"] = base["alarm_type"] or next((t.alarm_type for t in items if t.alarm_type), None)
        if updates:
            state_at_start = updates[0].from_state
            first = _from_iso(updates[0].timestamp)
        elif cur and transitioned is not None and transitioned <= start:
            state_at_start = cur.get("StateValue")  # current state already held at the period start
            first = end
        else:
            state_at_start = None  # unknown: no transition in the period and the current state began later
            first = end
        in_alarm = sum(t.duration_s or 0 for t in updates if t.to_state == "ALARM")
        if state_at_start == "ALARM":
            in_alarm += (first - start).total_seconds()  # time in ALARM before the first transition
        summaries.append(AlarmSummary(
            **base,
            state_at_start=state_at_start,
            transitions=len(updates),
            into_alarm=sum(1 for t in updates if t.to_state == "ALARM"),
            seconds_in_alarm=in_alarm,
        ))
        log.info("%-60s %3d transition(s), %d into ALARM", name[:60], len(updates),
                 sum(1 for t in updates if t.to_state == "ALARM"))
        transitions.extend(items)

    transitions.sort(key=lambda t: (_from_iso(t.timestamp), t.alarm))
    return HistoryReport(
        generated_at=_iso(now), account=account, region=region, start=_iso(start), end=_iso(end),
        history_types=history_types, alarms=summaries, transitions=transitions,
        alarms_not_found=not_found, errors=errors,
    )


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def render_json(report: HistoryReport) -> str:
    return json.dumps(report.to_dict(), indent=2, default=str)


def render_csv(report: HistoryReport) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(CSV_COLUMNS)
    for t in report.transitions:
        w.writerow([csv_safe(v) for v in (
            t.alarm, t.alarm_type, t.timestamp, t.from_state or "", t.to_state or "",
            "" if t.duration_s is None else int(round(t.duration_s)), t.duration if t.duration_s is not None else "",
            "yes" if t.ongoing else "", t.reason or "", report.account or "", report.region, t.history_type, t.summary or "",
        )])
    return buf.getvalue()


def render_html_report(report: HistoryReport, theme: str = "dark") -> str:
    return render_html(report.to_dict(), theme=theme)


RENDERERS = {"json": render_json, "csv": render_csv, "html": render_html_report}


def write_report(report: HistoryReport, out_dir: Path, formats: Iterable[str] = ("html",),
                 theme: str = "dark") -> list[Path]:
    """Write <out_dir>/<YYYY-MM-DD>/<account>/alarm_history_<HHMMSS>.{html,csv,json}; return paths."""
    ts = _from_iso(report.generated_at)
    day_dir = out_dir / report.date / (report.account or "unknown-account")
    day_dir.mkdir(parents=True, exist_ok=True)
    stem = f"alarm_history_{ts.strftime('%H%M%S')}"
    paths: list[Path] = []
    for fmt in formats:
        if fmt not in RENDERERS:
            raise SystemExit(f"Unknown report format {fmt!r}; choose from {', '.join(REPORT_FORMATS)}")
        path = day_dir / f"{stem}.{fmt}"
        text = render_html_report(report, theme) if fmt == "html" else RENDERERS[fmt](report)
        path.write_text(text, encoding="utf-8")
        paths.append(path)
    return paths


def print_summary(report: HistoryReport) -> None:
    d = report.to_dict()
    print(f"\n=== Alarm history {report.start} → {report.end}  account={report.account or '?'} region={report.region} ===")
    print(f"alarms: {d['alarm_count']}  transitions: {d['transition_count']}  into ALARM: {d['into_alarm_count']}  "
          f"time in ALARM: {d['time_in_alarm']}")
    if report.alarms_not_found:
        print(f"not found: {', '.join(report.alarms_not_found)}")
    hdr = f"{'ALARM':<50} {'TYPE':<10} {'NOW':<17} {'AT START':<17} {'TRANS':>5} {'→ALARM':>6}  IN ALARM"
    print(hdr)
    print("-" * len(hdr))
    for a in report.alarms:
        if a.error:
            print(f"{a.alarm[:50]:<50} ERROR: {a.error}")
            continue
        print(f"{a.alarm[:50]:<50} {(a.alarm_type or '?')[:10]:<10} {(a.current_state or '?'):<17} "
              f"{(a.state_at_start or '?'):<17} {a.transitions:>5} {a.into_alarm:>6}  {fmt_duration(a.seconds_in_alarm)}")
    if report.transitions:
        print()
        hdr = f"{'TIMESTAMP (UTC)':<21} {'ALARM':<40} {'FROM':<17} {'TO':<17} {'FOR':>9}  REASON"
        print(hdr)
        print("-" * len(hdr))
        for t in report.transitions:
            if t.history_type != "StateUpdate":
                print(f"{t.timestamp[:19]:<21} {t.alarm[:40]:<40} {t.history_type:<35} {'':>9}  {(t.summary or '')[:70]}")
                continue
            tail = f"{t.duration}{'+' if t.ongoing else ''}"
            print(f"{t.timestamp[:19]:<21} {t.alarm[:40]:<40} {(t.from_state or '?'):<17} {(t.to_state or '?'):<17} "
                  f"{tail:>9}  {(t.reason or '')[:70]}")
    print()


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _split_csv(values: Iterable[str] | None) -> list[str]:
    out: list[str] = []
    for v in values or ():
        out.extend(x.strip() for x in v.split(",") if x.strip())
    return out


def read_alarms_file(path: str | os.PathLike) -> list[str]:
    """One alarm name per line; blank lines and ``#`` comments ignored."""
    names: list[str] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            names.append(s)
    return names


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--alarm", "-a", action="append", default=[], metavar="NAME",
                   help="Alarm name; repeat or comma-separate (default: $CWAH_ALARMS)")
    p.add_argument("--alarms-file", default=os.getenv("CWAH_ALARMS_FILE"), metavar="FILE",
                   help="File with one alarm name per line (# comments allowed)")
    p.add_argument("--alarm-prefix", action="append", default=[], metavar="PREFIX",
                   help="Include every alarm whose name starts with PREFIX; repeatable")
    p.add_argument("--start", help="Period start: ISO 8601 (2026-11-01T14:30Z; naive = local time) or a duration "
                                   "ago (36h, 3d; write --start=-36h for the signed form) ($CWAH_START)")
    p.add_argument("--end", help="Period end, same forms as --start (default: now; $CWAH_END)")
    p.add_argument("--last", help=f"Window ending at --end: 30m, 6h, 7d, 2w (default {DEFAULT_LAST}; not with "
                                  "--start; $CWAH_LAST)")
    p.add_argument("--history-types", default=os.getenv("CWAH_HISTORY_TYPES", "StateUpdate"),
                   help="Comma-separated: StateUpdate (default), ConfigurationUpdate, Action, or all")
    p.add_argument("--alarm-types", default=os.getenv("CWAH_ALARM_TYPES", ",".join(ALARM_TYPES)),
                   help="Comma-separated: MetricAlarm, CompositeAlarm (default both)")
    p.add_argument("--profile", default=os.getenv("AWS_PROFILE"), help="AWS profile (default: $AWS_PROFILE / credential chain)")
    p.add_argument("--region", default=os.getenv("AWS_REGION", "us-east-1"), help="Region of the alarms (default us-east-1)")
    p.add_argument("--out-dir", default=os.getenv("CWAH_OUT_DIR", "reports"),
                   help="Report root; files land in <out-dir>/<date>/<account>/ (default reports)")
    p.add_argument("--formats", default=os.getenv("CWAH_FORMATS", "html"),
                   help="Comma-separated report formats to write: html (default), csv, json")
    p.add_argument("--theme", default=os.getenv("CWAH_THEME", "dark"),
                   help="HTML report theme: dark (default), light, or auto (follow the OS); toggle in-page")
    p.add_argument("--json", action="store_true", help="Print the JSON report to stdout instead of the table")
    p.add_argument("--no-write", action="store_true", help="Do not write report files")
    p.add_argument("-v", "--verbose", "--debug", action="store_true", help="Debug logging, including botocore")
    p.add_argument("-q", "--quiet", action="store_true", help="Warnings only")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("botocore").setLevel(logging.INFO)
    elif args.quiet:
        logging.getLogger().setLevel(logging.WARNING)

    alarms = _split_csv(args.alarm) or _split_csv([os.getenv("CWAH_ALARMS", "")])
    if args.alarms_file:
        try:
            alarms += read_alarms_file(args.alarms_file)
        except OSError as e:
            log.error("Cannot read %s: %s", args.alarms_file, e)
            return 2
    history_types = _split_csv([args.history_types])
    if any(h.lower() == "all" for h in history_types):
        history_types = list(HISTORY_TYPES)
    formats = [f.strip().lower() for f in args.formats.split(",") if f.strip()]
    # A CLI --start or --last overrides both CWAH_START and CWAH_LAST from the environment.
    start_s, last_s, end_s = args.start, args.last, args.end or os.getenv("CWAH_END")
    if start_s is None and last_s is None:
        start_s, last_s = os.getenv("CWAH_START") or None, os.getenv("CWAH_LAST") or None
        if start_s and last_s:
            log.warning("Both CWAH_START and CWAH_LAST are set; using CWAH_START")
            last_s = None
    try:
        bad = [f for f in formats if f not in REPORT_FORMATS]
        if bad or not formats:
            raise ValueError(f"unknown format(s) {', '.join(bad) or '(none)'}; choose from {', '.join(REPORT_FORMATS)}")
        if args.theme not in THEMES:
            raise ValueError(f"unknown theme {args.theme!r}; choose from {', '.join(THEMES)}")
        _canon(history_types, HISTORY_TYPES, "history type")
        _canon(_split_csv([args.alarm_types]), ALARM_TYPES, "alarm type")
        if not alarms and not args.alarm_prefix:
            raise ValueError("no alarms given: pass --alarm, --alarms-file or --alarm-prefix")
        start, end = resolve_period(start_s, end_s, last_s)
        report = collect_alarm_history(
            alarms=alarms, prefixes=args.alarm_prefix, start=start, end=end,
            history_types=history_types, alarm_types=_split_csv([args.alarm_types]),
            region=args.region, profile=args.profile,
        )
    except ValueError as e:
        log.error("%s", e)
        return 2
    except ClientError as e:
        log.error("AWS error %s: %s", e.response["Error"]["Code"], e.response["Error"]["Message"])
        return 1
    except BotoCoreError as e:
        log.error("AWS error: %s", e)
        return 1

    if not args.no_write:
        for path in write_report(report, Path(args.out_dir), formats, args.theme):
            log.info("Report written to %s", path)
    if args.json:
        print(render_json(report))
    else:
        print_summary(report)
    if report.errors:
        log.warning("%d alarm(s) could not be read; see errors", len(report.errors))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
