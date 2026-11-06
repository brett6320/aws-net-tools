"""In-memory stand-in for the CloudWatch alarm APIs, with a small synthetic alarm set.

Account 111111111111, us-east-1. Alarms:
  net-dx-bgp-down        metric alarm, flaps OK -> ALARM -> OK twice, ends OK
  net-tgw-packet-drops   metric alarm, goes to ALARM near the end and stays there
  net-vpn-tunnel-status  composite alarm, one INSUFFICIENT_DATA episode
  net-quiet              metric alarm, no history in the period
Alarm "net-deleted" no longer exists but still has one history item.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

ACCOUNT = "111111111111"
T0 = datetime(2026, 11, 1, 0, 0, tzinfo=timezone.utc)
NOW = datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)


def _reason(state: str, value: float) -> str:
    if state == "ALARM":
        return f"Threshold Crossed: 1 datapoint [{value}] was greater than the threshold (5.0)."
    if state == "OK":
        return f"Threshold Crossed: 1 datapoint [{value}] was not greater than the threshold (5.0)."
    return "Insufficient Data: 1 datapoint was unknown."


def _state_item(name: str, atype: str, ts: datetime, old: str, new: str, value: float = 7.0) -> dict:
    data = {
        "version": "1.0",
        "oldState": {"stateValue": old, "stateReason": _reason(old, 1.0)},
        "newState": {
            "stateValue": new, "stateReason": _reason(new, value),
            "stateReasonData": {"version": "1.0", "queryDate": ts.isoformat(), "statistic": "Sum",
                                "period": 60, "recentDatapoints": [value], "threshold": 5.0},
        },
    }
    return {"AlarmName": name, "AlarmType": atype, "Timestamp": ts, "HistoryItemType": "StateUpdate",
            "HistorySummary": f"Alarm updated from {old} to {new}", "HistoryData": json.dumps(data)}


def _action_item(name: str, ts: datetime) -> dict:
    return {"AlarmName": name, "AlarmType": "MetricAlarm", "Timestamp": ts, "HistoryItemType": "Action",
            "HistorySummary": "Successfully executed action arn:aws:sns:us-east-1:111111111111:net-alerts",
            "HistoryData": json.dumps({"actionState": "Succeeded", "notificationResource": "arn:aws:sns:..."})}


def _config_item(name: str, ts: datetime) -> dict:
    return {"AlarmName": name, "AlarmType": "MetricAlarm", "Timestamp": ts, "HistoryItemType": "ConfigurationUpdate",
            "HistorySummary": "Alarm \"net-dx-bgp-down\" updated", "HistoryData": json.dumps({"version": "1.0", "type": "Update"})}


H = timedelta(hours=1)
HISTORY: list[dict] = [
    _state_item("net-dx-bgp-down", "MetricAlarm", T0 + 2 * H, "OK", "ALARM", 9.0),
    _action_item("net-dx-bgp-down", T0 + 2 * H + timedelta(seconds=1)),
    _state_item("net-dx-bgp-down", "MetricAlarm", T0 + 2 * H + timedelta(minutes=15), "ALARM", "OK", 0.0),
    _state_item("net-dx-bgp-down", "MetricAlarm", T0 + 30 * H, "OK", "ALARM", 12.0),
    _state_item("net-dx-bgp-down", "MetricAlarm", T0 + 31 * H, "ALARM", "OK", 0.0),
    _config_item("net-dx-bgp-down", T0 + 40 * H),
    _state_item("net-tgw-packet-drops", "MetricAlarm", T0 + 100 * H, "OK", "ALARM", 50.0),
    _state_item("net-vpn-tunnel-status", "CompositeAlarm", T0 + 10 * H, "OK", "INSUFFICIENT_DATA", 0.0),
    _state_item("net-vpn-tunnel-status", "CompositeAlarm", T0 + 12 * H, "INSUFFICIENT_DATA", "OK", 1.0),
    _state_item("net-deleted", "MetricAlarm", T0 + 5 * H, "ALARM", "OK", 0.0),
    # outside the default test period (before T0)
    _state_item("net-dx-bgp-down", "MetricAlarm", T0 - 5 * H, "ALARM", "OK", 0.0),
]

ALARMS = {
    "net-dx-bgp-down": {"AlarmName": "net-dx-bgp-down", "StateValue": "OK", "StateUpdatedTimestamp": T0 + 31 * H,
                        "StateTransitionedTimestamp": T0 + 31 * H, "_kind": "MetricAlarms"},
    "net-tgw-packet-drops": {"AlarmName": "net-tgw-packet-drops", "StateValue": "ALARM",
                             "StateUpdatedTimestamp": T0 + 100 * H, "StateTransitionedTimestamp": T0 + 100 * H,
                             "_kind": "MetricAlarms"},
    "net-vpn-tunnel-status": {"AlarmName": "net-vpn-tunnel-status", "StateValue": "OK",
                              "StateUpdatedTimestamp": T0 + 12 * H, "StateTransitionedTimestamp": T0 + 12 * H,
                              "_kind": "CompositeAlarms"},
    # quiet all period; its StateUpdatedTimestamp moved (reason refresh) but the state began before T0
    "net-quiet": {"AlarmName": "net-quiet", "StateValue": "OK", "StateUpdatedTimestamp": T0 + 1 * H,
                  "StateTransitionedTimestamp": T0 - 30 * H, "_kind": "MetricAlarms"},
    # in ALARM for the whole period, no transitions
    "net-stuck-alarm": {"AlarmName": "net-stuck-alarm", "StateValue": "ALARM", "StateUpdatedTimestamp": T0 - 2 * H,
                        "StateTransitionedTimestamp": T0 - 2 * H, "_kind": "MetricAlarms"},
    "other-unrelated": {"AlarmName": "other-unrelated", "StateValue": "OK", "StateUpdatedTimestamp": T0,
                        "StateTransitionedTimestamp": T0, "_kind": "MetricAlarms"},
}


class _Paginator:
    def __init__(self, fn):
        self.fn = fn

    def paginate(self, **kwargs):
        return self.fn(**kwargs)


class FakeCloudWatch:
    """Supports get_paginator('describe_alarms') and get_paginator('describe_alarm_history')."""

    def __init__(self, history=None, alarms=None, page_size: int = 2, deny: set[str] | None = None):
        self.history = list(history if history is not None else HISTORY)
        self.alarms = dict(alarms if alarms is not None else ALARMS)
        self.page_size = page_size
        self.deny = deny or set()
        self.calls: list[tuple[str, dict]] = []

    def get_paginator(self, op: str):
        if op == "describe_alarms":
            return _Paginator(self._describe_alarms)
        if op == "describe_alarm_history":
            return _Paginator(self._describe_alarm_history)
        raise ValueError(op)

    def _describe_alarms(self, **kw):
        self.calls.append(("describe_alarms", kw))
        names, prefix = kw.get("AlarmNames"), kw.get("AlarmNamePrefix")
        types = kw.get("AlarmTypes") or ["MetricAlarm", "CompositeAlarm"]
        sel = [a for n, a in sorted(self.alarms.items())
               if (names is None or n in names) and (prefix is None or n.startswith(prefix))
               and a["_kind"][:-1] in types]
        for i in range(0, max(len(sel), 1), self.page_size):
            chunk = sel[i:i + self.page_size]
            page = {"MetricAlarms": [], "CompositeAlarms": []}
            for a in chunk:
                page[a["_kind"]].append({k: v for k, v in a.items() if k != "_kind"})
            yield page

    def _describe_alarm_history(self, **kw):
        self.calls.append(("describe_alarm_history", kw))
        name = kw["AlarmName"]
        if name in self.deny:
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "nope"}}, "DescribeAlarmHistory")
        htype, start, end = kw.get("HistoryItemType"), kw.get("StartDate"), kw.get("EndDate")
        sel = [h for h in self.history if h["AlarmName"] == name
               and (htype is None or h["HistoryItemType"] == htype)
               and (start is None or h["Timestamp"] >= start) and (end is None or h["Timestamp"] <= end)]
        sel.sort(key=lambda h: h["Timestamp"], reverse=kw.get("ScanBy") != "TimestampAscending")
        for i in range(0, max(len(sel), 1), self.page_size):
            yield {"AlarmHistoryItems": sel[i:i + self.page_size]}
