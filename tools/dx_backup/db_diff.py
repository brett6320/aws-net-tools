"""Compare two dx_backup snapshots, object by object and field by field.

Lists whose order means nothing are matched by a stable key before comparing: BGP
peers by address family and customer address, prefixes by CIDR, tags by key, gateway
associations by the associated gateway, attachments by VIF, routes by direction and
prefix. Operational state (BGP status, object state, LOA times, device names, pool
counters, route install times) changes on its own, so it's left out unless asked for.
"""
from __future__ import annotations

from typing import Any

import db_core as core

# Fields that describe state rather than configuration.
STATE_KEYS = {
    "connectionState", "lagState", "virtualInterfaceState", "directConnectGatewayState", "associationState",
    "attachmentState", "proposalState", "bgpPeerState", "bgpStatus", "stateChangeError", "loaIssueTime",
    "prefixPoolUnallocatedCountIpv4",
    "prefixPoolUnallocatedCountIpv6", "totalPrefixPoolAllocations", "rateLimiterStatus", "portEncryptionStatus",
    "awsDevice", "awsDeviceV2", "awsLogicalDeviceId", "bgpPeerId", "installed", "device", "startOn", "state",
}

# Keyed lists: name -> function giving each element's key.
_KEYS = {
    "bgpPeers": lambda p: f"{p.get('addressFamily')} {p.get('customerAddress')}",
    "routeFilterPrefixes": lambda p: p.get("cidr"),
    "allowedPrefixesToDirectConnectGateway": lambda p: p.get("cidr"),
    "existingAllowedPrefixesToDirectConnectGateway": lambda p: p.get("cidr"),
    "requestedAllowedPrefixesToDirectConnectGateway": lambda p: p.get("cidr"),
    "connections": lambda c: c.get("connectionId"),
    "macSecKeys": lambda k: k.get("ckn") or k.get("secretARN"),
    "associations": lambda a: (a.get("associatedGateway") or {}).get("id") or a.get("virtualGatewayId")
    or a.get("associationId"),
    "attachments": lambda a: a.get("virtualInterfaceId"),
    "proposals": lambda p: p.get("proposalId"),
    "advertised": lambda r: r.get("cidr"),
    "accepted": lambda r: r.get("cidr"),
}
_SETS = {"routeFilterPrefixes", "allowedPrefixesToDirectConnectGateway",
         "existingAllowedPrefixesToDirectConnectGateway", "requestedAllowedPrefixesToDirectConnectGateway"}
_SKIP = {"kind", "id", "region"}


class Keyed(dict):
    """A list turned into {key: element}; its entries print as name[key]."""


class PrefixSet(Keyed):
    """A list of prefixes turned into {cidr: True}."""


def _as_path_text(as_path: list[dict]) -> str:
    parts = []
    for seg in as_path or []:
        nums = [str(a) for a in seg.get("path") or []]
        parts.append("{" + ",".join(nums) + "}" if seg.get("type") == "set" else " ".join(nums))
    return " ".join(p for p in parts if p) or "(empty)"


def canonical(value: Any, name: str = "", state: bool = False) -> Any:
    """Turn keyed lists into dicts, tags into {key: value}, prefix lists into sets of
    CIDRs and AS paths into text, and drop state fields unless state=True."""
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if k in _SKIP and name == "" or (not state and k in STATE_KEYS):
                continue
            out[k] = canonical(v, k, state)
        return out
    if isinstance(value, list):
        if name == "tags":
            return Keyed((t.get("key"), t.get("value")) for t in value)
        if name == "as_path":
            return _as_path_text(value)
        if name in _SETS:
            return PrefixSet((_KEYS[name](p), True) for p in value)
        if name in _KEYS:
            out = Keyed()
            for el in value:
                key = str(_KEYS[name](el))
                n, base = 2, key
                while key in out:      # duplicate keys stay distinct
                    key, n = f"{base} #{n}", n + 1
                out[key] = canonical(el, name + "[]", state)
            return out
        return [canonical(v, name, state) for v in value]
    return value


def _walk(old: Any, new: Any, path: str, out: list[tuple[str, Any, Any]]) -> None:
    if isinstance(old, dict) and isinstance(new, dict):
        keyed = isinstance(old, Keyed) or isinstance(new, Keyed)
        for k in sorted(set(old) | set(new), key=str):
            p = f"{path}[{k}]" if keyed else (f"{path}.{k}" if path else str(k))
            if k not in old:
                out.append((p, None, new[k]))
            elif k not in new:
                out.append((p, old[k], None))
            else:
                _walk(old[k], new[k], p, out)
    elif old != new:
        out.append((path, old, new))


def _flatten_record(rec: dict, state: bool) -> dict:
    """The comparable part of a stored record: the API item plus gateway/route extras."""
    body = {k: v for k, v in rec.items() if k not in _SKIP}
    if "item" in body:
        item = body.pop("item")
        body = {**item, **body}
    return canonical(body, "", state)


def diff(old: dict, new: dict, state: bool = False) -> list[dict]:
    """Changes from snapshot old to snapshot new: one entry per object added (+),
    removed (-) or changed (~), each changed one with its (field, before, after) list."""
    changes = []
    order = {k: i for i, k in enumerate(core.KINDS)}
    keys = sorted(set(old["objects"]) | set(new["objects"]),
                  key=lambda k: (order.get(k.split("/", 1)[0], len(order)), k))
    for key in keys:
        a, b = old["objects"].get(key), new["objects"].get(key)
        ref = b or a
        entry = {"key": key, "kind": ref["kind"], "id": ref["id"], "region": ref.get("region"),
                 "name": core.object_name(b) or core.object_name(a) or core.object_name(old["objects"].get(
                     f"vif/{ref['id']}")) or core.object_name(new["objects"].get(f"vif/{ref['id']}"))}
        if a is None:
            changes.append({**entry, "op": "+", "fields": []})
        elif b is None:
            changes.append({**entry, "op": "-", "fields": []})
        else:
            fields: list[tuple[str, Any, Any]] = []
            _walk(_flatten_record(a, state), _flatten_record(b, state), "", fields)
            if fields:
                changes.append({**entry, "op": "~", "fields": fields})
    return changes


def summary(changes: list[dict]) -> dict[str, int]:
    return {op: sum(1 for c in changes if c["op"] == op) for op in "+-~"}


# ---------- text ----------

LABELS = {"connection": "connection", "lag": "LAG", "vif": "VIF", "dx-gateway": "Direct Connect gateway",
          "routes": "routes of VIF"}


def show(value: Any) -> str:
    if value is None:
        return "(none)"
    if core.is_fingerprint(value):
        return "auth key " + value.split(":", 1)[1][:12] + "…"
    if isinstance(value, dict) and "cidr" in value and "as_path" in value:     # a route
        comm = value.get("communities") or []
        return f"AS path {value['as_path']}" + (f", communities {' '.join(comm)}" if comm else "")
    if isinstance(value, PrefixSet):
        return ", ".join(map(str, value)) or "(empty)"
    if isinstance(value, dict):
        return "{" + ", ".join(f"{k}: {show(v)}" for k, v in value.items()) + "}"
    if isinstance(value, list):
        return "[" + ", ".join(show(v) for v in value) + "]"
    return str(value)


def heading(c: dict) -> str:
    name = f" ({c['name']})" if c.get("name") else ""
    where = f", {c['region']}" if c.get("region") else ""
    return f"{c['op']} {LABELS.get(c['kind'], c['kind'])} {c['id']}{name}{where}"


def field_line(path: str, before: Any, after: Any) -> str:
    if before is True or after is True:          # a prefix-set member
        return f"{'+' if after is True else '-'} {path}"
    if before is None:
        return f"+ {path}: {show(after)}"
    if after is None:
        return f"- {path}: {show(before)}"
    if core.is_fingerprint(before) and core.is_fingerprint(after):
        return f"~ {path}: auth key changed"
    return f"~ {path}: {show(before)} -> {show(after)}"


def render_text(changes: list[dict], old_m: dict, new_m: dict) -> str:
    lines = [f"Old: {describe(old_m)}", f"New: {describe(new_m)}", ""]
    if not changes:
        return "\n".join(lines + ["No configuration changes."]) + "\n"
    s = summary(changes)
    lines.append(f"{s['+']} added, {s['-']} removed, {s['~']} changed")
    for c in changes:
        lines += ["", heading(c)]
        lines += [f"    {field_line(*f)}" for f in c["fields"]]
    return "\n".join(lines) + "\n"


def describe(m: dict) -> str:
    where = m.get("path") or "live"
    return f"{where} (account {m.get('account')}, {', '.join(m.get('regions') or [])}, {m.get('generated')})"
