"""Render Reachability Analyzer path + analysis data to a self-contained HTML file.

No external assets: CSS and SVG icons are inlined. Every field returned by the
EC2 API for the path and analysis is rendered; fields without a dedicated
formatter fall back to a generic key/value rendering so nothing is dropped.
"""
from __future__ import annotations

import datetime as dt
import json
import re
from html import escape
from typing import Any

from ra_accounts import ROLE_SUGGESTED, account_summary, arn_account, component_account
from ra_codes import describe_code
from ra_icons import classify, icon_svg, label_for

# Per-account accent colors for cross-account paths (assigned in first-seen order).
ACCOUNT_COLORS = ["#0972d3", "#d45b07", "#037f0c", "#9469d6", "#c33d69", "#00819c", "#8d6605", "#5f6b7a"]

PROTO_NAMES = {"-1": "All", "1": "ICMP", "6": "TCP", "17": "UDP", "58": "ICMPv6",
               "tcp": "TCP", "udp": "UDP", "icmp": "ICMP", "all": "All"}

# Path component keys rendered by dedicated formatters (or used in the header).
_HANDLED_COMPONENT_KEYS = {
    "SequenceNumber", "Component", "Vpc", "Subnet", "AttachedTo", "SourceVpc", "DestinationVpc",
    "TransitGateway", "OutboundHeader", "InboundHeader", "SecurityGroupRule", "AclRule",
    "RouteTableRoute", "TransitGatewayRouteTableRoute", "TransitGatewayPolicyTableEntry",
    "ElasticLoadBalancerListener", "FirewallStatelessRule", "FirewallStatefulRule",
    "ServiceName", "AdditionalDetails", "Explanations",
}


def _e(v: Any) -> str:
    return escape("" if v is None else str(v))


def humanize(key: str) -> str:
    words = re.sub(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", " ", key)
    fixes = {"Vpc": "VPC", "Acl": "ACL", "Arn": "ARN", "Arns": "ARNs", "Ip": "IP", "Id": "ID", "Ids": "IDs",
             "Az": "AZ", "Sg": "SG", "Sgs": "SGs", "Elb": "ELB", "Rtb": "RTB", "Cidr": "CIDR", "Cidrs": "CIDRs",
             "Vpn": "VPN", "Nat": "NAT", "Tgw": "TGW"}
    return " ".join(fixes.get(w, w) for w in words.split())


def fmt_time(v: Any) -> str:
    if isinstance(v, dt.datetime):
        return v.astimezone(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if isinstance(v, str):
        try:
            return dt.datetime.fromisoformat(v.replace("Z", "+00:00")).astimezone(
                dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except ValueError:
            return v
    return _e(v)


def proto(v: Any) -> str:
    if v is None:
        return "—"
    return PROTO_NAMES.get(str(v).lower(), str(v))


def port_range(pr: dict | None) -> str:
    if not pr:
        return "All"
    lo = pr.get("From", pr.get("FromPort"))
    hi = pr.get("To", pr.get("ToPort"))
    if lo is None and hi is None:
        return "All"
    if lo == hi or hi is None:
        return str(lo)
    if lo == 0 and hi == 65535:
        return "All (0-65535)"
    return f"{lo}-{hi}"


def port_ranges(prs: list | None) -> str:
    return ", ".join(port_range(p) for p in prs) if prs else "All"


def _is_component(v: Any) -> bool:
    return isinstance(v, dict) and bool({"Id", "Arn"} & v.keys()) and set(v.keys()) <= {"Id", "Arn", "Name"}


def acct_pill(acct: str | None, colors: dict[str, str] | None = None, label: str = "acct") -> str:
    if not acct:
        return ""
    color = (colors or {}).get(acct)
    dot = f'<span class="dot" style="background:{color}"></span>' if color else ""
    return f'<span class="acctpill" title="AWS account {_e(acct)}">{dot}{_e(label)} <code>{_e(acct)}</code></span>'


def chip(c: dict | None, size: int = 18) -> str:
    """Inline component reference: mini icon + ID (+ name), ARN on hover."""
    if not c:
        return "—"
    kind, sub = classify(c.get("Id"), c.get("Arn"))
    ident = c.get("Id") or (c.get("Arn") or "").split("/")[-1] or "?"
    name = c.get("Name")
    name_html = f' <span class="nm">{_e(name)}</span>' if name and name != ident else ""
    return (f'<span class="chip" title="{_e(c.get("Arn") or ident)}">{icon_svg(kind, None, size)}'
            f'<code>{_e(ident)}</code>{name_html}</span>')


def fmt_value(v: Any) -> str:
    """Generic formatter used for any field without a dedicated renderer."""
    if v is None or v == "" or v == []:
        return "—"
    if isinstance(v, bool):
        return "Yes" if v else "No"
    if isinstance(v, (dt.datetime, dt.date)):
        return fmt_time(v)
    if _is_component(v):
        return chip(v)
    if isinstance(v, dict):
        if set(v.keys()) <= {"From", "To"} or set(v.keys()) <= {"FromPort", "ToPort"}:
            return _e(port_range(v))
        return kv_table(v)
    if isinstance(v, list):
        if all(_is_component(x) for x in v):
            return " ".join(chip(x) for x in v)
        if all(isinstance(x, dict) and set(x.keys()) <= {"From", "To"} for x in v):
            return _e(port_ranges(v))
        if all(not isinstance(x, (dict, list)) for x in v):
            return ", ".join(f"<code>{_e(x)}</code>" for x in v)
        return "".join(f'<div class="sub">{fmt_value(x)}</div>' for x in v)
    return f"<code>{_e(v)}</code>" if isinstance(v, (int, float)) or _looks_like_id(str(v)) else _e(v)


def _looks_like_id(s: str) -> bool:
    return s.startswith("arn:") or bool(re.match(r"^[a-z]+(-[a-z]+)*-[0-9a-f]{8,}$", s)) or bool(
        re.match(r"^[\d.:/]+$", s))


def kv_table(d: dict, skip: set[str] | None = None) -> str:
    rows = []
    for k, v in d.items():
        if skip and k in skip:
            continue
        if v is None or v == [] or v == {}:
            continue
        rows.append(f"<tr><th>{_e(humanize(k))}</th><td>{fmt_value(v)}</td></tr>")
    return f'<table class="kv">{"".join(rows)}</table>' if rows else "—"


# ---------- dedicated formatters ----------

def fmt_header(h: dict | None) -> str:
    if not h:
        return "—"
    src = ", ".join(h.get("SourceAddresses") or []) or "*"
    dst = ", ".join(h.get("DestinationAddresses") or []) or "*"
    return (f'<span class="hdr"><b>{_e(proto(h.get("Protocol")))}</b> '
            f'<code>{_e(src)}</code>:<code>{_e(port_ranges(h.get("SourcePortRanges")))}</code> '
            f'<span class="arr">→</span> <code>{_e(dst)}</code>:<code>{_e(port_ranges(h.get("DestinationPortRanges")))}</code></span>')


def fmt_sg_rule(r: dict) -> str:
    peer = r.get("Cidr") or r.get("PrefixListId") or "—"
    rows = {
        "Security group": f"<code>{_e(r.get('SecurityGroupId'))}</code>",
        "Direction": _e((r.get("Direction") or "").capitalize() or "—"),
        "Protocol": _e(proto(r.get("Protocol"))),
        "Port range": _e(port_range(r.get("PortRange"))),
        ("Source" if r.get("Direction") == "ingress" else "Destination" if r.get("Direction") == "egress"
         else "Peer"): f"<code>{_e(peer)}</code>",
    }
    return _rows(rows)


def fmt_acl_rule(r: dict) -> str:
    action = (r.get("RuleAction") or "").lower()
    cls = "ok" if action == "allow" else "bad" if action == "deny" else ""
    rows = {
        "Rule number": f"<code>{_e(r.get('RuleNumber'))}</code>",
        "Direction": "Outbound (egress)" if r.get("Egress") else "Inbound (ingress)",
        "Action": f'<span class="pill {cls}">{_e(action.upper() or "—")}</span>',
        "Protocol": _e(proto(r.get("Protocol"))),
        "Port range": _e(port_range(r.get("PortRange"))),
        "CIDR": f"<code>{_e(r.get('Cidr'))}</code>",
    }
    return _rows(rows)


_ROUTE_TARGETS = ["GatewayId", "NatGatewayId", "TransitGatewayId", "VpcPeeringConnectionId", "NetworkInterfaceId",
                  "InstanceId", "EgressOnlyInternetGatewayId", "CarrierGatewayId", "LocalGatewayId", "CoreNetworkArn"]


def fmt_route(r: dict) -> str:
    target = next((r[k] for k in _ROUTE_TARGETS if r.get(k)), None)
    rows = {
        "Destination": f"<code>{_e(r.get('DestinationCidr') or r.get('DestinationPrefixListId'))}</code>",
        "Target": chip({"Id": target}) if target and not str(target).startswith("arn:")
        else chip({"Arn": target}) if target else "—",
        "Origin": _e(r.get("Origin") or "—"),
        "State": _e(r.get("State") or "—"),
    }
    extra = {k: v for k, v in r.items() if k not in {"DestinationCidr", "DestinationPrefixListId", "Origin", "State"}
             and k not in _ROUTE_TARGETS and v}
    return _rows(rows) + (kv_table(extra) if extra else "")


def fmt_tgw_route(r: dict) -> str:
    rows = {
        "Destination": f"<code>{_e(r.get('DestinationCidr') or r.get('PrefixListId'))}</code>",
        "Attachment": chip({"Id": r.get("AttachmentId")}) if r.get("AttachmentId") else "—",
        "Resource": (f"<code>{_e(r.get('ResourceId'))}</code> ({_e(r.get('ResourceType'))})"
                     if r.get("ResourceId") else "—"),
        "Route origin": _e(r.get("RouteOrigin") or "—"),
        "State": _e(r.get("State") or "—"),
    }
    return _rows(rows)


def fmt_fw_rule(r: dict) -> str:
    rows = {
        "Rule group": f"<code>{_e(r.get('RuleGroupArn'))}</code>",
        "Action": f'<span class="pill">{_e((r.get("RuleAction") or "—").upper())}</span>',
    }
    if "Priority" in r:
        rows["Priority"] = _e(r.get("Priority"))
    if "Direction" in r:
        rows["Direction"] = _e(r.get("Direction"))
    rows["Protocol"] = _e(r.get("Protocol") or ", ".join(proto(p) for p in r.get("Protocols") or []) or "All")
    rows["Sources"] = fmt_value(r.get("Sources"))
    rows["Source ports"] = _e(port_ranges(r.get("SourcePorts")))
    rows["Destinations"] = fmt_value(r.get("Destinations"))
    rows["Destination ports"] = _e(port_ranges(r.get("DestinationPorts")))
    return _rows(rows)


def _rows(rows: dict[str, str]) -> str:
    return '<table class="kv">' + "".join(f"<tr><th>{_e(k)}</th><td>{v}</td></tr>" for k, v in rows.items()) + "</table>"


def fmt_explanation(x: dict) -> str:
    code = x.get("ExplanationCode")
    desc = describe_code(code)
    head = (f'<div class="xcode"><code>{_e(code or "EXPLANATION")}</code></div>'
            + (f'<p class="xdesc">{_e(desc)}</p>' if desc else ""))
    body = kv_table(x, skip={"ExplanationCode"})
    return f'<div class="expl">{head}{body if body != "—" else ""}</div>'


# ---------- component rendering ----------

def _comp_ident(c: dict) -> str:
    return c.get("Id") or (c.get("Arn") or "").split("/")[-1] or "?"


def _section(title: str, body: str) -> str:
    return f'<div class="sec"><h5>{_e(title)}</h5>{body}</div>'


def render_component(pc: dict, direction: str, aid: str, blocked: set[str],
                     colors: dict[str, str] | None = None) -> str:
    comp = pc.get("Component") or {}
    acct = component_account(pc)
    kind, sub = classify(comp.get("Id"), comp.get("Arn"))
    ident = _comp_ident(comp)
    seq = pc.get("SequenceNumber")
    anchor = f"{aid}-{direction}-{seq}"
    flag = " blocked" if ident in blocked or comp.get("Arn") in blocked else ""

    placement = {}
    for k in ("Vpc", "Subnet", "AttachedTo", "SourceVpc", "DestinationVpc", "TransitGateway"):
        if pc.get(k):
            placement[humanize(k)] = chip(pc[k])
    if pc.get("ServiceName"):
        placement["Service name"] = f"<code>{_e(pc['ServiceName'])}</code>"
    if pc.get("ElasticLoadBalancerListener"):
        placement["ELB listener"] = chip(pc["ElasticLoadBalancerListener"])

    secs = []
    if placement:
        secs.append(_section("Placement", _rows(placement)))
    if pc.get("OutboundHeader") or pc.get("InboundHeader"):
        secs.append(_section("Packet headers", _rows({
            "Inbound header": fmt_header(pc.get("InboundHeader")),
            "Outbound header": fmt_header(pc.get("OutboundHeader")),
        })))
    if pc.get("SecurityGroupRule"):
        secs.append(_section("Security group rule", fmt_sg_rule(pc["SecurityGroupRule"])))
    if pc.get("AclRule"):
        secs.append(_section("Network ACL rule", fmt_acl_rule(pc["AclRule"])))
    if pc.get("RouteTableRoute"):
        secs.append(_section("Route table route", fmt_route(pc["RouteTableRoute"])))
    if pc.get("TransitGatewayRouteTableRoute"):
        secs.append(_section("Transit gateway route", fmt_tgw_route(pc["TransitGatewayRouteTableRoute"])))
    if pc.get("TransitGatewayPolicyTableEntry"):
        secs.append(_section("Transit gateway policy table entry", kv_table(pc["TransitGatewayPolicyTableEntry"])))
    if pc.get("FirewallStatelessRule"):
        secs.append(_section("Network Firewall stateless rule", fmt_fw_rule(pc["FirewallStatelessRule"])))
    if pc.get("FirewallStatefulRule"):
        secs.append(_section("Network Firewall stateful rule", fmt_fw_rule(pc["FirewallStatefulRule"])))
    for ad in pc.get("AdditionalDetails") or []:
        secs.append(_section(f"Additional detail: {humanize(ad.get('AdditionalDetailType') or '')}".rstrip(": "),
                             kv_table(ad, skip={"AdditionalDetailType"})))
    if pc.get("Explanations"):
        secs.append(_section("Explanations", "".join(fmt_explanation(x) for x in pc["Explanations"])))
    other = {k: v for k, v in pc.items() if k not in _HANDLED_COMPONENT_KEYS and v not in (None, [], {})}
    if other:
        secs.append(_section("Other", kv_table(other)))

    name = comp.get("Name")
    return f"""
<article class="comp{flag}" id="{_e(anchor)}">
  <header>
    <span class="seq">{_e(seq)}</span>{icon_svg(kind, sub, 40)}
    <div class="ct"><div class="ty">{_e(label_for(kind, sub))}</div>
      <div class="id"><code>{_e(ident)}</code>{f' <span class="nm">{_e(name)}</span>' if name and name != ident else ''}</div>
      {f'<div class="arn">{_e(comp.get("Arn"))}</div>' if comp.get("Arn") else ''}
    </div>
    {f'<div class="cacct">{acct_pill(acct, colors, "Account")}</div>' if acct else ''}
  </header>
  <div class="body">{''.join(secs) or '<p class="muted">No additional details.</p>'}</div>
</article>"""


def render_flow(components: list[dict], direction: str, aid: str, blocked: set[str],
                colors: dict[str, str] | None = None) -> str:
    """Icon diagram of one direction. With `colors` (multi-account paths), each node
    shows its account and account changes are drawn as labeled boundaries."""
    out: list[str] = []
    prev_acct = None
    for pc in sorted(components, key=lambda c: c.get("SequenceNumber") or 0):
        comp = pc.get("Component") or {}
        kind, sub = classify(comp.get("Id"), comp.get("Arn"))
        ident = _comp_ident(comp)
        flag = " blocked" if ident in blocked or comp.get("Arn") in blocked else ""
        hdr = pc.get("OutboundHeader") or pc.get("InboundHeader")
        hint = ""
        if pc.get("SecurityGroupRule"):
            r = pc["SecurityGroupRule"]
            hint = f"{proto(r.get('Protocol'))} {port_range(r.get('PortRange'))} {r.get('Cidr') or r.get('PrefixListId') or ''}"
        elif pc.get("AclRule"):
            r = pc["AclRule"]
            hint = f"#{r.get('RuleNumber')} {(r.get('RuleAction') or '').upper()} {'out' if r.get('Egress') else 'in'}"
        elif pc.get("RouteTableRoute"):
            r = pc["RouteTableRoute"]
            hint = f"→ {r.get('DestinationCidr') or r.get('DestinationPrefixListId') or ''}"
        elif hdr:
            hint = f"{proto(hdr.get('Protocol'))} → {', '.join(hdr.get('DestinationAddresses') or [])}"
        acct = component_account(pc)
        if out:
            if colors and acct and prev_acct and acct != prev_acct:
                out.append(f'<span class="link xacct" title="Account boundary: {_e(prev_acct)} → {_e(acct)}">'
                           f'<span class="xlbl">account<br>boundary</span></span>')
            else:
                out.append('<span class="link" aria-hidden="true"></span>')
        prev_acct = acct or prev_acct
        style = f' style="border-top:4px solid {colors[acct]}"' if colors and acct in colors else ""
        acct_html = f'<span class="nacct">{_e(acct)}</span>' if colors and acct else ""
        out.append(
            f'<a class="node{flag}"{style} href="#{_e(aid)}-{direction}-{_e(pc.get("SequenceNumber"))}" '
            f'title="{_e(comp.get("Arn") or ident)}">'
            f'<span class="nseq">{_e(pc.get("SequenceNumber"))}</span>{icon_svg(kind, sub, 44)}'
            f'<span class="nty">{_e(label_for(kind, sub))}</span><code class="nid">{_e(ident)}</code>'
            + (f'<span class="nnm">{_e(comp.get("Name"))}</span>' if comp.get("Name") and comp.get("Name") != ident else "")
            + (f'<span class="nhint">{_e(hint.strip())}</span>' if hint.strip() else "")
            + acct_html + "</a>")
    return '<div class="flow">' + "".join(out) + "</div>"


def _endpoint_cell(ref: str | None, ip: str | None, acct: str | None = None,
                   colors: dict[str, str] | None = None) -> str:
    parts = []
    if ref:
        if ref.startswith("arn:"):
            parts.append(chip({"Arn": ref, "Id": ref.split("/")[-1]}, 22))
        else:
            parts.append(chip({"Id": ref}, 22))
    if ip:
        parts.append(f'<span class="chip">{icon_svg("ip-address", None, 22)}<code>{_e(ip)}</code></span>')
    if acct:
        parts.append(acct_pill(acct, colors))
    return " ".join(parts) or "—"


def _filter_cell(f: dict | None) -> str:
    if not f:
        return "—"
    return _rows({
        "Source address": f"<code>{_e(f.get('SourceAddress') or 'Any')}</code>",
        "Source port range": _e(port_range(f.get("SourcePortRange"))),
        "Destination address": f"<code>{_e(f.get('DestinationAddress') or 'Any')}</code>",
        "Destination port range": _e(port_range(f.get("DestinationPortRange"))),
    })


def _tags(tags: list | None) -> str:
    if not tags:
        return "—"
    return " ".join(f'<span class="tag"><b>{_e(t.get("Key"))}</b>={_e(t.get("Value"))}</span>' for t in tags)


def _tag(tags: list | None, key: str) -> str | None:
    return next((t.get("Value") for t in tags or [] if t.get("Key") == key), None)


def _status_badge(a: dict) -> str:
    st = a.get("Status")
    if st == "succeeded":
        if a.get("NetworkPathFound"):
            return '<span class="badge ok">● Reachable</span>'
        return '<span class="badge bad">● Not reachable</span>'
    if st == "failed":
        return '<span class="badge warn">● Analysis failed</span>'
    return f'<span class="badge">● {_e((st or "unknown").capitalize())}</span>'


def _blocked_ids(a: dict) -> set[str]:
    ids: set[str] = set()
    for x in a.get("Explanations") or []:
        for k in ("Component", "Acl", "SecurityGroup", "RouteTable", "Subnet", "NetworkInterface",
                  "InternetGateway", "NatGateway", "TransitGateway", "TransitGatewayAttachment",
                  "TransitGatewayRouteTable", "VpcEndpoint", "VpcPeeringConnection", "VpnGateway",
                  "VpnConnection", "LoadBalancerTargetGroup", "ElasticLoadBalancerListener"):
            c = x.get(k)
            if isinstance(c, dict):
                ids.update(v for v in (c.get("Id"), c.get("Arn")) if v)
    return ids


def _legend(colors: dict[str, str] | None) -> str:
    if not colors:
        return ""
    return ('<div class="legend">' + "".join(
        f'<span><span class="dot" style="background:{c}"></span><code>{_e(a)}</code></span>' for a, c in colors.items())
        + '<span class="muted">Node top border = owning account</span></div>')


def render_accounts(accts: dict, colors: dict[str, str] | None) -> str:
    """Accounts card: every account involved, its roles, and hops it owns per direction."""
    if not accts["accounts"]:
        return ""
    rows = []
    for acct, info in accts["accounts"].items():
        dot = f'<span class="dot" style="background:{colors[acct]}"></span>' if colors and acct in colors else ""
        roles = " ".join(f'<span class="tag">{_e(r)}</span>' for r in info["roles"]) or '<span class="muted">Transit</span>'
        rows.append(f'<tr><td>{dot}<code>{_e(acct)}</code></td><td>{roles}</td>'
                    f'<td class="num">{info["forward"] or "—"}</td><td class="num">{info["return"] or "—"}</td></tr>')
    note = ""
    suggested = [a for a, i in accts["accounts"].items() if ROLE_SUGGESTED in i["roles"]]
    if suggested:
        note = ('<p class="warnmsg">AWS suggests including these accounts. Re-run the analysis with '
                + " ".join(f"<code>--additional-account {_e(a)}</code>" for a in suggested)
                + " for a complete result.</p>")
    title = "Accounts" + (' <span class="muted">(cross-account path)</span>' if accts["cross_account"] else "")
    return (f'<div class="card"><h3>{title}</h3><table class="grid"><thead><tr><th>Account</th><th>Roles</th>'
            f'<th class="num">Forward hops</th><th class="num">Return hops</th></tr></thead><tbody>'
            + "".join(rows) + f"</tbody></table>{note}</div>")


def render_analysis(bundle: dict, idx: int) -> str:
    p = bundle.get("path") or {}
    a = bundle.get("analysis") or {}
    aid = a.get("NetworkInsightsAnalysisId") or f"analysis{idx}"
    blocked = _blocked_ids(a)
    path_name = _tag(p.get("Tags"), "Name")
    analysis_name = _tag(a.get("Tags"), "Name")

    fwd = a.get("ForwardPathComponents") or []
    ret = a.get("ReturnPathComponents") or []
    accts = account_summary(p, a)
    colors = ({acct: ACCOUNT_COLORS[i % len(ACCOUNT_COLORS)] for i, acct in enumerate(accts["accounts"])}
              if accts["cross_account"] else None)

    path_rows = {
        "Path ID": f"<code>{_e(p.get('NetworkInsightsPathId'))}</code>",
        "Path ARN": f"<code>{_e(p.get('NetworkInsightsPathArn'))}</code>",
        "Source": _endpoint_cell(p.get("SourceArn") or p.get("Source"), p.get("SourceIp"), accts["source"], colors),
        "Destination": _endpoint_cell(p.get("DestinationArn") or p.get("Destination"), p.get("DestinationIp"),
                                      accts["destination"], colors),
        "Path owner account": acct_pill(arn_account(p.get("NetworkInsightsPathArn")), colors, "") or "—",
        "Protocol": _e(proto(p.get("Protocol"))),
    }
    if p.get("DestinationPort") is not None:
        path_rows["Destination port"] = f"<code>{_e(p.get('DestinationPort'))}</code>"
    path_rows["Filter at source"] = _filter_cell(p.get("FilterAtSource"))
    if p.get("FilterAtDestination"):
        path_rows["Filter at destination"] = _filter_cell(p.get("FilterAtDestination"))
    path_rows["Created"] = _e(fmt_time(p.get("CreatedDate")))
    path_rows["Tags"] = _tags(p.get("Tags"))
    known_path = {"NetworkInsightsPathId", "NetworkInsightsPathArn", "Source", "SourceArn", "SourceIp",
                  "Destination", "DestinationArn", "DestinationIp", "Protocol", "DestinationPort",
                  "FilterAtSource", "FilterAtDestination", "CreatedDate", "Tags"}
    for k, v in p.items():
        if k not in known_path and v not in (None, [], {}):
            path_rows[humanize(k)] = fmt_value(v)

    an_rows = {
        "Analysis ID": f"<code>{_e(a.get('NetworkInsightsAnalysisId'))}</code>",
        "Analysis ARN": f"<code>{_e(a.get('NetworkInsightsAnalysisArn'))}</code>",
        "Status": _e(a.get("Status")),
        "Reachability": _status_badge(a),
        "Started": _e(fmt_time(a.get("StartDate"))),
    }
    if a.get("StatusMessage"):
        an_rows["Status message"] = _e(a["StatusMessage"])
    if a.get("WarningMessage"):
        an_rows["Warning"] = f'<span class="warnmsg">{_e(a["WarningMessage"])}</span>'
    an_rows["Include intermediate (filter-in)"] = fmt_value(a.get("FilterInArns"))
    an_rows["Exclude intermediate (filter-out)"] = fmt_value(a.get("FilterOutArns"))
    an_rows["Additional accounts"] = fmt_value(a.get("AdditionalAccounts"))
    if a.get("SuggestedAccounts"):
        an_rows["Suggested accounts"] = fmt_value(a["SuggestedAccounts"])
    an_rows["Tags"] = _tags(a.get("Tags"))
    known_an = {"NetworkInsightsAnalysisId", "NetworkInsightsAnalysisArn", "NetworkInsightsPathId", "Status",
                "StatusMessage", "WarningMessage", "StartDate", "NetworkPathFound", "FilterInArns", "FilterOutArns",
                "AdditionalAccounts", "SuggestedAccounts", "Tags", "ForwardPathComponents", "ReturnPathComponents",
                "Explanations", "AlternatePathHints"}
    for k, v in a.items():
        if k not in known_an and v not in (None, [], {}):
            an_rows[humanize(k)] = fmt_value(v)

    parts = [f"""
<section class="analysis" id="{_e(aid)}">
  <div class="ahead">
    <div><h2>{_e(analysis_name or path_name or aid)}</h2>
      <div class="muted"><code>{_e(aid)}</code> · path <code>{_e(p.get('NetworkInsightsPathId'))}</code></div></div>
    <div class="badges">{'<span class="badge xa">⇄ Cross-account</span>' if accts["cross_account"] else ''}{_status_badge(a)}</div>
  </div>
  <div class="grid2">
    <div class="card"><h3>Path</h3>{_rows(path_rows)}</div>
    <div class="card"><h3>Analysis</h3>{_rows(an_rows)}</div>
  </div>
  {render_accounts(accts, colors)}"""]

    if a.get("Explanations"):
        parts.append('<div class="card xcard"><h3>Explanations</h3>'
                     + "".join(fmt_explanation(x) for x in a["Explanations"]) + "</div>")

    if not fwd and a.get("Status") == "succeeded" and not a.get("NetworkPathFound"):
        # Show the intended endpoints with a break so the failure reads visually.
        src = p.get("SourceArn") or p.get("Source")
        dst = p.get("DestinationArn") or p.get("Destination")
        sk, ss = classify(p.get("Source"), p.get("SourceArn"))
        dk, ds = classify(p.get("Destination"), p.get("DestinationArn")) if dst else ("ip-address", None)
        dest_tail = (f'<span class="node"><span class="nseq">S</span>{icon_svg(sk, ss, 44)}<span class="nty">'
                     f'{_e(label_for(sk, ss))}</span><code class="nid">{_e((src or "").split("/")[-1])}</code></span>'
                     f'<span class="link broken" aria-hidden="true"></span>'
                     f'<span class="node blocked"><span class="nseq">D</span>{icon_svg(dk, ds, 44)}<span class="nty">'
                     f'{_e(label_for(dk, ds))}</span><code class="nid">'
                     f'{_e((dst or p.get("DestinationIp") or "").split("/")[-1])}</code></span>')
        parts.append(f'<div class="card"><h3>Intended path</h3><div class="flow">{dest_tail}</div></div>')

    for title, comps, direction in (("Forward path", fwd, "fwd"), ("Return path", ret, "ret")):
        if not comps:
            continue
        parts.append(f'<div class="card"><h3>{title} <span class="muted">({len(comps)} components)</span></h3>'
                     + render_flow(comps, direction, aid, blocked, colors)
                     + _legend(colors)
                     + '<details class="comps" open><summary>Component details</summary>'
                     + "".join(render_component(pc, direction, aid, blocked, colors)
                               for pc in sorted(comps, key=lambda c: c.get("SequenceNumber") or 0))
                     + "</details></div>")

    if a.get("AlternatePathHints"):
        parts.append('<div class="card"><h3>Alternate path hints</h3>'
                     + "".join(f'<div class="sub">{chip({"Id": h.get("ComponentId"), "Arn": h.get("ComponentArn")})}'
                               f'</div>' for h in a["AlternatePathHints"]) + "</div>")

    raw = json.dumps(bundle, indent=2, default=str, sort_keys=False)
    parts.append(f'<details class="card raw"><summary>Raw API data (JSON)</summary><pre>{_e(raw)}</pre></details>')
    parts.append("</section>")
    return "".join(parts)


CSS = """
/* Dark is the default; data-theme="light" or "auto" (follow the OS) override it. */
:root{--bg:#0f1419;--card:#192029;--fg:#e6e9ee;--muted:#9aa5b1;--line:#2e3a47;--code:#232d38;--ok:#5fd16a;--okbg:#14301a;--bad:#ff7b6b;--badbg:#3a1714;--warn:#f2c94c;--warnbg:#3a2f0c;--accent:#58a6ff;color-scheme:dark}
:root[data-theme="light"]{--bg:#f4f5f7;--card:#fff;--fg:#16191f;--muted:#5f6b7a;--line:#d5dbdb;--code:#eef1f4;--ok:#037f0c;--okbg:#e9f7ea;--bad:#d1321e;--badbg:#fdecea;--warn:#8d6605;--warnbg:#fff6dd;--accent:#0972d3;color-scheme:light}
@media (prefers-color-scheme:light){:root[data-theme="auto"]{--bg:#f4f5f7;--card:#fff;--fg:#16191f;--muted:#5f6b7a;--line:#d5dbdb;--code:#eef1f4;--ok:#037f0c;--okbg:#e9f7ea;--bad:#d1321e;--badbg:#fdecea;--warn:#8d6605;--warnbg:#fff6dd;--accent:#0972d3;color-scheme:light}}
@media print{:root,:root[data-theme]{--bg:#f4f5f7;--card:#fff;--fg:#16191f;--muted:#5f6b7a;--line:#d5dbdb;--code:#eef1f4;--ok:#037f0c;--okbg:#e9f7ea;--bad:#d1321e;--badbg:#fdecea;--warn:#8d6605;--warnbg:#fff6dd;--accent:#0972d3;color-scheme:light}.themebtn{display:none}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:1280px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:19px;margin:0}h3{font-size:15px;margin:0 0 12px}
h5{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:0 0 6px}
code{font:12.5px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--code);padding:1px 5px;border-radius:4px;word-break:break-all}
a{color:var(--accent)}
.muted{color:var(--muted);font-weight:400}
.top{display:flex;justify-content:space-between;align-items:flex-end;gap:12px;flex-wrap:wrap;margin-bottom:16px}
nav.toc{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 20px}
nav.toc a{background:var(--card);border:1px solid var(--line);border-radius:999px;padding:4px 12px;text-decoration:none;color:var(--fg)}
.analysis{margin-bottom:40px}
.ahead{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:16px;min-width:0}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,460px),1fr));gap:16px}
.grid2 .card{margin-bottom:0}.grid2{margin-bottom:16px}
table.kv{border-collapse:collapse;width:100%}
table.kv th{text-align:left;vertical-align:top;color:var(--muted);font-weight:500;padding:4px 12px 4px 0;width:34%;white-space:nowrap}
table.kv td{padding:4px 0;vertical-align:top;word-break:break-word}
table.kv table.kv th{width:auto}
.badge{display:inline-block;padding:6px 14px;border-radius:999px;font-weight:600;background:var(--code)}
.badge.ok{color:var(--ok);background:var(--okbg)}.badge.bad{color:var(--bad);background:var(--badbg)}
.badge.warn{color:var(--warn);background:var(--warnbg)}
.pill{display:inline-block;padding:0 8px;border-radius:4px;font-weight:600;font-size:12px;background:var(--code)}
.pill.ok{color:var(--ok);background:var(--okbg)}.pill.bad{color:var(--bad);background:var(--badbg)}
.chip{display:inline-flex;align-items:center;gap:6px;margin:1px 6px 1px 0;vertical-align:middle}
.chip .ico{flex:none}
.nm{color:var(--muted)}
.tag{display:inline-block;background:var(--code);border-radius:4px;padding:0 6px;margin:1px 4px 1px 0;font-size:12px}
.warnmsg{color:var(--warn)}
.flow{display:flex;flex-wrap:wrap;align-items:stretch;gap:0;row-gap:16px;padding:4px 0 8px}
.node{position:relative;display:flex;flex-direction:column;align-items:center;text-align:center;gap:3px;width:136px;
padding:12px 8px 10px;border:1px solid var(--line);border-radius:10px;background:var(--bg);text-decoration:none;color:var(--fg)}
.node:hover{border-color:var(--accent)}
.node.blocked{border-color:var(--bad);box-shadow:0 0 0 2px var(--badbg)}
.nseq{position:absolute;top:4px;left:6px;font-size:11px;color:var(--muted)}
.nty{font-size:11.5px;font-weight:600;line-height:1.2}
.nid{font-size:10.5px;padding:0 3px}
.nnm{font-size:11px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:100%}
.nhint{font-size:10.5px;color:var(--muted);font-family:ui-monospace,Menlo,monospace;word-break:break-all}
.link{align-self:center;width:24px;height:2px;background:var(--muted);position:relative;flex:none}
.link::after{content:"";position:absolute;right:-1px;top:-4px;border:5px solid transparent;border-left:7px solid var(--muted);border-right:0}
.link.broken{width:48px;background:repeating-linear-gradient(90deg,var(--bad) 0 6px,transparent 6px 10px)}
.link.broken::after{border-left-color:var(--bad)}
details.comps>summary,details.raw>summary{cursor:pointer;font-weight:600;margin:12px 0 4px}
.comp{border:1px solid var(--line);border-radius:10px;margin:12px 0;overflow:hidden;scroll-margin-top:12px}
.comp.blocked{border-color:var(--bad)}
.comp:target{box-shadow:0 0 0 3px var(--accent)}
.comp>header{display:flex;align-items:center;gap:12px;padding:10px 12px;background:var(--bg);border-bottom:1px solid var(--line)}
.comp .seq{font-weight:700;color:var(--muted);min-width:20px;text-align:right}
.comp .ty{font-weight:600}.comp .arn{font:11px ui-monospace,Menlo,monospace;color:var(--muted);word-break:break-all}
.comp .body{padding:12px;display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,340px),1fr));gap:12px 24px}
.sub{margin:2px 0}
.expl{border-left:3px solid var(--bad);background:var(--badbg);border-radius:0 8px 8px 0;padding:10px 12px;margin:8px 0}
.comp .expl{border-left-color:var(--warn);background:var(--warnbg)}
.xcode code{font-weight:700;background:transparent;padding:0}
.xdesc{margin:4px 0 8px}
.hdr .arr{color:var(--muted)}
pre{overflow:auto;max-height:520px;background:var(--code);padding:12px;border-radius:8px;font-size:12px}
.themebtn{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:999px;padding:4px 12px;font:inherit;font-size:12px;cursor:pointer}
.badges{display:flex;gap:8px;flex-wrap:wrap}
.badge.xa{color:var(--accent);background:var(--code)}
.acctpill{display:inline-flex;align-items:center;gap:4px;font-size:12px;color:var(--muted);white-space:nowrap}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:4px;vertical-align:middle}
.nacct{font:10px ui-monospace,Menlo,monospace;color:var(--muted);margin-top:2px}
.cacct{margin-left:auto}
.link.xacct{width:56px;height:0;background:none;border-top:2px dashed var(--accent);display:flex;justify-content:center}
.link.xacct::after{border-left-color:var(--accent);top:-6px}
.xlbl{position:relative;top:4px;font-size:9.5px;line-height:1.1;color:var(--accent);text-align:center;font-weight:600}
.legend{display:flex;flex-wrap:wrap;gap:6px 16px;align-items:center;font-size:12px;margin:2px 0 4px}
table.grid{border-collapse:collapse;width:100%}
table.grid th,table.grid td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:middle}
table.grid th{color:var(--muted);font-weight:500;font-size:12px}
table.grid .num{text-align:right;width:110px}
footer{color:var(--muted);font-size:12px;margin-top:32px}
@media print{details{display:block}details>summary{display:none}.node{break-inside:avoid}.comp{break-inside:avoid}
body{background:#fff}.card{border-color:#ccc}}
@media (max-width:520px){.node{width:118px}table.kv th{white-space:normal;width:40%}}
"""


THEMES = ("dark", "light", "auto")

# Inline toggle: flips between dark and light without leaving the page (no storage, no network).
_THEME_JS = (
    "document.querySelector('.themebtn').addEventListener('click',function(){"
    "var r=document.documentElement,c=r.getAttribute('data-theme');"
    "if(c==='auto')c=matchMedia('(prefers-color-scheme: light)').matches?'light':'dark';"
    "r.setAttribute('data-theme',c==='light'?'dark':'light');});"
)


def render_html(bundles: list[dict], title: str | None = None, theme: str = "dark") -> str:
    if theme not in THEMES:
        raise ValueError(f"theme must be one of {THEMES}")
    generated = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    page_title = title or "Reachability Trace"
    toc = ""
    if len(bundles) > 1:
        toc = '<nav class="toc">' + "".join(
            f'<a href="#{_e((b.get("analysis") or {}).get("NetworkInsightsAnalysisId") or f"analysis{i}")}">'
            f'{_e((b.get("analysis") or {}).get("NetworkInsightsAnalysisId") or f"Analysis {i + 1}")}</a>'
            for i, b in enumerate(bundles)) + "</nav>"
    body = "".join(render_analysis(b, i) for i, b in enumerate(bundles))
    return f"""<!doctype html>
<html lang="en" data-theme="{theme}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(page_title)}</title><style>{CSS}</style></head>
<body><main>
<div class="top"><div><h1>{_e(page_title)}</h1>
<div class="muted">AWS VPC Reachability Analyzer · exported {generated}</div></div>
<button class="themebtn" type="button" title="Toggle light/dark">◐ Theme</button></div>
{toc}{body}
<footer>Generated from the EC2 Network Insights API. Analyses are retained by AWS for 120 days.</footer>
</main><script>{_THEME_JS}</script></body></html>
"""
