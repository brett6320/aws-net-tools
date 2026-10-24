"""Inline SVG icons for path components, plus component type classification.

Icons are drawn here (not downloaded) so exported HTML is fully self-contained.
Colors follow the AWS architecture icon category palette: compute orange,
networking purple, security red.
"""
from __future__ import annotations

COMPUTE = "#ED7100"
NETWORK = "#8C4FFF"
SECURITY = "#DD344C"
GENERIC = "#7D8998"

# kind: (display label, category color, glyph SVG body drawn in a 48x48 box)
_S = 'fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"'

ICONS: dict[str, tuple[str, str, str]] = {
    "instance": ("EC2 instance", COMPUTE,
        f'<g {_S}><rect x="15" y="15" width="18" height="18" rx="1"/><rect x="20" y="20" width="8" height="8"/>'
        '<path d="M19 15v-4M24 15v-4M29 15v-4M19 33v4M24 33v4M29 33v4M15 19h-4M15 24h-4M15 29h-4M33 19h4M33 24h4M33 29h4"/></g>'),
    "network-interface": ("Network interface", NETWORK,
        f'<g {_S}><rect x="10" y="16" width="28" height="16" rx="2"/><path d="M15 32v4M21 32v4M27 32v4M33 32v4"/>'
        '<rect x="14" y="20" width="6" height="6"/><rect x="22" y="20" width="6" height="6"/><circle cx="33" cy="23" r="1.5"/></g>'),
    "internet-gateway": ("Internet gateway", NETWORK,
        f'<g {_S}><circle cx="24" cy="24" r="12"/><ellipse cx="24" cy="24" rx="5" ry="12"/><path d="M12 24h24M14 18h20M14 30h20"/></g>'),
    "egress-only-internet-gateway": ("Egress-only internet gateway", NETWORK,
        f'<g {_S}><circle cx="21" cy="24" r="10"/><ellipse cx="21" cy="24" rx="4" ry="10"/><path d="M11 24h20"/><path d="M31 15l7-7M33 8h5v5"/></g>'),
    "nat-gateway": ("NAT gateway", NETWORK,
        f'<g {_S}><path d="M10 18h22l-5-5M38 30H16l5 5"/><circle cx="24" cy="24" r="14" stroke-dasharray="3 3"/></g>'),
    "network-acl": ("Network ACL", SECURITY,
        f'<g {_S}><rect x="11" y="10" width="26" height="28" rx="2"/><path d="M11 17h26M11 24h26M11 31h26M18 10v28"/>'
        '<path d="M28 13.5l2 2 3-3"/><path d="M27 27l5 5M32 27l-5 5"/></g>'),
    "security-group": ("Security group", SECURITY,
        f'<g {_S}><path d="M24 9l12 5v9c0 8-5 13-12 16-7-3-12-8-12-16v-9z"/><path d="M19 24l4 4 7-8"/></g>'),
    "route-table": ("Route table", NETWORK,
        f'<g {_S}><circle cx="24" cy="24" r="6"/><path d="M24 18V9M21 12l3-3 3 3M24 30v9M21 36l3 3 3-3M18 24H9M12 21l-3 3 3 3M30 24h9M36 21l3 3-3 3"/></g>'),
    "subnet": ("Subnet", NETWORK,
        f'<g {_S}><rect x="10" y="10" width="28" height="28" rx="2" stroke-dasharray="4 3"/><rect x="17" y="17" width="14" height="14" rx="1"/></g>'),
    "vpc": ("VPC", NETWORK,
        f'<g {_S}><path d="M15 33h19a6 6 0 0 0 0-12 9 9 0 0 0-17-2 7 7 0 0 0-2 14z"/><rect x="20" y="24" width="8" height="6" rx="1"/><path d="M22 24v-2a2 2 0 0 1 4 0v2"/></g>'),
    "transit-gateway": ("Transit gateway", NETWORK,
        f'<g {_S}><circle cx="24" cy="24" r="5"/><circle cx="11" cy="11" r="3"/><circle cx="37" cy="11" r="3"/><circle cx="11" cy="37" r="3"/><circle cx="37" cy="37" r="3"/>'
        '<path d="M13 13l7.5 7.5M35 13l-7.5 7.5M13 35l7.5-7.5M35 35l-7.5-7.5"/></g>'),
    "transit-gateway-attachment": ("Transit gateway attachment", NETWORK,
        f'<g {_S}><rect x="8" y="19" width="16" height="10" rx="5"/><rect x="24" y="19" width="16" height="10" rx="5"/><path d="M19 24h10"/></g>'),
    "transit-gateway-route-table": ("Transit gateway route table", NETWORK,
        f'<g {_S}><rect x="10" y="10" width="28" height="28" rx="2"/><path d="M10 18h28M10 26h28M19 18v20"/><circle cx="14.5" cy="14" r="1.5"/></g>'),
    "transit-gateway-policy-table": ("Transit gateway policy table", NETWORK,
        f'<g {_S}><rect x="10" y="10" width="28" height="28" rx="2"/><path d="M10 18h28M15 24h18M15 30h12"/></g>'),
    "vpn-gateway": ("Virtual private gateway", NETWORK,
        f'<g {_S}><rect x="14" y="22" width="20" height="15" rx="2"/><path d="M18 22v-5a6 6 0 0 1 12 0v5"/><circle cx="24" cy="29" r="2"/><path d="M24 31v3"/></g>'),
    "customer-gateway": ("Customer gateway", NETWORK,
        f'<g {_S}><path d="M12 38V16l12-6 12 6v22z"/><path d="M18 22h4M26 22h4M18 28h4M26 28h4M21 38v-5h6v5"/></g>'),
    "vpn-connection": ("VPN connection", NETWORK,
        f'<g {_S}><path d="M8 20h32M8 28h32" stroke-dasharray="3 3"/><rect x="18" y="16" width="12" height="16" rx="2"/><circle cx="24" cy="23" r="2"/><path d="M24 25v3"/></g>'),
    "vpc-endpoint": ("VPC endpoint", NETWORK,
        f'<g {_S}><path d="M18 14v6M30 14v6M14 20h20v5a10 10 0 0 1-20 0z"/><path d="M24 35v5"/></g>'),
    "vpc-endpoint-service": ("VPC endpoint service", NETWORK,
        f'<g {_S}><rect x="9" y="9" width="30" height="30" rx="3"/><path d="M20 15v4M28 15v4M16 19h16v4a8 8 0 0 1-16 0z"/><path d="M24 31v4"/></g>'),
    "vpc-peering-connection": ("VPC peering connection", NETWORK,
        f'<g {_S}><circle cx="14" cy="24" r="6"/><circle cx="34" cy="24" r="6"/><path d="M20 24h8"/></g>'),
    "prefix-list": ("Prefix list", NETWORK,
        f'<g {_S}><path d="M18 14h20M18 24h20M18 34h20"/><circle cx="12" cy="14" r="1.5"/><circle cx="12" cy="24" r="1.5"/><circle cx="12" cy="34" r="1.5"/></g>'),
    "load-balancer": ("Load balancer", NETWORK,
        f'<g {_S}><circle cx="24" cy="24" r="14"/><circle cx="17" cy="24" r="3"/><path d="M20 24h11M20 22l9-6M20 26l9 6M29 14l3 2-2 3M29 34l3-2-2-3M31 22l2 2-2 2"/></g>'),
    "target-group": ("Target group", COMPUTE,
        f'<g {_S}><rect x="9" y="9" width="30" height="30" rx="2" stroke-dasharray="4 3"/><rect x="14" y="14" width="8" height="8"/><rect x="26" y="14" width="8" height="8"/><rect x="14" y="26" width="8" height="8"/><rect x="26" y="26" width="8" height="8"/></g>'),
    "listener": ("Load balancer listener", NETWORK,
        f'<g {_S}><circle cx="24" cy="24" r="13"/><path d="M8 24h12M16 20l4 4-4 4"/><circle cx="26" cy="24" r="4"/></g>'),
    "network-firewall": ("Network Firewall", SECURITY,
        f'<g {_S}><rect x="9" y="12" width="30" height="24" rx="1"/><path d="M9 20h30M9 28h30M19 12v8M29 12v8M14 20v8M24 20v8M34 20v8M19 28v8M29 28v8"/></g>'),
    "firewall-rule-group": ("Firewall rule group", SECURITY,
        f'<g {_S}><rect x="11" y="10" width="26" height="28" rx="2"/><path d="M16 17h16M16 24h16M16 31h10"/></g>'),
    "local-gateway": ("Local gateway", NETWORK,
        f'<g {_S}><rect x="10" y="14" width="28" height="20" rx="2"/><path d="M16 24h16M28 20l4 4-4 4"/></g>'),
    "carrier-gateway": ("Carrier gateway", NETWORK,
        f'<g {_S}><path d="M24 22v16M17 38h14"/><path d="M18 16a8 8 0 0 1 12 0M14 12a14 14 0 0 1 20 0"/><circle cx="24" cy="20" r="2"/></g>'),
    "core-network": ("Cloud WAN core network", NETWORK,
        f'<g {_S}><circle cx="24" cy="24" r="13"/><path d="M24 11v26M11 24h26M15 15l18 18M33 15L15 33"/></g>'),
    "ip-address": ("IP address", GENERIC, ""),  # glyph is text, see icon_svg
    "unknown": ("Component", GENERIC,
        f'<g {_S}><path d="M24 9l13 7v16l-13 7-13-7V16z"/><path d="M11 16l13 7 13-7M24 23v16"/></g>'),
}

# Ordered: longer prefixes first.
_ID_PREFIXES: list[tuple[str, str]] = [
    ("tgw-attach-", "transit-gateway-attachment"),
    ("tgw-rtb-", "transit-gateway-route-table"),
    ("tgw-ptb-", "transit-gateway-policy-table"),
    ("tgw-", "transit-gateway"),
    ("vpce-svc-", "vpc-endpoint-service"),
    ("vpce-", "vpc-endpoint"),
    ("eigw-", "egress-only-internet-gateway"),
    ("igw-", "internet-gateway"),
    ("eni-", "network-interface"),
    ("nat-", "nat-gateway"),
    ("acl-", "network-acl"),
    ("sg-", "security-group"),
    ("rtb-", "route-table"),
    ("subnet-", "subnet"),
    ("vpc-", "vpc"),
    ("vgw-", "vpn-gateway"),
    ("cgw-", "customer-gateway"),
    ("vpn-", "vpn-connection"),
    ("pcx-", "vpc-peering-connection"),
    ("pl-", "prefix-list"),
    ("lgw-", "local-gateway"),
    ("cagw-", "carrier-gateway"),
    ("i-", "instance"),
]


def classify(component_id: str | None = None, arn: str | None = None) -> tuple[str, str | None]:
    """Return (icon kind, optional sub-label) for a component ID/ARN.

    Non-EC2 resources (load balancers, target groups, listeners, Network Firewall,
    Cloud WAN) are recognized from the ARN's service and resource path; the sub-label
    distinguishes ALB/NLB/GWLB/CLB. Everything else is matched on its ID prefix
    (sg-, rtb-, tgw-attach-, ...). Unknown components get a generic icon."""
    if arn and arn.startswith("arn:"):
        parts = arn.split(":", 5)
        service = parts[2] if len(parts) > 2 else ""
        resource = parts[5] if len(parts) == 6 else ""
        if service == "elasticloadbalancing":
            if resource.startswith("targetgroup/"):
                return "target-group", None
            if resource.startswith("listener/"):
                return "listener", None
            if resource.startswith("loadbalancer/app/"):
                return "load-balancer", "ALB"
            if resource.startswith("loadbalancer/net/"):
                return "load-balancer", "NLB"
            if resource.startswith("loadbalancer/gwy/"):
                return "load-balancer", "GWLB"
            if resource.startswith("loadbalancer/"):
                return "load-balancer", "CLB"
        if service == "network-firewall":
            if resource.startswith("firewall/"):
                return "network-firewall", None
            if "rulegroup" in resource:
                return "firewall-rule-group", None
        if service == "networkmanager" and resource.startswith("core-network/"):
            return "core-network", None
        if not component_id:
            component_id = resource.split("/")[-1]
    for prefix, kind in _ID_PREFIXES:
        if component_id and component_id.startswith(prefix):
            return kind, None
    return "unknown", None


def label_for(kind: str, sub: str | None = None) -> str:
    """Display name for an icon kind ("Network ACL", "Network Load Balancer", ...)."""
    base = ICONS.get(kind, ICONS["unknown"])[0]
    if kind == "load-balancer" and sub:
        return {"ALB": "Application Load Balancer", "NLB": "Network Load Balancer",
                "GWLB": "Gateway Load Balancer", "CLB": "Classic Load Balancer"}.get(sub, base)
    return base


def icon_svg(kind: str, sub: str | None = None, size: int = 40) -> str:
    """Inline <svg>: category-colored rounded square, white glyph, and an optional
    badge (e.g. "NLB") along the bottom edge."""
    _, color, glyph = ICONS.get(kind, ICONS["unknown"])
    if kind == "ip-address":
        glyph = ('<text x="24" y="29" text-anchor="middle" font-family="Helvetica,Arial,sans-serif" '
                 'font-size="14" font-weight="700" fill="#fff">IP</text>')
    badge = ""
    if sub:
        badge = (f'<rect x="2" y="36" width="44" height="10" rx="2" fill="#000" fill-opacity=".35"/>'
                 f'<text x="24" y="44" text-anchor="middle" font-family="Helvetica,Arial,sans-serif" '
                 f'font-size="8" font-weight="700" fill="#fff">{sub}</text>')
    return (f'<svg class="ico" width="{size}" height="{size}" viewBox="0 0 48 48" role="img" '
            f'aria-label="{label_for(kind, sub)}"><rect width="48" height="48" rx="6" fill="{color}"/>'
            f'{glyph}{badge}</svg>')
