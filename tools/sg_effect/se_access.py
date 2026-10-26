"""Security group rule algebra for sg_effect.

A rule allows a block of traffic: a protocol, a port range (ICMP type range for ICMP)
and a set of peers. Security groups only allow, so a resource's access in one
direction is the union of every rule in every group on it.

To answer "what would be lost", rules are turned into rectangles and subtracted:

    key    one of tcp, udp, icmp, icmpv6, ip (other protocols, by number)
    lo-hi  ports for tcp/udp, ICMP types for icmp/icmpv6, protocol numbers for ip
    peers  CIDR networks (prefix lists are expanded to their entries) plus atoms for
           what can't be expanded: referenced security groups ("sg:<id>") and prefix
           lists whose entries couldn't be read ("pl:<id>")

A rule's residual after subtracting every other rule is exactly the traffic only it
allows. An empty residual means the rule is redundant on that resource.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Iterable

Network = ipaddress.IPv4Network | ipaddress.IPv6Network

KEYS = ("tcp", "udp", "icmp", "icmpv6", "ip")
FULL = {"tcp": (0, 65535), "udp": (0, 65535), "icmp": (0, 255), "icmpv6": (0, 255), "ip": (0, 255)}
PROTO_NAMES = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6"}
IP_NAMES = {0: "HOPOPT", 2: "IGMP", 4: "IPv4", 41: "IPv6", 47: "GRE", 50: "ESP", 51: "AH", 89: "OSPF",
            103: "PIM", 112: "VRRP", 132: "SCTP"}


def _collapse(nets: Iterable[Network]) -> tuple[Network, ...]:
    v4 = [n for n in nets if n.version == 4]
    v6 = [n for n in nets if n.version == 6]
    return tuple(ipaddress.collapse_addresses(v4)) + tuple(ipaddress.collapse_addresses(v6))


@dataclass(frozen=True)
class Peers:
    nets: tuple[Network, ...] = ()
    atoms: frozenset[str] = frozenset()

    @staticmethod
    def of(nets: Iterable[Network] = (), atoms: Iterable[str] = ()) -> "Peers":
        return Peers(_collapse(nets), frozenset(atoms))

    def __bool__(self) -> bool:
        return bool(self.nets or self.atoms)

    def minus(self, other: "Peers") -> "Peers":
        left = list(self.nets)
        for o in other.nets:
            nxt = []
            for n in left:
                if n.version != o.version or not n.overlaps(o):
                    nxt.append(n)
                elif n.subnet_of(o):
                    continue
                else:
                    nxt.extend(n.address_exclude(o))
            left = nxt
        return Peers.of(left, self.atoms - other.atoms)

    def overlaps(self, other: "Peers") -> bool:
        if self.atoms & other.atoms:
            return True
        return any(a.version == b.version and a.overlaps(b) for a in self.nets for b in other.nets)


@dataclass(frozen=True)
class Rect:
    key: str
    lo: int
    hi: int
    peers: Peers

    def minus(self, other: "Rect") -> list["Rect"]:
        if other.key != self.key or other.hi < self.lo or other.lo > self.hi or not self.peers.overlaps(other.peers):
            return [self]
        out = []
        if self.lo < other.lo:
            out.append(Rect(self.key, self.lo, other.lo - 1, self.peers))
        if other.hi < self.hi:
            out.append(Rect(self.key, other.hi + 1, self.hi, self.peers))
        mid = self.peers.minus(other.peers)
        if mid:
            out.append(Rect(self.key, max(self.lo, other.lo), min(self.hi, other.hi), mid))
        return out


@dataclass
class Rule:
    """One security group rule, normalized."""
    id: str
    group: str
    egress: bool
    protocol: str            # -1, tcp, udp, icmp, icmpv6, or a protocol number
    lo: int | None
    hi: int | None
    peer_kind: str           # cidr, pl, sg
    peer: str
    description: str | None = None
    peer_nets: tuple = field(default=(), repr=False)    # expanded prefix list entries

    def signature(self) -> tuple:
        return (self.egress, self.protocol, self.lo, self.hi, self.peer_kind, self.peer)

    def peers(self) -> Peers:
        if self.peer_kind == "cidr":
            return Peers.of([ipaddress.ip_network(self.peer, strict=False)])
        if self.peer_kind == "pl":
            return Peers.of(self.peer_nets) if self.peer_nets else Peers.of(atoms=[f"pl:{self.peer}"])
        return Peers.of(atoms=[f"sg:{self.peer}"])

    def rects(self) -> list[Rect]:
        peers = self.peers()
        if self.protocol == "-1":
            return [Rect(k, *FULL[k], peers) for k in KEYS]
        if self.protocol in ("tcp", "udp"):
            lo, hi = (0, 65535) if self.lo in (None, -1) else (self.lo, self.hi if self.hi is not None else self.lo)
            return [Rect(self.protocol, lo, hi, peers)]
        if self.protocol in ("icmp", "icmpv6"):
            if self.lo in (None, -1):
                return [Rect(self.protocol, 0, 255, peers)]
            return [Rect(self.protocol, self.lo, self.lo, peers)]
        num = int(self.protocol)
        return [Rect("ip", num, num, peers)]


def normalize_protocol(p: str | int | None) -> str:
    p = str(p if p is not None else "-1").lower()
    return PROTO_NAMES.get(p, p)


def subtract(rects: list[Rect], others: Iterable[Rect]) -> list[Rect]:
    left = list(rects)
    for o in others:
        left = [piece for r in left for piece in r.minus(o)]
        if not left:
            break
    return left


def residual(rule: Rule, others: Iterable[Rule]) -> list[Rect]:
    """The traffic `rule` allows that none of `others` (same direction) allows."""
    rects = [r for o in others if o.egress == rule.egress for r in o.rects()]
    return subtract(rule.rects(), rects)


def covers(big: Rule, small: Rule) -> bool:
    return big.egress == small.egress and not subtract(small.rects(), big.rects())


# ---------- display ----------

def ports_text(protocol: str, lo: int | None, hi: int | None) -> str:
    if protocol == "-1":
        return "all traffic"
    if protocol in ("tcp", "udp"):
        if lo in (None, -1) or (lo == 0 and hi == 65535):
            return f"{protocol} all ports"
        return f"{protocol} {lo}" if lo == hi else f"{protocol} {lo}-{hi}"
    if protocol in ("icmp", "icmpv6"):
        return f"{protocol} all types" if lo in (None, -1) else f"{protocol} type {lo}"
    num = int(protocol)
    return f"protocol {num}" + (f" ({IP_NAMES[num]})" if num in IP_NAMES else "")


def rule_traffic(rule: Rule) -> str:
    return ports_text(rule.protocol, rule.lo, rule.hi)


def _rect_traffic(r: Rect) -> str:
    if r.key in ("tcp", "udp"):
        return ports_text(r.key, r.lo, r.hi) if (r.lo, r.hi) != FULL[r.key] else f"{r.key} all ports"
    if r.key in ("icmp", "icmpv6"):
        if (r.lo, r.hi) == FULL[r.key]:
            return f"{r.key} all types"
        return f"{r.key} type {r.lo}" if r.lo == r.hi else f"{r.key} types {r.lo}-{r.hi}"
    if (r.lo, r.hi) == FULL["ip"]:
        return "all other protocols"
    return ports_text(str(r.lo), r.lo, r.lo) if r.lo == r.hi else f"protocols {r.lo}-{r.hi}"


def peers_text(peers: Peers, names: dict[str, str] | None = None, limit: int = 6) -> str:
    names = names or {}
    parts = [str(n) for n in peers.nets]
    for a in sorted(peers.atoms):
        kind, _, ident = a.partition(":")
        parts.append(f"{ident} ({names[ident]})" if names.get(ident) else ident)
    if len(parts) > limit:
        return ", ".join(parts[:limit]) + f" and {len(parts) - limit} more"
    return ", ".join(parts)


def describe(rects: list[Rect], egress: bool, names: dict[str, str] | None = None,
             original: Rule | None = None) -> list[str]:
    """Human lines for a residual. When it's all of a rule, say it in the rule's terms."""
    if not rects:
        return []
    word = "to" if egress else "from"
    if original is not None and not subtract(original.rects(), rects):
        return [f"{rule_traffic(original)} {word} {peer_label(original, names)}"]
    if original is not None:
        # Same traffic as the rule, fewer peers: say which peers are still allowed.
        whole = original.rects()
        out, rest = [], []
        for r in rects:
            src = next((w for w in whole if (w.key, w.lo, w.hi) == (r.key, r.lo, r.hi)), None)
            (out if src is not None and src.peers != r.peers else rest).append((r, src))
        if out and not rest:
            kept = {peers_text(src.peers.minus(r.peers), names) for r, src in out}
            return [f"{rule_traffic(original)} {word} {peer_label(original, names)} except {k}" for k in sorted(kept)]
    every = all((r.lo, r.hi) == FULL[r.key] for r in rects) and {r.key for r in rects} == set(KEYS) \
        and len({r.peers for r in rects}) == 1
    if every:
        return [f"all traffic {word} {peers_text(rects[0].peers, names)}"]
    return [f"{_rect_traffic(r)} {word} {peers_text(r.peers, names)}" for r in rects]


def peer_label(rule: Rule, names: dict[str, str] | None = None) -> str:
    names = names or {}
    if rule.peer_kind == "cidr":
        return rule.peer
    label = names.get(rule.peer)
    return f"{rule.peer} ({label})" if label else rule.peer
