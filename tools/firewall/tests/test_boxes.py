import ipaddress
import itertools
import random

import pytest

from lib.boxes import (ALL_PORTS, ALL_PROTOS, addr_interval, fmt_addrs, fmt_proto_ports, intersects, merge,
                       proto_num, proto_port_box, remainder, subtract)

V4 = lambda c: addr_interval(ipaddress.ip_network(c))  # noqa: E731
TCP = (6, 6)


def box(pr, ports, cidr):
    return (pr, ports, V4(cidr))


def points(boxes):
    """Every integer point of a list of (small) boxes."""
    return {p for b in boxes for p in itertools.product(*(range(lo, hi + 1) for lo, hi in b))}


def rand_box(rng, n=6):
    def iv():
        a, b = sorted((rng.randint(0, n), rng.randint(0, n)))
        return (a, b)
    return (iv(), iv(), iv())


# --------------------------------------------------------------------------- #
# intersects / subtract / merge / remainder
# --------------------------------------------------------------------------- #
def test_intersects_needs_overlap_in_every_dimension():
    a = box(TCP, (443, 443), "10.0.0.0/8")
    assert intersects(a, box(TCP, (443, 443), "10.1.0.0/16"))
    assert not intersects(a, box(TCP, (80, 80), "10.1.0.0/16"))          # ports differ
    assert not intersects(a, box((17, 17), (443, 443), "10.0.0.0/8"))    # protocol differs
    assert not intersects(a, box(TCP, (443, 443), "11.0.0.0/8"))         # addresses differ


def test_intersects_touching_intervals_are_inclusive():
    a = ((0, 0), (10, 20), (0, 0))
    assert intersects(a, ((0, 0), (20, 30), (0, 0)))
    assert not intersects(a, ((0, 0), (21, 30), (0, 0)))


def test_subtract_disjoint_returns_original():
    a = box(TCP, (22, 22), "10.0.0.0/8")
    assert subtract(a, box(TCP, (80, 80), "10.0.0.0/8")) == [a]


def test_subtract_full_cover_is_empty():
    a = box(TCP, (443, 443), "10.1.0.0/16")
    assert subtract(a, box(ALL_PROTOS, ALL_PORTS, "0.0.0.0/0")) == []


def test_subtract_port_hole():
    a = box(TCP, ALL_PORTS, "10.0.0.0/8")
    assert subtract(a, box(TCP, (443, 443), "10.0.0.0/8")) == [
        box(TCP, (0, 442), "10.0.0.0/8"), box(TCP, (444, 65535), "10.0.0.0/8")]


@pytest.mark.parametrize("seed", range(40))
def test_subtract_is_exact_and_disjoint(seed):
    rng = random.Random(seed)
    a, b = rand_box(rng), rand_box(rng)
    pieces = subtract(a, b)
    assert points(pieces) == points([a]) - points([b])
    assert sum(len(points([p])) for p in pieces) == len(points(pieces))   # pieces never overlap


@pytest.mark.parametrize("seed", range(20))
def test_remainder_and_merge_preserve_points(seed):
    rng = random.Random(1000 + seed)
    a = rand_box(rng)
    others = [rand_box(rng) for _ in range(4)]
    rem = remainder(a, others)
    assert points(rem) == points([a]) - points(others)
    merged = merge(rem)
    assert points(merged) == points(rem)
    assert len(merged) <= len(rem)


def test_remainder_no_others_and_full_cover():
    a = box(TCP, (443, 443), "10.0.0.0/8")
    assert remainder(a, []) == [a]
    assert remainder(a, [box(TCP, (0, 1000), "0.0.0.0/0"), box(TCP, (443, 443), "10.0.0.0/8")]) == []


def test_merge_coalesces_adjacent_and_overlapping():
    a = V4("10.0.0.0/8")
    assert merge([(TCP, (0, 442), a), (TCP, (443, 443), a), (TCP, (444, 65535), a)]) == [(TCP, ALL_PORTS, a)]
    assert merge([(TCP, (10, 20), a), (TCP, (15, 30), a)]) == [(TCP, (10, 30), a)]
    # a gap stays a gap; result is sorted and deduplicated
    assert merge([(TCP, (40, 50), a), (TCP, (10, 20), a), (TCP, (10, 20), a)]) == [(TCP, (10, 20), a),
                                                                                   (TCP, (40, 50), a)]
    assert merge([]) == []


def test_merge_adjacent_cidrs_then_format():
    lo, hi = V4("10.0.0.0/25"), V4("10.0.0.128/25")
    merged = merge([(TCP, (22, 22), lo), (TCP, (22, 22), hi)])
    assert merged == [(TCP, (22, 22), V4("10.0.0.0/24"))]
    assert fmt_addrs("ipv4", merged[0][2]) == ["10.0.0.0/24"]


def test_cidr_hole_matches_address_exclude():
    big, hole = ipaddress.ip_network("10.0.0.0/16"), ipaddress.ip_network("10.0.3.0/24")
    rem = merge(remainder((TCP, (443, 443), addr_interval(big)), [(TCP, (443, 443), addr_interval(hole))]))
    got = sorted(ipaddress.ip_network(c) for b in rem for c in fmt_addrs("ipv4", b[2]))
    assert got == sorted(big.address_exclude(hole))


def test_ipv6_interval_round_trip():
    net = ipaddress.ip_network("2001:db8::/32")
    iv = addr_interval(net)
    assert iv == (int(net.network_address), int(net.broadcast_address))
    assert fmt_addrs("ipv6", iv) == ["2001:db8::/32"]
    assert fmt_addrs("ipv6", addr_interval(ipaddress.ip_network("::/0"))) == ["::/0"]


def test_fmt_addrs_non_contiguous_range_and_opaque_spaces():
    lo = int(ipaddress.ip_address("10.0.0.0"))
    assert fmt_addrs("ipv4", (lo, lo + 2)) == ["10.0.0.0/31", "10.0.0.2/32"]
    assert fmt_addrs("sg:sg-0123456789abcdef0", (0, 0)) == ["sg-0123456789abcdef0"]
    assert fmt_addrs("pl:pl-0abc", (0, 0)) == ["pl-0abc"]


# --------------------------------------------------------------------------- #
# protocols / ports
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("raw,num", [("-1", None), ("all", None), ("", None), ("ALL", None), ("tcp", 6),
                                     (" UDP ", 17), ("icmp", 1), ("icmpv6", 58), ("50", 50), (6, 6), (-1, None)])
def test_proto_num(raw, num):
    assert proto_num(raw) == num


def test_proto_num_rejects_unknown_name():
    with pytest.raises(ValueError):
        proto_num("gre")


@pytest.mark.parametrize("proto,fp,tp,expected", [
    ("-1", None, None, (ALL_PROTOS, ALL_PORTS)),
    ("-1", 0, 0, (ALL_PROTOS, ALL_PORTS)),            # all traffic ignores ports
    ("tcp", 80, 90, (TCP, (80, 90))),
    ("tcp", -1, -1, (TCP, ALL_PORTS)),
    ("udp", None, None, ((17, 17), ALL_PORTS)),
    ("6", 443, 443, (TCP, (443, 443))),
    ("icmp", -1, -1, ((1, 1), ALL_PORTS)),
    ("icmp", 8, -1, ((1, 1), (2048, 2303))),          # type 8, any code
    ("icmp", 3, 4, ((1, 1), (772, 772))),             # type 3 code 4
    ("icmpv6", 128, None, ((58, 58), (32768, 33023))),
    ("58", 1, 0, ((58, 58), (256, 256))),
    ("50", 0, 0, ((50, 50), ALL_PORTS)),              # other protocols span every port
])
def test_proto_port_box(proto, fp, tp, expected):
    assert proto_port_box(proto, fp, tp) == expected


@pytest.mark.parametrize("pr,ports,text", [
    (ALL_PROTOS, ALL_PORTS, "all traffic"),
    (ALL_PROTOS, (1, 2), "all traffic"),
    ((0, 5), ALL_PORTS, "protocols 0-5"),
    ((0, 5), (1, 2), "protocols 0-5 ports 1-2"),
    (TCP, ALL_PORTS, "tcp all"),
    ((50, 50), ALL_PORTS, "proto 50"),
    ((50, 50), (1, 2), "proto 50 1-2"),
    (TCP, (443, 443), "tcp 443"),
    ((17, 17), (1000, 2000), "udp 1000-2000"),
    ((1, 1), (2048, 2303), "icmp type 8"),
    ((1, 1), (772, 772), "icmp type 3 code 4"),
    ((1, 1), (768, 1279), "icmp types 3-4"),
    ((1, 1), (770, 1000), "icmp type/code 3/2-3/232"),
    ((58, 58), (32768, 33023), "icmpv6 type 128"),
    ((1, 1), ALL_PORTS, "icmp all"),
])
def test_fmt_proto_ports(pr, ports, text):
    assert fmt_proto_ports(pr, ports) == text


def test_fmt_round_trips_proto_port_box():
    assert fmt_proto_ports(*proto_port_box("icmp", 0, -1)) == "icmp type 0"
    assert fmt_proto_ports(*proto_port_box("tcp", 8000, 8100)) == "tcp 8000-8100"
    assert fmt_proto_ports(*proto_port_box("-1", None, None)) == "all traffic"
