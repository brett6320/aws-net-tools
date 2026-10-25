"""Synthetic prefix_list_audit report: made-up PrefixList records (as collect_region() would
build them) run through the tool's own dedupe_shared(), check_list() and check_name_drift()."""
from __future__ import annotations

import re
from collections import Counter

import prefix_list_audit as pla
from lib.output import SEVERITY_ORDER

SHOTS = [("prefix-list-audit", "dark", 1000)]

HUB, APP, DEV = "111122223333", "444455556666", "777788889999"
PROFILE = {HUB: "network-ro", APP: "apps-prod-ro", DEV: "dev-ro"}
GENERATED = "2026-03-16 09:42:07"

ONPREM = ["10.0.0.0/16", "10.1.0.0/16", "10.2.0.0/16", "10.8.0.0/14", "10.16.0.0/12", "172.16.0.0/16",
          "172.17.0.0/16", "172.20.0.0/14", "192.168.0.0/20", "192.168.16.0/20", "192.168.64.0/18",
          "192.168.128.0/17"]


def ent(cidrs: list[str], desc: str = "") -> list[dict]:
    return [{"cidr": pla._norm_cidr(c), "description": desc} for c in cidrs]


def assoc(*ids: str) -> list[dict]:
    return [{"ResourceId": i, "ResourceOwner": HUB} for i in ids]


def pl(account: str, region: str, pid: str, name: str, cidrs: list[str], max_entries: int | None,
       associations: list[dict] | None, *, owner: str | None = None, state: str = "modify-complete",
       family: str = "IPv4", version: int = 3) -> pla.PrefixList:
    owner = owner or account
    return pla.PrefixList(account=account, profile=PROFILE[account], region=region, prefix_list_id=pid, name=name,
                          family=family, owner=owner, ownership=pla.ownership_of(owner, account), state=state,
                          version=version, max_entries=max_entries, entries=ent(cidrs), associations=associations)


LISTS = [
    # hub: the corporate list, its us-west-2 copy, and a full partner list
    pl(HUB, "us-east-1", "pl-0123456789abcdef0", "corp-onprem-v4", ONPREM, 20,
       assoc("sg-0fedcba9876543210", "sg-01a2b3c4d5e6f7081", "rtb-0a1b2c3d4e5f60718", "rtb-0a1b2c3d4e5f60719"),
       version=14),
    pl(HUB, "us-west-2", "pl-0abcdef1234567890", "corp-onprem-v4", ONPREM, 20,
       assoc("sg-02b3c4d5e6f708192", "rtb-0b1c2d3e4f5a60718"), version=9),
    pl(HUB, "us-east-1", "pl-0c0ffee0123456789", "partner-vpn", [f"10.200.{i}.0/24" for i in range(10)], 10,
       assoc("sg-0fedcba9876543210", "sg-03c4d5e6f7081920a"), version=22),
    pl(HUB, "us-east-1", "pl-0d1e2f3a4b5c6d7e8", "corp-onprem-v6", ["fd00:10::/32", "fd00:20::/32", "fd00:20:1::/48"],
       10, assoc("sg-01a2b3c4d5e6f7081"), family="IPv6", version=2),
    pl(HUB, "us-east-1", "pl-63a5400a", "com.amazonaws.us-east-1.s3", ["198.51.100.0/24", "203.0.113.0/24"], None,
       None, owner="AWS", state="create-complete", version=1),
    # app account: sees the hub's list via RAM, owns a few of its own
    pl(APP, "us-east-1", "pl-0123456789abcdef0", "corp-onprem-v4", ONPREM, 20, None, owner=HUB, version=14),
    pl(APP, "us-east-1", "pl-0e1f2a3b4c5d6e7f8", "office-egress",
       ["192.0.2.0/28", "192.0.2.16/28", "192.0.2.32/28", "192.0.2.48/28", "192.0.2.64/28", "192.0.2.80/28",
        "198.51.100.8/29", "198.51.100.16/29", "198.51.100.24/29"], 10,
       assoc("sg-04d5e6f708192a3b4", "sg-05e6f708192a3b4c5")),
    pl(APP, "us-east-1", "pl-0f2a3b4c5d6e7f809", "vendor-saas", ["203.0.113.32/27", "203.0.113.64/27"], 5, []),
    pl(APP, "us-west-2", "pl-01b2c3d4e5f607182", "monitoring-sources",
       ["10.50.0.0/24", "10.50.1.0/24", "10.51.0.0/24", "10.51.1.0/24", "172.31.200.0/24", "172.31.201.0/24"], 100,
       assoc("sg-06f708192a3b4c5d6", "sg-0708192a3b4c5d6e7", "sg-08192a3b4c5d6e7f8", "sg-092a3b4c5d6e7f809")),
    pl(APP, "us-west-2", "pl-02c3d4e5f60718293", "corp-onprem-v4", ONPREM, 20, assoc("sg-0a3b4c5d6e7f8091a")),
    # dev account: a drifted copy, an abandoned list, and a stuck one with overlaps
    pl(DEV, "us-east-1", "pl-03d4e5f6071829304", "corp-onprem-v4",
       [c for c in ONPREM if c not in ("192.168.64.0/18", "192.168.128.0/17")] + ["10.99.0.0/16"], 20,
       assoc("sg-0b4c5d6e7f8091a2b")),
    pl(DEV, "us-east-1", "pl-04e5f60718293a415", "legacy-dmz", [], 10, []),
    pl(DEV, "us-west-2", "pl-05f60718293a4b526", "build-runners",
       ["10.70.0.0/16", "10.70.4.0/24", "10.70.8.0/24", "10.71.0.0/16", "10.71.0.0/16"], 25,
       assoc("sg-0c5d6e7f8091a2b3c"), state="modify-failed"),
    pl(DEV, "us-west-2", "pl-06071829304a5b637", "office-egress",
       ["192.0.2.0/28", "192.0.2.16/28", "192.0.2.32/28"], 50, assoc("sg-0d6e7f8091a2b3c4d")),
]

SKIPPED = [pla.Finding("error", "PROFILE_ACCOUNT_MISMATCH", account="555566667777", profile="sandbox-ro",
                       detail="profile sandbox-ro resolves to 999988887777, not 555566667777")]


def render() -> str:
    """Run the checks the way run() does after collection, and return the HTML report."""
    findings = list(SKIPPED)
    for p in pla.dedupe_shared(LISTS):
        findings += pla.check_list(p, pla.DEFAULT_HEADROOM, pla.DEFAULT_FULL_PCT)
    findings += pla.check_name_drift(LISTS)
    findings.sort(key=lambda f: (f.account, f.region, f.prefix_list_name, f.prefix_list_id,
                                 SEVERITY_ORDER[f.severity], f.code))
    stats = {"accounts": len({p.account for p in LISTS}), "accounts_skipped": len(SKIPPED),
             "regions": len({p.region for p in LISTS}), "prefix_lists": len({p.prefix_list_id for p in LISTS}),
             "by_code": dict(sorted(Counter(f.code for f in findings).items()))}
    html = pla.render_html(LISTS, findings, stats)
    # render_html stamps the current time; pin it so the screenshot is reproducible
    return re.sub(r"Generated \d{4}-\d\d-\d\d \d\d:\d\d:\d\d", f"Generated {GENERATED}", html, count=1)
