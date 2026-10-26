#!/usr/bin/env python3
"""Simulate a router's "show ip bgp" / "show ip route" over AWS Direct Connect virtual interfaces.

dr_core.collect() reads the VIFs in scope and every route each one has accepted from
the customer router (ListVirtualInterfaceRoutes: prefix, AS path, communities).
dr_core.select() ranks the paths for each prefix the way AWS documents for traffic
toward on-premises: longest prefix, local preference (7224:7x00 communities, or the
associated-Region default), AS_PATH length, then ECMP. dr_cisco prints the result in
Cisco IOS syntax, and dr_export writes an HTML report. Read-only.

    dx_route.py show ip bgp 10.20.30.0/24 --dx-gateway dxgw-0123...
    dx_route.py show ip route 10.20.30.7 --region us-east-1
    dx_route.py show ip bgp 10.0.0.0 255.0.0.0 longer-prefixes
    dx_route.py show ip bgp summary
    dx_route.py show ip bgp neighbors 169.254.10.1 advertised-routes
    dx_route.py show ipv6 route 2001:db8:10::/48

Logs go to stderr; the router output (or --json) goes to stdout.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

import truststore

truststore.inject_into_ssl()

from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound  # noqa: E402
from dotenv import load_dotenv  # noqa: E402

import dr_cisco as cisco  # noqa: E402
import dr_core as core  # noqa: E402
from dr_export import THEMES, render_html  # noqa: E402

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("dx_route")

EXIT_OK, EXIT_ERROR, EXIT_NO_ROUTE = 0, 1, 2

USAGE = """\
  show {ip|ipv6} bgp [vrf TABLE] [PREFIX [MASK] [longer-prefixes]]
  show {ip|ipv6} bgp [vrf TABLE] summary
  show {ip|ipv6} bgp [vrf TABLE] neighbors [ADDRESS|VIF] {received-routes|advertised-routes}
  show {ip|ipv6} route [vrf TABLE] [PREFIX [MASK] [longer-prefixes]]
'show' is optional. TABLE is a Direct Connect gateway or virtual private gateway ID.
PREFIX is an address (longest match) or a prefix of any length."""


def parse_command(words: list[str]) -> dict:
    """Parse IOS-style words into {kind, afi, prefix, longer, table, which, neighbor, text}."""
    w = [x for x in words if x]
    if w and w[0].lower() in ("show", "sh"):
        w = w[1:]
    if len(w) < 2 or w[0].lower() not in ("ip", "ipv6") or w[1].lower() not in ("bgp", "route"):
        raise core.ValidationError("Expected a command like 'show ip bgp PREFIX' or 'show ip route PREFIX':\n" + USAGE)
    afi, kind = w[0].lower(), w[1].lower()
    rest = w[2:]
    cmd: dict = {"afi": afi, "kind": kind, "prefix": None, "longer": False, "table": None,
                 "which": None, "neighbor": None}
    if len(rest) >= 2 and rest[0].lower() == "vrf":
        cmd["table"], rest = rest[1], rest[2:]
    low = [x.lower() for x in rest]
    if kind == "bgp" and low[:1] == ["summary"]:
        cmd["kind"] = "summary"
        rest = rest[1:]
    elif kind == "bgp" and low[:1] in (["neighbors"], ["neighbor"]):
        cmd["kind"] = "neighbors"
        args = rest[1:]
        tail = [a.lower() for a in args]
        which = next((t for t in tail if t in ("received-routes", "advertised-routes", "routes")), None)
        if not which:
            raise core.ValidationError("'show ip bgp neighbors' needs received-routes or advertised-routes:\n" + USAGE)
        cmd["which"] = "received-routes" if which == "routes" else which
        others = [a for a in args if a.lower() != which]
        cmd["neighbor"] = others[0] if others else None
        rest = others[1:]
    else:
        if low and low[-1] == "longer-prefixes":
            cmd["longer"] = True
            rest = rest[:-1]
        if rest:
            cmd["prefix"] = core.parse_prefix(" ".join(rest[:2]))
            if cmd["prefix"].version != (6 if afi == "ipv6" else 4):
                raise core.ValidationError(f"{cmd['prefix']} is not an {'IPv6' if afi == 'ipv6' else 'IPv4'} prefix; "
                                           f"use 'show {'ip' if afi == 'ipv6' else 'ipv6'} ...'")
            rest = rest[2:]
        if cmd["longer"] and not cmd["prefix"]:
            raise core.ValidationError("longer-prefixes needs a PREFIX")
    if rest:
        raise core.ValidationError(f"Unexpected words: {' '.join(rest)}\n" + USAGE)
    cmd["text"] = "show " + " ".join(w)
    return cmd


def _dump(obj) -> str:
    return json.dumps(obj, indent=2, default=lambda o: o.isoformat() if hasattr(o, "isoformat") else str(o))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0], usage="%(prog)s [options] COMMAND...\n\n" + USAGE,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("command", nargs="*", metavar="COMMAND", help="IOS-style command (see usage)")
    p.add_argument("--profile", default=os.getenv("AWS_PROFILE"),
                   help="AWS profile (not included in reports)")
    p.add_argument("--region", default=os.getenv("DXR_REGION") or os.getenv("AWS_REGION")
                   or os.getenv("AWS_DEFAULT_REGION"), help="Region whose VIFs to read (and the API Region)")
    p.add_argument("--regions", metavar="R1,R2", default=os.getenv("DXR_REGIONS"),
                   help="Read the VIFs of several Regions (comma-separated)")
    p.add_argument("--from-region", default=os.getenv("DXR_FROM_REGION"),
                   help="Region the traffic leaves from, for the default local preference (default: --region)")
    p.add_argument("--dx-gateway", default=os.getenv("DXR_DX_GATEWAY"), metavar="DXGW_ID",
                   help="Only this Direct Connect gateway's VIFs, in any Region or account")
    p.add_argument("--vif", action="append", default=[], metavar="DXVIF_ID", help="Only these VIFs (repeatable)")
    p.add_argument("--account-profile", action="append", default=[], metavar="ACCOUNT_ID=PROFILE",
                   help="Profile for VIFs owned by another account (repeatable); otherwise found in the local AWS "
                        "config by account ID, never using profiles that end in -priv or -cpar")
    p.add_argument("--advertised", action="store_true",
                   help="Also collect the routes AWS advertises on each VIF (implied by advertised-routes)")
    p.add_argument("--output", "-o", metavar="FILE.html", help="Write the HTML report here")
    p.add_argument("--reports-dir", default=os.getenv("DXR_REPORTS_DIR", "reports"), metavar="DIR",
                   help="Reports root; reports go to DIR/<YYYY-MM-DD>/<scope>/ (default: ./reports)")
    p.add_argument("--no-report", action="store_true", help="Print the router output only")
    p.add_argument("--theme", choices=THEMES, default=os.getenv("DXR_THEME", "dark"),
                   help="HTML report theme: dark (default), light, or auto")
    p.add_argument("--title", help="HTML page title")
    p.add_argument("--json", action="store_true", help="Print the path selection as JSON instead")
    p.add_argument("--json-out", metavar="FILE.json", help="Also save the bundle for --from-json")
    p.add_argument("--from-json", metavar="FILE.json", help="Re-run commands on a saved bundle, offline")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    return p


def _no_route(bundle: dict, cmd: dict) -> bool:
    """True when a prefix lookup found nothing in any routing table."""
    if cmd["kind"] not in ("bgp", "route") or not cmd["prefix"] or cmd["longer"]:
        return False
    tables = core.select(bundle)
    return not any(core.covering(t, cmd["prefix"]) for t in tables.values())


def selection_json(bundle: dict, cmd: dict) -> dict:
    tables = core.select(bundle)
    v = 6 if cmd["afi"] == "ipv6" else 4
    out = {}
    for key, table in tables.items():
        prefixes = [c for c in table if core.net(c).version == v]
        if cmd["prefix"]:
            q = cmd["prefix"]
            prefixes = core.longer_prefixes(table, q) if cmd["longer"] else core.covering(table, q)
        out[key] = {c: table[c] for c in core.sort_prefixes(prefixes)}
    return {"command": cmd["text"], "from_region": bundle.get("from_region"), "tables": out,
            "warnings": bundle.get("warnings") or []}


def run(args) -> int:
    cmd = parse_command(args.command)
    if args.from_json:
        bundle = json.loads(Path(args.from_json).read_text(encoding="utf-8"))
        if cmd["which"] == "advertised-routes" and core.ADVERTISED not in (bundle.get("directions") or []):
            log.warning("This bundle has no advertised routes; collect it again with --advertised")
    else:
        regions = [r.strip() for r in args.regions.split(",") if r.strip()] if args.regions else []
        if not regions and args.region:
            regions = [args.region]
        sessions = core.Sessions(args.profile, regions[0] if regions else None,
                                 core.parse_account_profiles(args.account_profile))
        if not regions:
            if not sessions.region:
                raise core.ValidationError("No region configured; pass --region or set AWS_REGION")
            regions = [sessions.region]
        directions = (core.ACCEPTED, core.ADVERTISED) if args.advertised or cmd["which"] == "advertised-routes" \
            else (core.ACCEPTED,)
        bundle = json.loads(_dump(core.collect(
            sessions, cmd["prefix"], regions=regions, from_region=args.from_region or regions[0],
            dx_gateway=args.dx_gateway, vif_ids=args.vif, directions=directions,
            fam="ipv6" if cmd["afi"] == "ipv6" else "ipv4")))
    if args.from_region and args.from_json:
        bundle["from_region"] = args.from_region

    output = cisco.render(bundle, cmd)
    if args.json:
        print(_dump(selection_json(bundle, cmd)))
    else:
        sys.stdout.write(output)
    for w in bundle.get("warnings") or []:
        log.warning("%s", w)
    if args.json_out:
        Path(args.json_out).write_text(_dump(bundle), encoding="utf-8")
        log.info("Wrote JSON %s", args.json_out)
    if not args.no_report:
        out = Path(args.output) if args.output else core.report_path(bundle, cmd["text"], args.reports_dir)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(render_html(bundle, cmd, output, args.title, args.theme), encoding="utf-8")
        log.info("Wrote HTML report %s", out)
    return EXIT_NO_ROUTE if _no_route(bundle, cmd) else EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.quiet:
        logging.getLogger().setLevel(logging.WARNING)
    try:
        return run(args)
    except (core.ValidationError, LookupError, ValueError) as e:
        log.error("%s", e)
        return EXIT_ERROR
    except (NoCredentialsError, ProfileNotFound) as e:
        log.error("Credentials error: %s", e)
        return EXIT_ERROR
    except ClientError as e:
        log.error("AWS error %s: %s", e.response["Error"]["Code"], e.response["Error"]["Message"])
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
