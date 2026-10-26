#!/usr/bin/env python3
"""Back up AWS Direct Connect configuration, compare backups, and plan a restore.

    dx_backup.py backup --region us-east-1
    dx_backup.py diff previous latest
    dx_backup.py diff latest live
    dx_backup.py restore-plan latest -o restore.sh

backup        reads every connection, LAG, VIF (BGP peers, prefixes, tags), Direct
              Connect gateway (associations, allowed prefixes, attachments, proposals)
              and each VIF's advertised and accepted routes, and writes one JSON file
              per object plus a manifest to <backup-dir>/<account>/<UTC timestamp>/.
diff          compares two backups, or a backup and the live configuration ("live").
restore-plan  writes the AWS CLI commands that would bring the current configuration
              back to a backup. It never runs them.

A backup can be named by its directory, or as "latest" / "previous". BGP auth keys are
stored only as salted SHA-256 fingerprints. Read-only against AWS.
Logs go to stderr; results go to stdout.
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

import db_core as core  # noqa: E402
import db_diff  # noqa: E402
import db_restore  # noqa: E402
from db_export import THEMES, render_html  # noqa: E402

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("dx_backup")

EXIT_OK, EXIT_ERROR, EXIT_CHANGES = 0, 1, 2
LIVE = "live"


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--profile", default=os.getenv("AWS_PROFILE"), help="AWS profile (never written to backups)")
    common.add_argument("--region", default=os.getenv("DXB_REGION") or os.getenv("AWS_REGION")
                        or os.getenv("AWS_DEFAULT_REGION"), help="Region to read (and the API Region)")
    common.add_argument("--regions", metavar="R1,R2", default=os.getenv("DXB_REGIONS"),
                        help="Read several Regions (comma-separated)")
    common.add_argument("--backup-dir", default=os.getenv("DXB_BACKUP_DIR", "backups"), metavar="DIR",
                        help="Backups root: DIR/<account>/<timestamp>/ (default: ./backups)")
    common.add_argument("--account", metavar="ACCOUNT_ID", help="With latest/previous: only this account's backups")
    common.add_argument("-v", "--verbose", action="store_true")
    common.add_argument("-q", "--quiet", action="store_true")

    p = argparse.ArgumentParser(description=__doc__.splitlines()[0], formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog="\n".join(__doc__.splitlines()[2:]))
    sub = p.add_subparsers(dest="command", required=True, metavar="COMMAND")

    b = sub.add_parser("backup", parents=[common], help="Write a backup of the live configuration")
    b.add_argument("--no-routes", action="store_true", help="Skip the advertised and accepted routes")
    b.add_argument("--json", action="store_true", help="Print the manifest as JSON")

    d = sub.add_parser("diff", parents=[common], help="Compare two backups, or a backup and live")
    d.add_argument("old", help="Backup directory, latest, previous (or live)")
    d.add_argument("new", nargs="?", default=LIVE, help="Backup directory, latest, previous, or live (default)")
    d.add_argument("--state", action="store_true", help="Also compare operational state (BGP status, object state...)")
    d.add_argument("--json", action="store_true", help="Print the changes as JSON")
    d.add_argument("--output", "-o", metavar="FILE.html", help="Write the HTML report here")
    d.add_argument("--reports-dir", default=os.getenv("DXB_REPORTS_DIR", "reports"), metavar="DIR",
                   help="Reports root; reports go to DIR/<YYYY-MM-DD>/<account>/ (default: ./reports)")
    d.add_argument("--no-report", action="store_true", help="Print the text diff only")
    d.add_argument("--theme", choices=THEMES, default=os.getenv("DXB_THEME", "dark"), help="HTML report theme")
    d.add_argument("--title", help="HTML page title")

    r = sub.add_parser("restore-plan", parents=[common], help="AWS CLI commands to restore a backup (never run)")
    r.add_argument("backup", help="Backup to restore: a directory, latest or previous")
    r.add_argument("--against", default=LIVE, metavar="REF",
                   help="Configuration to restore over: live (default) or a backup")
    r.add_argument("--output", "-o", metavar="FILE.sh", help="Write the plan here instead of stdout")
    return p


def _regions(args, fallback: list[str] | None = None) -> list[str]:
    if args.regions:
        return [r.strip() for r in args.regions.split(",") if r.strip()]
    if args.region:
        return [args.region]
    return list(fallback or [])


def live_snapshot(args, like: dict | None = None) -> dict:
    """Collect the live configuration, for the same Regions (and route setting) as `like`."""
    m = (like or {}).get("manifest") or {}
    regions = _regions(args, m.get("regions"))
    session = core.get_session(args.profile, regions[0] if regions else None)
    if not regions and session.region_name:
        regions = [session.region_name]
    snap = core.collect(session, regions, routes=m.get("routes", True) if like else not getattr(args, "no_routes", False))
    if m.get("account") and snap["manifest"]["account"] != m["account"]:
        log.warning("The live account (%s) is not the backup's account (%s)", snap["manifest"]["account"], m["account"])
    return snap


def load(ref: str, args, like: dict | None = None) -> dict:
    if ref == LIVE:
        return live_snapshot(args, like)
    snap = core.load_backup(core.resolve(ref, args.backup_dir, args.account))
    log.info("Loaded %s", snap["manifest"]["path"])
    return snap


def _warn(*snaps: dict) -> None:
    for s in snaps:
        for w in s["manifest"].get("warnings") or []:
            log.warning("%s", w)


def cmd_backup(args) -> int:
    snap = live_snapshot(args)
    _warn(snap)
    root = core.write_backup(snap, args.backup_dir)
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    if args.json:
        print(json.dumps(manifest, indent=2))
    else:
        c = manifest["counts"]
        print(f"{root}\n  {c['connection']} connections, {c['lag']} LAGs, {c['vif']} VIFs, "
              f"{c['dx-gateway']} Direct Connect gateways, routes for {c['routes']} VIFs")
    log.info("Wrote backup %s", root)
    return EXIT_OK


def report_path(old: dict, new: dict, reports_dir: str) -> Path:
    def tag(s):
        return Path(s["manifest"]["path"]).name if s["manifest"].get("path") else LIVE
    day = (new["manifest"].get("generated") or "")[:10] or "undated"
    acct = new["manifest"].get("account") or "account"
    return Path(reports_dir) / day / acct / f"dx-backup_diff_{tag(old)}_{tag(new)}.html"


def cmd_diff(args) -> int:
    old = load(args.old, args)
    new = load(args.new, args, like=old)
    _warn(old, new)
    changes = db_diff.diff(old, new, state=args.state)
    if args.json:
        print(json.dumps({"old": old["manifest"], "new": new["manifest"], "summary": db_diff.summary(changes),
                          "changes": changes}, indent=2, default=str))
    else:
        sys.stdout.write(db_diff.render_text(changes, old["manifest"], new["manifest"]))
    if not args.no_report:
        out = Path(args.output) if args.output else report_path(old, new, args.reports_dir)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(render_html(changes, old, new, title=args.title, theme=args.theme, state=args.state),
                       encoding="utf-8")
        log.info("Wrote HTML report %s", out)
    return EXIT_CHANGES if changes else EXIT_OK


def cmd_restore_plan(args) -> int:
    if args.backup == LIVE:
        raise core.ValidationError("restore-plan needs a backup to restore, not live")
    target = load(args.backup, args)
    current = load(args.against, args, like=target)
    _warn(target, current)
    plan = db_restore.plan(target, current)
    if args.output:
        Path(args.output).write_text(plan.text, encoding="utf-8")
        log.info("Wrote restore plan %s (review it before running)", args.output)
    else:
        sys.stdout.write(plan.text)
    return EXIT_OK if plan.empty() else EXIT_CHANGES


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.quiet:
        logging.getLogger().setLevel(logging.WARNING)
    try:
        return {"backup": cmd_backup, "diff": cmd_diff, "restore-plan": cmd_restore_plan}[args.command](args)
    except (core.ValidationError, LookupError, ValueError, OSError) as e:
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
