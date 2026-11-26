#!/usr/bin/env python3
"""Copy Name tags from the owner of shared VPCs and subnets to a participant account (dry run by default).

Reads the VPCs and subnets both ``--owner-profile`` and ``--participant-profile`` can see in each
Region. Every one they share must be owned (EC2 ``OwnerId``) by the owner profile's account; if
one is owned by any other account, the run stops with an error and nothing is changed.

The owner's ``Name`` tag is copied only where the participant has no ``Name`` tag or an empty one.
Tags in the owner account are never changed, and a ``Name`` with a value is never changed. With
``--apply``, each resource is confirmed one at a time at the terminal (``--force`` skips the
confirmations), and every rule is re-checked against live data right before its write.

Logs and prompts go to stderr; the table / CSV / JSON goes to stdout.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import logging
import os
import sys
import unicodedata
from dataclasses import dataclass
from typing import Any, Callable, Sequence

import truststore

# Use the OS certificate store. Injecting after urllib3 has captured ssl.SSLContext recurses
# forever, which only happens when something imported boto3 first (e.g. the tests).
if "urllib3" not in sys.modules:
    truststore.inject_into_ssl()

import boto3  # noqa: E402
from botocore.exceptions import BotoCoreError, ClientError  # noqa: E402
from dotenv import load_dotenv  # noqa: E402

import nts_core as core  # noqa: E402

load_dotenv()

log = logging.getLogger("name_tag_sync")

TABLE_COLUMNS = ("region", "type", "resource_id", "vpc_id", "owner_name", "participant_name", "action")
FULL_COLUMNS = ("region", "type", "resource_id", "vpc_id", "cidr", "owner", "target", "owner_name",
                "participant_name", "action", "permission", "result")
ERROR_EXIT = 1
USAGE_EXIT = 2
MISMATCH_EXIT = 3


def configure_logging(verbose: bool = False, quiet: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.WARNING if quiet else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
                        datefmt="%Y-%m-%dT%H:%M:%S", stream=sys.stderr)
    logging.getLogger().setLevel(level)
    if not verbose:
        for noisy in ("botocore", "boto3", "urllib3"):
            logging.getLogger(noisy).setLevel(logging.WARNING)


# --------------------------------------------------------------------------- styling (table and prompts only)

RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
GREEN, RED, YELLOW, CYAN = "\033[32m", "\033[31m", "\033[33m", "\033[36m"
# Every emoji here is a single wide (2-column) code point, so the table stays aligned.
OK, MISSING, DIFFERS, NEUTRAL, DENIED, INTERRUPTED = "✅", "❌", "🔶", "➖", "⛔", "⚡"

ACTION_STYLE = {  # action -> (emoji, color)
    core.SET: (MISSING, RED),  # participant Name missing or empty
    core.SKIP_SAME: (OK, GREEN),
    core.SKIP_POPULATED: (DIFFERS, YELLOW),
    core.SKIP_WHITESPACE: (DIFFERS, YELLOW),
    core.SKIP_NO_SOURCE: (NEUTRAL, DIM),
}


def outcome_style(text: str) -> tuple[str, str]:
    """(emoji, color) for a permission or result value."""
    if text in ("tagged", "allowed"):
        return OK, GREEN
    if text.startswith(("denied", "not asked (denied)", "not asked (permission")):
        return DENIED, RED
    if text.startswith(("error", "stopped")):
        return MISSING, RED
    if text.startswith("interrupted"):
        return INTERRUPTED, YELLOW
    if text.startswith("skipped"):
        return DIFFERS, YELLOW
    return NEUTRAL, DIM  # declined, not asked


@dataclass
class Style:
    color: bool = False
    emoji: bool = False

    def paint(self, text: str, code: str) -> str:
        return f"{code}{text}{RESET}" if self.color and code and text else text

    def mark(self, text: str, emoji: str) -> str:
        return f"{emoji} {text}" if self.emoji and text else text


PLAIN = Style()


def use_color(mode: str, stream) -> bool:
    """--color always/never, or auto: only on a terminal, and never when NO_COLOR is set."""
    if mode == "never":
        return False
    if mode == "always":
        return True
    return not os.getenv("NO_COLOR") and bool(getattr(stream, "isatty", lambda: False)())


def width(text: str) -> int:
    """Terminal columns: wide characters (the emojis) take two."""
    return sum(2 if unicodedata.east_asian_width(c) in ("W", "F") else 1 for c in text)


def _cell(column: str, v: Any, style: Style = PLAIN) -> tuple[str, str]:
    """(text, color) of one table cell."""
    if column in ("owner_name", "participant_name"):
        return core.show(v), (RED if column == "participant_name" and core.is_unset(v) else "")
    text = "" if v is None else str(v)
    if column == "action" and text in ACTION_STYLE:
        emoji, code = ACTION_STYLE[text]
        return style.mark(text, emoji), code
    if column in ("permission", "result") and text:
        emoji, code = outcome_style(text)
        return style.mark(text, emoji), code
    return text, ""


def render(items: Sequence[core.Item], fmt: str, stream=None, style: Style = PLAIN) -> None:
    stream = stream or sys.stdout
    rows = [i.row() for i in items]
    if fmt == "json":
        json.dump(rows, stream, indent=2, default=str)
        stream.write("\n")
        return
    if fmt == "csv":
        w = csv.writer(stream)
        w.writerow(FULL_COLUMNS)
        for r in rows:
            w.writerow(["" if r.get(c) is None else r.get(c) for c in FULL_COLUMNS])
        return
    columns = TABLE_COLUMNS + tuple(c for c in ("permission", "result") if any(r.get(c) for r in rows))
    table = [[_cell(c, r.get(c), style) for c in columns] for r in rows]
    widths = [max([len(c)] + [width(row[i][0]) for row in table]) for i, c in enumerate(columns)]
    buf = io.StringIO()
    buf.write(style.paint("  ".join(c.upper().ljust(widths[i]) for i, c in enumerate(columns)).rstrip(), BOLD) + "\n")
    buf.write("  ".join("-" * w for w in widths) + "\n")
    for row in table:
        cells = [style.paint(text, code) + " " * (widths[i] - width(text)) for i, (text, code) in enumerate(row)]
        buf.write("  ".join(cells).rstrip() + "\n")
    stream.write(buf.getvalue())
    if not rows:
        stream.write("(no VPCs or subnets shared between the two accounts)\n")


def tty_ask(question: str) -> str:
    """Prompt on stderr and read one answer; EOF and Ctrl-C mean quit."""
    sys.stderr.write(question)
    sys.stderr.flush()
    try:
        return input().strip().lower()
    except (EOFError, KeyboardInterrupt):
        sys.stderr.write("\n")
        return "q"


def prompt_text(item: core.Item, participant: core.Account, style: Style = PLAIN) -> str:
    p = style.paint
    new = p(core.show(item.source_name), GREEN + BOLD)
    return (f"\n{p(f'{item.region} {item.kind} {item.resource_id}', BOLD)}"
            f"{'' if item.kind == 'vpc' else f' (in {item.vpc_id})'} {item.cidr}\n"
            f"  owner {item.owner} Name: {p(core.show(item.source_name), GREEN)}\n"
            f"  participant {participant.account} "
            f"(profile {participant.profile}) Name: {style.mark(p(core.show(item.target_name), RED), MISSING)}\n"
            f"{p('Set Name', CYAN)} in {participant.account} to {new}? [y/N/q] ")


def skip_reason(item: core.Item, force: bool) -> str:
    """Why a planned item isn't asked about at all ("" when it is).

    Interactive: only --check-permissions denials are skipped; any other check error is shown in the
    table and the prompt, so it can be declined. --force: anything the check didn't call "allowed".
    """
    if item.permission.startswith("denied"):
        return "not asked (denied)"
    if force and item.permission and item.permission != "allowed":
        return f"not asked (permission {item.permission})"
    return ""


def apply_plan(items: list[core.Item], owner: core.Account, participant: core.Account,
               ask: Callable[[str], str] = tty_ask, style: Style = PLAIN, force: bool = False) -> None:
    """Confirm (unless ``force``) and write each planned item. Raises OwnerMismatch (the run stops).

    Ctrl-C at any point stops like quit; the item being written is marked interrupted.
    """
    todo = [i for i in items if i.action == core.SET]
    for item in todo:
        item.result = skip_reason(item, force)
    todo = [i for i in todo if not i.result]
    if force:
        log.warning("--force: tagging %d resource(s) in %s without asking for each one", len(todo),
                    participant.account)
    for n, item in enumerate(todo):
        try:
            if not force:
                answer = ask(prompt_text(item, participant, style))
                if answer in ("q", "quit"):
                    for rest in todo[n:]:
                        rest.result = "not asked (quit)"
                    log.info("Quit; %d resource(s) not asked", len(todo) - n)
                    return
                if answer not in ("y", "yes"):
                    item.result = "declined"
                    continue
            else:
                log.warning("--force: %s %s %s in %s: Name=%s", item.region, item.kind, item.resource_id,
                            participant.account, core.show(item.source_name))
            try:
                core.apply_item(item, owner, participant)
            except core.OwnerMismatch:
                item.result = "stopped: owner mismatch"
                for rest in todo[n + 1:]:
                    rest.result = "not asked (stopped)"
                raise
            except core.SafetyError as e:
                item.result = f"skipped: {e}"
                log.warning("%s", e)
                continue
            except (ClientError, BotoCoreError) as e:
                item.result = f"error: {core._error(e)}"
                log.error("%s: %s", item.resource_id, core._error(e))
                continue
            item.result = "tagged"
            log.info("Tagged %s in %s: Name=%s", item.resource_id, participant.account, core.show(item.source_name))
        except KeyboardInterrupt:
            if not item.result:
                item.result = "interrupted (check its Name tag)"
                log.warning("Interrupted while tagging %s; it may or may not be tagged", item.resource_id)
            for rest in todo[n + 1:]:
                rest.result = "not asked (quit)"
            return


def build_parser() -> argparse.ArgumentParser:
    env = os.getenv
    p = argparse.ArgumentParser(
        description="Copy Name tags from the owner of shared VPCs and subnets to a participant account "
                    "(dry run unless --apply).")
    p.add_argument("--owner-profile", default=env("NTS_OWNER_PROFILE"),
                   help="Profile for the account that owns the shared VPCs (env NTS_OWNER_PROFILE). Never written to")
    p.add_argument("--participant-profile", default=env("NTS_PARTICIPANT_PROFILE"),
                   help="Profile for the participant account whose missing Name tags are filled in "
                        "(env NTS_PARTICIPANT_PROFILE)")
    p.add_argument("--regions", action="append",
                   help="Regions to read; repeat or comma-separate (default: the participant profile's Region)")
    p.add_argument("--vpc-ids", action="append", metavar="VPC_ID",
                   help="Only these VPCs and their subnets; repeat or comma-separate")
    p.add_argument("--check-permissions", action="store_true",
                   help="For each planned tag, call CreateTags with DryRun=True to see whether it would be allowed "
                        "(writes nothing)")
    p.add_argument("--apply", action="store_true",
                   help="Write the planned Name tags, confirming each resource at the terminal (default: dry run)")
    p.add_argument("--force", action="store_true",
                   help="With --apply: write every planned tag without asking for each resource (no terminal "
                        "needed). Every other safety rule and live re-check still applies")
    p.add_argument("--output", "-o", choices=("table", "json", "csv"), default="table",
                   help="Output format (default: table)")
    p.add_argument("--json", dest="output", action="store_const", const="json", help="Shortcut for --output json")
    p.add_argument("--color", choices=("auto", "always", "never"), default="auto",
                   help="Color the table and prompts (default auto: only on a terminal, and not when NO_COLOR is set)")
    p.add_argument("--no-emoji", dest="emoji", action="store_false",
                   help="No status emojis in the table and prompts (CSV and JSON never have them)")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    p.add_argument("-q", "--quiet", action="store_true", help="Warnings/errors only (prompts still show)")
    return p


def main(argv: list[str] | None = None, session_for=None, ask: Callable[[str], str] | None = None,
         interactive: Callable[[], bool] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.verbose, args.quiet)
    if not args.owner_profile or not args.participant_profile:
        log.error("Give --owner-profile and --participant-profile")
        return USAGE_EXIT
    if args.owner_profile == args.participant_profile:
        log.error("--owner-profile and --participant-profile are the same profile")
        return USAGE_EXIT
    if args.force and not args.apply:
        log.error("--force only skips the confirmations of --apply; pass --apply --force to write")
        return USAGE_EXIT
    interactive = interactive or (lambda: sys.stdin.isatty() and sys.stderr.isatty())
    if args.apply and not args.force and not interactive():
        log.error("--apply confirms each resource at the terminal; stdin and stderr must be a terminal")
        return USAGE_EXIT
    try:
        regions = core.check_regions(core.split_csv(args.regions))
        vpc_ids = core.check_vpc_ids(core.split_csv(args.vpc_ids)) or None
    except ValueError as e:
        log.error("%s", e)
        return USAGE_EXIT
    session_for = session_for or (lambda profile: boto3.Session(profile_name=profile))

    try:
        o_session, p_session = session_for(args.owner_profile), session_for(args.participant_profile)
        if not regions:
            if not (default := getattr(p_session, "region_name", None)):
                log.error("The participant profile has no Region; pass --regions")
                return USAGE_EXIT
            regions = [default]
        owner = core.identify("owner", args.owner_profile, o_session)
        participant = core.identify("participant", args.participant_profile, p_session)
    except (ClientError, BotoCoreError, ValueError) as e:
        log.error("Can't sign in: %s", core._error(e))
        return ERROR_EXIT
    log.info("Owner %s (profile %s) -> participant %s (profile %s); Regions %s", owner.account, owner.profile,
             participant.account, participant.profile, ", ".join(regions))

    try:
        items, errors = core.build_plan(owner, participant, regions, vpc_ids)
    except core.OwnerMismatch as e:
        log.error("Owner mismatch, nothing changed: %s", e)
        return MISMATCH_EXIT

    planned = [i for i in items if i.action == core.SET]
    if args.check_permissions:
        for item in planned:
            item.permission = core.check_permission(item, owner, participant)
    stream_now = args.output == "table"
    table_style = Style(use_color(args.color, sys.stdout), args.emoji)
    prompt_style = Style(use_color(args.color, sys.stderr), args.emoji)
    if stream_now:
        render(items, args.output, style=table_style)

    status = 0
    if args.apply and planned:
        try:
            apply_plan(items, owner, participant, ask or tty_ask, prompt_style, force=args.force)
        except core.OwnerMismatch as e:
            log.error("Owner mismatch, stopped; nothing more changed: %s", e)
            status = MISMATCH_EXIT
        if stream_now:
            sys.stdout.write("\n")
            render(planned, args.output, style=table_style)
    if not stream_now:
        render(items, args.output, style=table_style)

    if args.apply:
        done = sum(i.result == "tagged" for i in planned)
        log.info("Tagged %d of %d planned resource(s) in %s", done, len(planned), participant.account)
    else:
        log.info("Dry run: %d resource(s) would be tagged in %s; pass --apply to confirm each one",
                 len(planned), participant.account)
    if args.check_permissions and (denied := [i for i in planned if i.permission != "allowed"]):
        log.warning("%d planned tag(s) would not be allowed (see the permission column)", len(denied))
        status = status or ERROR_EXIT
    if args.apply and any(i.result.startswith(("error", "skipped", "interrupted")) for i in planned):
        status = status or ERROR_EXIT
    if errors:
        log.warning("Incomplete: %d Region(s) couldn't be read", len(errors))
        status = status or ERROR_EXIT
    return status


if __name__ == "__main__":
    sys.exit(main())
