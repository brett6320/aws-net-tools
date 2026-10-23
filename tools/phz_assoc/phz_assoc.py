#!/usr/bin/env python3
"""Generate (and optionally run) AWS CLI commands to associate / disassociate PHZs with VPCs.

Handles same-account and cross-account cases. For cross-account association the PHZ
owner must first create a VPC association authorization, the VPC owner then associates,
and the PHZ owner deletes the (now unneeded) authorization.

By default the tool queries both accounts to validate inputs and skip no-op steps.
``--offline`` generates commands purely from the arguments with no AWS calls.
Nothing is changed unless ``--execute`` / ``--apply`` is passed.
"""
from __future__ import annotations

import argparse
import json
import logging
import shlex
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from lib.aws_common import (  # noqa: E402
    AccountContext,
    AccountSessions,
    ClientError,
    VpcRef,
    add_account_args,
    add_common_args,
    configure_logging,
    log_client_error,
    normalize_zone_id,
    parse_tag_filters,
    parse_vpc_refs,
)
from lib.route53_helpers import Zone, list_authorizations, load_vpcs, select_zones  # noqa: E402

log = logging.getLogger("phz_assoc")

CREATE_AUTH = "create-vpc-association-authorization"
ASSOCIATE = "associate-vpc-with-hosted-zone"
DELETE_AUTH = "delete-vpc-association-authorization"
DISASSOCIATE = "disassociate-vpc-from-hosted-zone"

# Order steps run in: all authorizations, then (dis)associations, then authorization cleanup.
PHASE = {CREATE_AUTH: 1, ASSOCIATE: 2, DISASSOCIATE: 2, DELETE_AUTH: 3}


@dataclass
class ZoneState:
    """Observed state of a PHZ (None fields = unknown / offline)."""

    zone_id: str
    zone_name: str = ""
    associated: set[tuple[str, str]] | None = None  # (region, vpc_id)
    authorized: set[tuple[str, str]] | None = None


@dataclass
class Step:
    action: str
    side: str  # "phz" or "vpc"
    account: str
    zone_id: str
    zone_name: str
    vpc_id: str
    vpc_region: str
    note: str = ""
    skipped: str = ""
    cli: str = ""
    profile: str | None = None
    params: dict[str, Any] = field(default_factory=dict)
    tolerate_failure: bool = False  # e.g. offline cleanup of an authorization that may not exist

    @property
    def phase(self) -> int:
        return PHASE[self.action]


def build_plan(
    action: str,
    zones: Sequence[ZoneState],
    vpcs: Sequence[VpcRef],
    phz_account: str,
    keep_authorization: bool = False,
    disassociate_as: str = "vpc",
    cleanup_authorization: bool = False,
    comment: str | None = None,
) -> list[Step]:
    """Pure planning function: (zones x vpcs) -> ordered steps. Skipped steps are kept with a reason."""
    steps: list[Step] = []
    for z in zones:
        remaining = set(z.associated) if z.associated is not None else None
        for v in vpcs:
            if not v.account or not v.region:
                raise ValueError(f"VPC {v.vpc_id} is missing account/region")
            key = (v.region, v.vpc_id)
            cross = v.account != phz_account
            base = dict(zone_id=z.zone_id, zone_name=z.zone_name, vpc_id=v.vpc_id, vpc_region=v.region)

            def add(act: str, side: str, note: str = "", skipped: str = "", tolerate: bool = False) -> None:
                acct = phz_account if side == "phz" else v.account
                params: dict[str, Any] = {"HostedZoneId": z.zone_id, "VPC": {"VPCRegion": v.region, "VPCId": v.vpc_id}}
                if comment and act in (ASSOCIATE, DISASSOCIATE):
                    params["Comment"] = comment
                steps.append(
                    Step(action=act, side=side, account=acct, note=note, skipped=skipped, params=params, tolerate_failure=tolerate, **base)
                )

            if action == "associate":
                if z.associated is not None and key in z.associated:
                    add(ASSOCIATE, "vpc", skipped="already associated")
                    if cross and z.authorized and key in z.authorized and not keep_authorization:
                        add(DELETE_AUTH, "phz", note="stale authorization from a previous association")
                    continue
                if cross:
                    if z.authorized is not None and key in z.authorized:
                        add(CREATE_AUTH, "phz", skipped="authorization already exists")
                    else:
                        add(CREATE_AUTH, "phz", note=f"allow account {v.account} to associate its VPC")
                add(ASSOCIATE, "vpc", note="cross-account" if cross else "same account")
                if cross and not keep_authorization:
                    add(DELETE_AUTH, "phz", note="authorization no longer needed once associated")
            else:
                if z.associated is not None and key not in z.associated:
                    add(DISASSOCIATE, disassociate_as, skipped="not associated")
                elif remaining is not None and remaining == {key}:
                    add(DISASSOCIATE, disassociate_as, skipped="last VPC on the PHZ; Route 53 does not allow removing it")
                else:
                    if remaining is not None:
                        remaining.discard(key)
                    add(DISASSOCIATE, disassociate_as, note="cross-account" if cross else "same account")
                if cross and z.authorized is not None and key in z.authorized:
                    add(DELETE_AUTH, "phz", note="remove authorization so the VPC cannot re-associate")
                elif cross and z.authorized is None and cleanup_authorization:
                    add(DELETE_AUTH, "phz", note="remove authorization if one exists", tolerate=True)
    steps.sort(key=lambda s: s.phase)  # stable: preserves zone/vpc order within a phase
    return steps


def cli_for(step: Step, profile: str | None) -> str:
    vpc = f"VPCRegion={step.vpc_region},VPCId={step.vpc_id}"
    parts = ["aws", "route53", step.action, "--hosted-zone-id", step.zone_id, "--vpc", vpc]
    if "Comment" in step.params:
        parts += ["--comment", step.params["Comment"]]
    if profile:
        parts += ["--profile", profile]
    cmd = " ".join(shlex.quote(p) for p in parts)
    if step.tolerate_failure:
        cmd += " || echo 'No authorization to delete (ok)'"
    return cmd


def render_script(steps: Sequence[Step], action: str, phz_account: str) -> str:
    lines = [
        "#!/usr/bin/env bash",
        f"# PHZ {action} plan — generated by phz_assoc.py",
        f"# PHZ owner account: {phz_account}",
        "# Review before running. Commands are grouped by the account that must run them.",
        "set -euo pipefail",
    ]
    active = [s for s in steps if not s.skipped]
    current: tuple[int, str, str] | None = None
    n = 0
    for s in steps:
        header = (s.phase, s.side, s.account)
        if not s.skipped and header != current:
            current = header
            n += 1
            who = "PHZ owner" if s.side == "phz" else "VPC owner"
            prof = f" (profile: {s.profile})" if s.profile else ""
            lines += ["", f"# ===== Step {n}: run as {who} account {s.account}{prof} ====="]
        target = f"{s.zone_id} {s.zone_name or ''} <-> {s.vpc_id} ({s.vpc_region})".replace("  ", " ")
        if s.skipped:
            lines.append(f"# SKIP {s.action} {target}: {s.skipped}")
            continue
        lines.append(f"# {target}{' — ' + s.note if s.note else ''}")
        lines.append(s.cli)
    if not active:
        lines += ["", "# Nothing to do."]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- online state


def gather_state(
    ctx: AccountContext, args: argparse.Namespace, vpcs: list[VpcRef]
) -> tuple[str, list[ZoneState], list[VpcRef], AccountSessions, AccountSessions]:
    phz_side = ctx.phz_sessions()
    vpc_side = ctx.vpc_sessions()
    phz_account = ctx.phz_account or phz_side.caller_account
    route53 = phz_side.client("route53", phz_account)

    zones: list[Zone] = select_zones(
        route53, args.zone, args.zone_name, parse_tag_filters(args.zone_tag), parse_tag_filters(args.exclude_zone_tag)
    )
    if not zones:
        raise LookupError("No hosted zones matched the selectors")
    for z in zones:
        if not z.private:
            raise ValueError(f"{z.zone_id} ({z.name}) is a public hosted zone; VPC association applies to PHZs only")
        if not z.vpcs:  # zones selected by name/tag come from list_hosted_zones, which omits VPCs
            load_vpcs(route53, z)

    resolved: list[VpcRef] = []
    for ref in vpcs:
        acct = ref.account or vpc_side.caller_account
        ec2 = vpc_side.client("ec2", acct, ref.region)
        found = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ref.vpc_id]}]).get("Vpcs", [])
        if not found:
            raise LookupError(f"VPC {ref.vpc_id} not found in account {acct} region {ref.region}")
        owner = found[0]["OwnerId"]
        if owner != acct:
            raise ValueError(
                f"VPC {ref.vpc_id} is owned by {owner} (shared to {acct}); PHZ association must be done by the VPC owner"
            )
        log.debug("Validated %s owner=%s", ref.vpc_id, owner)
        resolved.append(VpcRef(ref.vpc_id, ref.region, acct))

    any_cross = any(r.account != phz_account for r in resolved)
    states = []
    for z in zones:
        authorized = set(list_authorizations(route53, z.zone_id)) if any_cross else set()
        states.append(ZoneState(z.zone_id, z.name, set(z.vpcs), authorized))
        log.info("Zone %s (%s): %d VPC(s) associated, %d authorization(s)", z.zone_id, z.name, len(z.vpcs), len(authorized))
    return phz_account, states, resolved, phz_side, vpc_side


def execute_steps(steps: Sequence[Step], phz_side: AccountSessions, vpc_side: AccountSessions, execute: bool) -> None:
    for s in steps:
        if s.skipped:
            log.info("Skipping %s %s<->%s: %s", s.action, s.zone_id, s.vpc_id, s.skipped)
            continue
        desc = f"{s.action} zone={s.zone_id} vpc={s.vpc_id}/{s.vpc_region} as {s.side} account {s.account}"
        if not execute:
            log.info("[DRY-RUN] Would run %s", desc)
            continue
        log.info("[EXECUTE] %s", desc)
        sessions = phz_side if s.side == "phz" else vpc_side
        route53 = sessions.client("route53", s.account)
        method = getattr(route53, s.action.replace("-", "_"))
        resp = method(**s.params)
        change = resp.get("ChangeInfo", {}).get("Id")
        if change:
            log.info("Waiting for change %s to reach INSYNC", change)
            route53.get_waiter("resource_record_sets_changed").wait(Id=change)


# --------------------------------------------------------------------------- CLI


def build_parser() -> argparse.ArgumentParser:
    parent = argparse.ArgumentParser(add_help=False)
    add_common_args(parent)
    add_account_args(parent)
    parent.add_argument("--zone", action="append", default=[], metavar="ID|ARN", help="Hosted zone ID/ARN (repeatable / comma-separated)")
    parent.add_argument("--zone-name", action="append", default=[], metavar="GLOB", help="Select PHZs by name glob (online only)")
    parent.add_argument("--zone-tag", action="append", metavar="KEY[=V1,V2]", help="Select PHZs by tag (online only)")
    parent.add_argument("--exclude-zone-tag", action="append", metavar="KEY[=V1,V2]", help="Exclude PHZs by tag (online only)")
    parent.add_argument("--vpc", action="append", required=True, metavar="ID|ARN", help="VPC ID or ARN (repeatable / comma-separated)")
    parent.add_argument("--vpc-region", help="Region for VPC IDs given without an ARN (default: --region)")
    parent.add_argument("--offline", action="store_true", help="Generate commands without any AWS API calls")
    parent.add_argument("--comment", help="Comment passed to associate/disassociate")
    parent.add_argument("--cli-vpc-profile", help="Profile to put in generated VPC-owner commands")
    parent.add_argument("--cli-phz-profile", help="Profile to put in generated PHZ-owner commands")
    parent.add_argument("--format", choices=("sh", "json"), default="sh", help="Output: shell script or JSON plan")
    parent.add_argument("--out", metavar="FILE", help="Write output to FILE instead of stdout")
    parent.add_argument("--execute", action="store_true", help="Run the plan via boto3 (default: generate only)")
    parent.add_argument("--apply", action="store_true", help="Alias for --execute")

    p = argparse.ArgumentParser(description="Generate CLI commands to associate/disassociate PHZs and VPCs (incl. cross-account).")
    sub = p.add_subparsers(dest="action", required=True)
    a = sub.add_parser("associate", parents=[parent], help="Associate VPC(s) with PHZ(s)")
    a.add_argument("--keep-authorization", action="store_true", help="Don't delete the cross-account authorization afterwards")
    d = sub.add_parser("disassociate", parents=[parent], help="Disassociate VPC(s) from PHZ(s)")
    d.add_argument("--disassociate-as", choices=("vpc", "phz"), default="vpc", help="Which owner account runs the disassociation")
    d.add_argument("--cleanup-authorization", action="store_true", help="Offline: also emit delete-vpc-association-authorization for cross-account VPCs")
    return p


def cli_profiles(args: argparse.Namespace) -> tuple[str | None, str | None]:
    """Profiles to embed in generated commands. A shared --profile is only reused when no role is assumed."""
    shared = args.profile if not args.role_name else None
    return (args.cli_vpc_profile or args.vpc_profile or shared, args.cli_phz_profile or args.phz_profile or shared)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.verbose, args.quiet)
    execute = args.execute or args.apply
    action = args.action
    try:
        ctx = AccountContext.from_args(args)
        vpcs = parse_vpc_refs(args.vpc, args.vpc_region or args.region, ctx.vpc_account)
        args.zone = [normalize_zone_id(z) for raw in args.zone for z in raw.split(",") if z.strip()]
        if args.offline:
            if execute:
                raise ValueError("--execute cannot be combined with --offline")
            if args.zone_name or args.zone_tag or args.exclude_zone_tag:
                raise ValueError("--zone-name/--zone-tag need AWS access; use --zone IDs with --offline")
            if not args.zone:
                raise ValueError("Specify at least one --zone")
            if not ctx.phz_account:
                raise ValueError("--offline needs the PHZ account: pass --account or --phz-account")
            missing = [v.vpc_id for v in vpcs if not v.account]
            if missing:
                raise ValueError(f"--offline needs the VPC account for {', '.join(missing)}: pass --account/--vpc-account or VPC ARNs")
            phz_account = ctx.phz_account
            zones = [ZoneState(z) for z in args.zone]
            phz_side = vpc_side = None
        else:
            phz_account, zones, vpcs, phz_side, vpc_side = gather_state(ctx, args, vpcs)

        steps = build_plan(
            action,
            zones,
            vpcs,
            phz_account,
            keep_authorization=getattr(args, "keep_authorization", False),
            disassociate_as=getattr(args, "disassociate_as", "vpc"),
            cleanup_authorization=getattr(args, "cleanup_authorization", False),
            comment=args.comment,
        )
    except (ValueError, LookupError, PermissionError) as e:
        log.error("%s", e)
        return 2
    except ClientError as e:
        log_client_error(e)
        return 1

    vpc_prof, phz_prof = cli_profiles(args)
    vpc_accounts = {v.account for v in vpcs}
    if vpc_prof and not ctx.vpc_account and len(vpc_accounts) > 1:
        log.warning("VPCs span accounts %s; omitting VPC-side --profile from generated commands", ", ".join(sorted(vpc_accounts)))
        vpc_prof = None
    for s in steps:
        prof = phz_prof if s.side == "phz" else vpc_prof
        # A VPC-side profile only applies to the account it was given for.
        if s.side == "vpc" and ctx.vpc_account and s.account != ctx.vpc_account:
            prof = None
        s.profile = prof
        s.cli = cli_for(s, prof)

    if args.format == "json":
        output = json.dumps([{**asdict(s), "phase": s.phase} for s in steps], indent=2) + "\n"
    else:
        output = render_script(steps, action, phz_account)
    if args.out:
        Path(args.out).write_text(output)
        log.info("Wrote %s", args.out)
    else:
        sys.stdout.write(output)

    active = [s for s in steps if not s.skipped]
    log.info("%d step(s) planned, %d skipped", len(active), len(steps) - len(active))
    if args.offline:
        return 0
    if not execute:
        log.info("Generate-only (dry-run). Pass --execute or --apply to run the plan via boto3.")
    try:
        execute_steps(steps, phz_side, vpc_side, execute)
    except ClientError as e:
        log_client_error(e, "plan aborted; later steps not run")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
