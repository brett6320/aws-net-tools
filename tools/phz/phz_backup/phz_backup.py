#!/usr/bin/env python3
"""Back up Route 53 private hosted zones and generate AWS CLI commands to restore them.

  backup         Save each selected PHZ (default: every PHZ in the account) as JSON: name,
                 comment, tags, every record set, the VPCs it is associated with (and their
                 owner accounts, where known) and pending cross-account authorizations.
  restore-plan   Turn a backup into a bash script of `aws route53` commands that recreates
                 the zone (or, with --into, refills an existing one). Nothing is run.
  report         Write an HTML report per zone of a backup: tags, VPC associations, record sets
                 and the zone's restore script. `backup` writes them too unless --no-html.

The tool is read-only: it never changes AWS resources.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import os
import re
import shlex
import sys
from pathlib import Path
from typing import Any, Iterable, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "common"))
import secure_io  # noqa: E402

from lib.aws_common import (  # noqa: E402
    AccountContext,
    ClientError,
    add_account_args,
    add_common_args,
    configure_logging,
    log_client_error,
    normalize_zone_id,
    parse_tag_filters,
    render,
    split_csv,
    validate_account,
    zone_name,
)
from lib.aws_profiles import priv_profile, priv_suffix  # noqa: E402
from lib.route53_helpers import Zone, get_zone, list_authorizations, load_tags, select_zones  # noqa: E402
from lib.vpc_owner_cache import VpcOwnerCache, default_path  # noqa: E402
from pb_html import render_html  # noqa: E402

log = logging.getLogger("phz_backup")

FORMAT = 1
DEFAULT_ROOT = "backups/phz"
STAMP = "%Y%m%dT%H%M%SZ"
STAMP_RE = re.compile(r"^\d{8}T\d{6}Z$")
MANIFEST = "manifest.json"

# ChangeResourceRecordSets allows 1000 records and 32,000 characters of values per request;
# stay well inside both.
BATCH_CHANGES = 100
BATCH_CHARS = 20000
TAGS_PER_CALL = 10


# --------------------------------------------------------------------------- backup


def iter_record_sets(route53, zone_id: str) -> Iterable[dict[str, Any]]:
    for page in route53.get_paginator("list_resource_record_sets").paginate(HostedZoneId=zone_id):
        yield from page["ResourceRecordSets"]


def resolve_owners(ec2_for, pairs: set[tuple[str, str]], cache: VpcOwnerCache | None) -> dict[str, str]:
    """VPC -> owner account: the local owner map (filled by ou_vpcs / phz_review) first, then
    DescribeVpcs in the PHZ account, which sees its own VPCs and VPCs shared with it."""
    owners: dict[str, str] = {}
    if cache is not None:
        for region, vpc in pairs:
            acct = cache.get(region, vpc)
            if acct:
                owners[vpc] = acct
    by_region: dict[str, list[str]] = {}
    for region, vpc in sorted(pairs):
        if vpc not in owners:
            by_region.setdefault(region, []).append(vpc)
    for region, ids in by_region.items():
        try:
            for page in ec2_for(region).get_paginator("describe_vpcs").paginate(Filters=[{"Name": "vpc-id", "Values": ids}]):
                for v in page["Vpcs"]:
                    owners[v["VpcId"]] = v["OwnerId"]
                    if cache is not None:
                        cache.put(region, v["VpcId"], v["OwnerId"], "phz-account")
        except ClientError as e:
            log.warning("Could not look up VPC owners in %s: %s", region, e.response.get("Error", {}).get("Message"))
    return owners


def zone_backup(route53, z: Zone, account: str, owners: dict[str, str], authorizations: list[tuple[str, str]], taken_at: str) -> dict[str, Any]:
    records = list(iter_record_sets(route53, z.zone_id))
    return {
        "format": FORMAT,
        "taken_at": taken_at,
        "account": account,
        "zone": {"id": z.zone_id, "name": z.name, "comment": z.comment, "private": z.private},
        "tags": dict(sorted(z.tags.items())),
        "vpcs": [{"region": r, "vpc_id": v, "owner": owners.get(v)} for r, v in z.vpcs],
        "authorizations": [{"region": r, "vpc_id": v} for r, v in authorizations],
        "records": records,
    }


def zone_filename(zone: dict[str, Any]) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", zone["name"]) or "root"
    return f"{zone['id']}_{safe}.json"


def write_json(path: Path, data: Any) -> None:
    secure_io.write_private_text(path, json.dumps(data, indent=2, default=str) + "\n")


def run_backup(args: argparse.Namespace) -> int:
    ctx = AccountContext.from_args(args)
    phz = ctx.phz_sessions()
    account = ctx.phz_account or phz.caller_account
    route53 = phz.client("route53", account)
    zones = select_zones(
        route53, args.zone, args.zone_name, parse_tag_filters(args.zone_tag), parse_tag_filters(args.exclude_zone_tag),
        require_selector=False,
    )
    public = [z for z in zones if not z.private]
    if public:
        raise ValueError(f"{', '.join(f'{z.zone_id} ({z.name})' for z in public)}: public hosted zone(s); this tool backs up PHZs only")
    if not zones:
        raise LookupError("No private hosted zones matched")

    full = [get_zone(route53, z.zone_id) for z in zones]  # list_hosted_zones omits VPCs
    load_tags(route53, full)
    cache = None if args.no_owner_cache else VpcOwnerCache(Path(args.owner_cache).expanduser() if args.owner_cache else default_path())
    owners = resolve_owners(lambda r: phz.client("ec2", account, r), {p for z in full for p in z.vpcs}, cache)
    if cache is not None:
        cache.save()

    now = dt.datetime.now(dt.timezone.utc)
    taken_at = now.isoformat(timespec="seconds")
    out_dir = Path(args.backup_dir).expanduser() / account / now.strftime(STAMP)
    secure_io.ensure_private_dir(out_dir.parent, owned_root=out_dir.parent)
    out_dir.mkdir(mode=0o700)                       # still raises FileExistsError if it exists
    secure_io.ensure_private_dir(out_dir, owned_root=out_dir)
    summary = []
    for z in full:
        auths = list_authorizations(route53, z.zone_id) if not args.no_authorizations else []
        data = zone_backup(route53, z, account, owners, auths, taken_at)
        name = zone_filename(data["zone"])
        write_json(out_dir / name, data)
        unknown = sum(1 for v in data["vpcs"] if not v["owner"])
        summary.append({
            "zone_id": z.zone_id, "name": z.name, "records": len(data["records"]), "vpcs": len(z.vpcs),
            "unknown_owners": unknown, "tags": len(z.tags), "authorizations": len(auths), "file": name,
        })
        if unknown:
            log.warning("%s (%s): %d VPC owner(s) unknown; restore-plan will ask for a profile for each", z.zone_id, z.name, unknown)
    write_json(out_dir / MANIFEST, {"format": FORMAT, "taken_at": taken_at, "account": account, "zones": summary})
    reports: list[Path] = []
    if not args.no_html:
        reports = write_reports(load_zone_backups(resolve_backup(str(out_dir), out_dir, None), []), str(out_dir), args.reports_dir, None, args)
    if args.json:
        json.dump({"backup": str(out_dir), "reports": [str(r) for r in reports], "zones": summary}, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        render(summary, ["zone_id", "name", "records", "vpcs", "unknown_owners", "tags", "authorizations"], "table")
        print(f"\nBackup: {out_dir}")
        for r in reports:
            print(f"Report: {r}")
    log.info("Backed up %d zone(s) to %s", len(summary), out_dir)
    return 0


# --------------------------------------------------------------------------- locating backups


def backup_dirs(root: Path, account: str | None) -> list[Path]:
    accounts = [root / account] if account else [p for p in root.iterdir() if p.is_dir()] if root.is_dir() else []
    dirs = [d for a in accounts if a.is_dir() for d in a.iterdir() if d.is_dir() and STAMP_RE.match(d.name)]
    return sorted(dirs, key=lambda d: d.name)


def resolve_backup(spec: str, root: Path, account: str | None) -> list[Path]:
    """Zone files for ``spec``: a backup directory, one zone file, or ``latest`` / ``previous``."""
    if spec in ("latest", "previous"):
        dirs = backup_dirs(root, account)
        owners = {d.parent.name for d in dirs}
        if len(owners) > 1:
            raise ValueError(f"Backups of several accounts in {root} ({', '.join(sorted(owners))}); pass --account")
        idx = -1 if spec == "latest" else -2
        if len(dirs) < -idx:
            raise LookupError(f"No {spec} backup in {root / account if account else root}")
        spec_path = dirs[idx]
    else:
        spec_path = Path(spec).expanduser()
    if spec_path.is_file():
        return [spec_path]
    if not spec_path.is_dir():
        raise LookupError(f"Backup {spec} not found")
    files = sorted(p for p in spec_path.glob("*.json") if p.name != MANIFEST)
    if not files:
        raise LookupError(f"No zone backups in {spec_path}")
    return files


def load_zone_backups(files: Sequence[Path], selectors: Sequence[str]) -> list[dict[str, Any]]:
    out = []
    for f in files:
        data = json.loads(f.read_text())
        if data.get("format") != FORMAT or "zone" not in data:
            raise ValueError(f"{f} is not a phz_backup zone file")
        data["_file"] = str(f)
        out.append(data)
    if not selectors:
        return out
    wanted = []
    for sel in selectors:
        match = [d for d in out if d["zone"]["id"] == sel.strip() or d["zone"]["name"] == zone_name(sel)]
        if not match:
            raise LookupError(f"Zone {sel} is not in the backup")
        wanted += [m for m in match if m not in wanted]
    return wanted


# --------------------------------------------------------------------------- restore plan


def var_name(prefix: str, ident: str) -> str:
    return prefix + "_" + re.sub(r"[^A-Za-z0-9]", "_", ident).upper()


def is_apex_default(rr: dict[str, Any], name: str) -> bool:
    """SOA and NS at the apex are created with the zone and can't be replaced from a backup."""
    return rr["Type"] in ("SOA", "NS") and zone_name(rr["Name"]) == name


def record_levels(records: Sequence[dict[str, Any]], zone_id: str) -> list[list[dict[str, Any]]]:
    """Plain records and aliases to other zones first, then aliases into this zone, one level per step of
    the alias chain. Each level goes in its own change batches, so an alias's target already exists."""
    plain = [r for r in records if "AliasTarget" not in r]
    external = [r for r in records if "AliasTarget" in r and normalize_zone_id(r["AliasTarget"]["HostedZoneId"]) != zone_id]
    internal = [r for r in records if "AliasTarget" in r and normalize_zone_id(r["AliasTarget"]["HostedZoneId"]) == zone_id]
    done = {zone_name(r["Name"]) for r in plain + external}
    levels = [plain + external]
    while internal:
        ready = [r for r in internal if zone_name(r["AliasTarget"]["DNSName"]) in done]
        if not ready:  # missing target or a cycle: keep the rest together and let Route 53 report it
            levels.append(internal)
            break
        levels.append(ready)
        done |= {zone_name(r["Name"]) for r in ready}
        internal = [r for r in internal if r not in ready]
    return [lvl for lvl in levels if lvl]


def order_records(records: Sequence[dict[str, Any]], zone_id: str) -> list[dict[str, Any]]:
    return [r for lvl in record_levels(records, zone_id) for r in lvl]


def chunk_changes(records: Sequence[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """UPSERT batches within the request limits, keeping the record order (batches run one call each, in order)."""
    batches: list[list[dict[str, Any]]] = []
    cur: list[dict[str, Any]] = []
    size = 0
    for rr in records:
        n = len(json.dumps(rr))
        if cur and (len(cur) >= BATCH_CHANGES or size + n > BATCH_CHARS):
            batches.append(cur)
            cur, size = [], 0
        cur.append({"Action": "UPSERT", "ResourceRecordSet": rr})
        size += n
    if cur:
        batches.append(cur)
    return batches


def profile_opt(var: str) -> str:
    return f'${{{var}:+--profile "${var}"}}'


class RestorePlan:
    def __init__(self, backups: Sequence[dict[str, Any]], into: str | None, phz_profile: str | None, vpc_profiles: dict[str, str]):
        self.backups = backups
        self.into = into
        self.phz_profile = phz_profile
        self.vpc_profiles = vpc_profiles  # account -> profile
        self.lines: list[str] = []
        self.profile_vars: dict[str, tuple[str, str]] = {}  # var -> (default, description)
        self.required: dict[str, str] = {}  # var -> description; the script stops if unset

    def emit(self, *lines: str) -> None:
        self.lines.extend(lines)

    def account_var(self, account: str) -> str:
        var = var_name("PROFILE", account)
        self.profile_vars.setdefault(var, (self.vpc_profiles.get(account, ""), f"VPC owner account {account}"))
        return var

    def build(self) -> str:
        accounts = sorted({b["account"] for b in self.backups})
        self.profile_vars["PHZ_PROFILE"] = (self.phz_profile or "", f"PHZ owner account {', '.join(accounts)}")
        for b in self.backups:
            self.zone(b)
        return self.render()

    def zone(self, b: dict[str, Any]) -> None:
        z = b["zone"]
        old_id, name, account = z["id"], z["name"], b["account"]
        zvar = var_name("ZONE", old_id)
        p = profile_opt("PHZ_PROFILE")
        vpcs = b.get("vpcs") or []
        records = [r for r in b.get("records") or [] if not is_apex_default(r, name)]
        skipped = [r for r in records if r.get("TrafficPolicyInstanceId")]
        records = [r for r in records if not r.get("TrafficPolicyInstanceId")]

        self.emit(
            "", "#" * 78,
            f"# Zone {name}  (backed up as {old_id}, account {account}, {b.get('taken_at')})",
            f"# {len(records)} record set(s), {len(vpcs)} VPC association(s), {len(b.get('tags') or {})} tag(s)",
            f"# from {b.get('_file', '?')}",
            "#" * 78,
        )

        # ----- 1. the zone
        create_vpc = None
        if self.into:
            self.emit("", f"# 1. Restore into existing zone {self.into} (not creating one)", f"{zvar}={shlex.quote(self.into)}")
        else:
            create_vpc = next((v for v in vpcs if v.get("owner") == account), None)
            if create_vpc:
                vpc_arg = f"VPCRegion={create_vpc['region']},VPCId={create_vpc['vpc_id']}"
                note = f"created with VPC {create_vpc['vpc_id']} ({create_vpc['region']})"
            else:
                rv, iv = var_name("CREATE_VPC_REGION", old_id), var_name("CREATE_VPC_ID", old_id)
                self.required[iv] = f"a VPC in account {account} to create {name} with (no VPC in the backup is known to be owned by {account})"
                self.required[rv] = f"region of ${iv}"
                vpc_arg = f'"VPCRegion=${rv},VPCId=${iv}"'
                note = f"created with ${iv}, a VPC in the PHZ account (route 53 needs one; disassociate it at the end if it isn't wanted)"
            config = json.dumps({"Comment": z.get("comment") or "", "PrivateZone": True})
            self.emit(
                "", f"# 1. Create the private hosted zone ({note})",
                f"{zvar}=$(aws route53 create-hosted-zone --name {shlex.quote(name + '.')} "
                f"--caller-reference \"phz-restore-{old_id}-$(date +%s)\" --vpc {vpc_arg} "
                f"--hosted-zone-config {shlex.quote(config)} {p} --query HostedZone.Id --output text)",
                f'{zvar}="${{{zvar}##*/}}"',
                f'echo "Created {name} as ${zvar}"',
            )

        # ----- 2. tags
        tags = [{"Key": k, "Value": v} for k, v in (b.get("tags") or {}).items()]
        if tags:
            self.emit("", "# 2. Tags")
            for i in range(0, len(tags), TAGS_PER_CALL):
                self.emit(
                    f'aws route53 change-tags-for-resource --resource-type hostedzone --resource-id "${zvar}" '
                    f"--add-tags {shlex.quote(json.dumps(tags[i:i + TAGS_PER_CALL]))} {p}"
                )

        # ----- 3. records
        if records or skipped:
            self.emit("", f"# 3. Record sets (UPSERT; apex SOA/NS come with the zone). Aliases into this zone are rewritten to ${zvar}.")
        for rr in skipped:
            self.emit(f"# SKIP {rr['Name']} {rr['Type']}: created by traffic policy instance {rr['TrafficPolicyInstanceId']}; recreate the instance")
        health = sorted({rr["HealthCheckId"] for rr in records if rr.get("HealthCheckId")})
        if health:
            self.emit(f"# Note: these records use health checks that must still exist: {', '.join(health)}")
        placeholder = "@@ZONE_ID@@"
        batches = []
        for level in record_levels(records, old_id):
            prepared = []
            for rr in level:
                if "AliasTarget" in rr and normalize_zone_id(rr["AliasTarget"]["HostedZoneId"]) == old_id:
                    rr = {**rr, "AliasTarget": {**rr["AliasTarget"], "HostedZoneId": placeholder}}
                prepared.append(rr)
            batches += chunk_changes(prepared)
        for i, changes in enumerate(batches, 1):
            body = json.dumps({"Comment": f"phz_backup restore {name} {i}/{len(batches)}", "Changes": changes}, indent=1)
            fname = f'"$WORK/{old_id}-{i:03d}.json"'
            self.emit(
                f"# batch {i}/{len(batches)}: {len(changes)} record set(s)",
                f"sed \"s/{placeholder}/${zvar}/g\" > {fname} <<'PHZ_BATCH_EOF'",
                body,
                "PHZ_BATCH_EOF",
                f'aws route53 change-resource-record-sets --hosted-zone-id "${zvar}" --change-batch file://{fname} '
                f"{p} --query ChangeInfo.Id --output text",
            )

        # ----- 4. VPC associations (after the records, so newly associated VPCs see a complete zone)
        rest = [v for v in vpcs if v is not create_vpc]
        auths = [a for a in b.get("authorizations") or [] if (a["region"], a["vpc_id"]) not in {(v["region"], v["vpc_id"]) for v in vpcs}]
        if rest or auths:
            self.emit("", "# 4. VPC associations")
        tolerate = " || echo \"  (failed; already associated?)\"" if self.into else ""
        for v in rest:
            vpc_arg = f"VPCRegion={v['region']},VPCId={v['vpc_id']}"
            base = f'--hosted-zone-id "${zvar}" --vpc {vpc_arg}'
            owner = v.get("owner")
            if owner == account:
                self.emit(f"# {v['vpc_id']} ({v['region']}): same account", f"aws route53 associate-vpc-with-hosted-zone {base} {p}{tolerate}")
                continue
            if owner:
                vvar = self.account_var(owner)
                who = f"account {owner}"
            else:
                vvar = var_name("PROFILE", v["vpc_id"])
                self.required[vvar] = f"profile in the account that owns {v['vpc_id']} ({v['region']}); owner unknown at backup time"
                who = "owner unknown at backup time"
            self.emit(
                f"# {v['vpc_id']} ({v['region']}): cross-account ({who}): authorize, associate as the VPC owner, clean up",
                f"aws route53 create-vpc-association-authorization {base} {p}{tolerate}",
                f"aws route53 associate-vpc-with-hosted-zone {base} {profile_opt(vvar)}{tolerate}",
                f"aws route53 delete-vpc-association-authorization {base} {p}{tolerate}",
            )
        for a in auths:
            self.emit(
                f"# pending authorization for {a['vpc_id']} ({a['region']}) (not associated at backup time)",
                f'aws route53 create-vpc-association-authorization --hosted-zone-id "${zvar}" '
                f"--vpc VPCRegion={a['region']},VPCId={a['vpc_id']} {p}{tolerate}",
            )
        if not self.into and not create_vpc:
            iv, rv = var_name("CREATE_VPC_ID", old_id), var_name("CREATE_VPC_REGION", old_id)
            self.emit(
                f"# If ${iv} isn't one of the zone's VPCs, remove it now that the others are associated:",
                f'# aws route53 disassociate-vpc-from-hosted-zone --hosted-zone-id "${zvar}" --vpc "VPCRegion=${rv},VPCId=${iv}" {p}',
            )

        # ----- 5. check
        self.emit(
            "", "# 5. Check",
            f'echo "{name} (${zvar}): $(aws route53 list-resource-record-sets --hosted-zone-id "${zvar}" {p} '
            f"--query 'length(ResourceRecordSets)' --output text) record set(s) "
            f'(backup: {len(b.get("records") or [])}), '
            f"$(aws route53 get-hosted-zone --id \"${zvar}\" {p} --query 'length(VPCs)' --output text) VPC(s) (backup: {len(vpcs)})\"",
        )

    def render(self) -> str:
        names = ", ".join(b["zone"]["name"] for b in self.backups)
        head = [
            "#!/usr/bin/env bash",
            f"# PHZ restore plan for {names}",
            f"# Generated by phz_backup.py restore-plan on {dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')}",
            "# " + ("Refills an existing zone (record sets are UPSERTed; records added since the backup are kept)."
                    if self.into else "Creates the zone(s) anew; the new zone ID is printed and used for every later step."),
            "# Review before running. Requires bash, sed and the AWS CLI v2.",
            "set -euo pipefail",
            'export AWS_PAGER=""',
            "",
            "# Profiles: override by exporting the variable before running. Empty = default credential chain.",
        ]
        for var, (default, what) in sorted(self.profile_vars.items(), key=lambda kv: kv[0] != "PHZ_PROFILE"):
            head.append(f'{var}="${{{var}-{default}}}"   # {what}')
        if self.required:
            head += ["", "# Must be set before running (the script stops otherwise):"]
            for var, what in self.required.items():
                head.append(f': "${{{var}:?set {var}: {what}}}"')
        head += ["", 'WORK="$(mktemp -d)"', "trap 'rm -rf \"$WORK\"' EXIT"]
        return "\n".join(head + self.lines) + "\n"


def parse_profile_overrides(values: Sequence[str] | None) -> dict[str, str]:
    """--cli-profile ACCOUNT=PROFILE (repeatable / comma-separated) -> {account: profile}."""
    out: dict[str, str] = {}
    for raw in values or []:
        for item in split_csv(raw):
            acct, sep, prof = item.partition("=")
            if not sep or not prof.strip():
                raise ValueError(f"--cli-profile: '{item}' is not ACCOUNT=PROFILE")
            out[validate_account(acct, "--cli-profile")] = prof.strip()
    return out


def default_profiles(backups: Sequence[dict[str, Any]], args: argparse.Namespace) -> tuple[str | None, dict[str, str]]:
    """Profiles written into restore scripts, per account: --cli-profile ACCOUNT=PROFILE if given, else the
    single profile in ~/.aws/config that maps to the account and ends in --profile-suffix (default -adm).
    An account without one falls back to the default credential chain unless its variable is set at run time."""
    overrides = parse_profile_overrides(getattr(args, "cli_profile", None))
    suffix = getattr(args, "profile_suffix", None) or priv_suffix()
    accounts = {b["account"] for b in backups}
    vpc_accounts = {v["owner"] for b in backups for v in b.get("vpcs") or [] if v.get("owner") and v["owner"] != b["account"]}
    found: dict[str, str] = {}
    for a in sorted(accounts | vpc_accounts):
        prof = overrides.get(a) or priv_profile(a, suffix)
        if prof:
            found[a] = prof
        else:
            log.warning("No profile ending in %s maps to account %s in your AWS config; its commands use the default "
                        "credential chain unless set (--cli-profile %s=PROFILE)", suffix, a, a)
    phz = getattr(args, "cli_phz_profile", None) or (found.get(next(iter(accounts))) if len(accounts) == 1 else None)
    return phz, {a: found[a] for a in vpc_accounts if a in found}


def run_restore_plan(args: argparse.Namespace) -> int:
    files = resolve_backup(args.backup, Path(args.backup_dir).expanduser(), args.account)
    selectors = [s for raw in args.zone for s in split_csv(raw)]
    backups = load_zone_backups(files, selectors)
    if args.into and len(backups) != 1:
        raise ValueError(f"--into needs exactly one zone; the backup has {len(backups)} (pick one with --zone)")
    into = normalize_zone_id(args.into) if args.into else None
    phz_profile, vpc_profiles = default_profiles(backups, args)
    script = RestorePlan(backups, into, phz_profile, vpc_profiles).build()
    if args.out:
        out = Path(args.out)
        secure_io.write_private_text(out, script, executable=True)
        log.info("Wrote %s", out)
    else:
        sys.stdout.write(script)
    return 0


# --------------------------------------------------------------------------- HTML report


def report_paths(b: dict[str, Any], reports_dir: str, now: dt.datetime) -> tuple[Path, Path]:
    """A zone's current report DIR/<account>/phz-backup_<zone-id>.html (overwritten each run) and a
    timestamped copy DIR/<YYYY-MM-DD>/<account>/phz-backup_<zone-id>_<HHMMSS>.html."""
    root, zid = Path(reports_dir).expanduser(), b["zone"]["id"]
    return (root / b["account"] / f"phz-backup_{zid}.html",
            root / now.date().isoformat() / b["account"] / f"phz-backup_{zid}_{now:%H%M%S}.html")


def write_reports(backups: Sequence[dict[str, Any]], source: str, reports_dir: str, out: str | None,
                  args: argparse.Namespace) -> list[Path]:
    """One report per zone. Returns the current report paths."""
    if out and len(backups) != 1:
        raise ValueError(f"--out needs exactly one zone; the backup has {len(backups)} (pick one with --zone, or use --reports-dir)")
    now = dt.datetime.now().astimezone()
    generated = now.astimezone(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    phz_profile, vpc_profiles = default_profiles(backups, args)
    written = []
    for b in backups:
        script = RestorePlan([b], None, phz_profile, vpc_profiles).build()
        page = render_html([b], [script], source, generated)
        targets = [Path(out)] if out else list(report_paths(b, reports_dir, now))
        for t in targets:
            secure_io.write_private_text(t, page)
        log.info("Report: %s", targets[0])
        written.append(targets[0])
    return written


def run_report(args: argparse.Namespace) -> int:
    files = resolve_backup(args.backup, Path(args.backup_dir).expanduser(), args.account)
    backups = load_zone_backups(files, [s for raw in args.zone for s in split_csv(raw)])
    spec = Path(args.backup).expanduser()
    source = str(spec if spec.is_file() else files[0].parent)
    for path in write_reports(backups, source, args.reports_dir, args.out, args):
        print(path)
    return 0


# --------------------------------------------------------------------------- CLI


def add_script_profile_args(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group(
        "restore script profiles",
        "Each account's profile is the one in ~/.aws/config that maps to it (sso_account_id / aws_account_id / role_arn) "
        "and ends in --profile-suffix. Every profile is a variable at the top of the script, so it can still be overridden "
        "at run time.")
    g.add_argument("--profile-suffix", default=None,
                   help="Suffix of the profile to use per account, given as --profile-suffix=-ops (default: VPCE_PRIV_PROFILE_SUFFIX or -adm)")
    g.add_argument("--cli-profile", action="append", metavar="ACCOUNT=PROFILE",
                   help="Use PROFILE for ACCOUNT instead of matching by suffix (repeatable / comma-separated)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Back up Route 53 private hosted zones and generate AWS CLI commands to restore them.")
    sub = p.add_subparsers(dest="command", required=True)
    root_help = "Backups root (default: VPCE_BACKUP_DIR or ./backups/phz)"
    root_default = os.getenv("VPCE_BACKUP_DIR") or DEFAULT_ROOT
    reports_default = os.getenv("VPCE_REPORTS_DIR") or "reports"
    reports_help = ("HTML report root: one report per zone, DIR/<account>/phz-backup_<zone-id>.html (overwritten each run), "
                    "plus a timestamped copy in DIR/<YYYY-MM-DD>/<account>/ (default: VPCE_REPORTS_DIR or ./reports)")

    b = sub.add_parser("backup", help="Back up PHZs (default: every PHZ in the account)")
    add_common_args(b)
    add_account_args(b)
    b.add_argument("--zone", action="append", default=[], metavar="ID|ARN", help="Hosted zone ID/ARN (repeatable / comma-separated)")
    b.add_argument("--zone-name", action="append", default=[], metavar="GLOB", help="Select PHZs by name glob")
    b.add_argument("--zone-tag", action="append", metavar="KEY[=V1,V2]", help="Select PHZs by tag")
    b.add_argument("--exclude-zone-tag", action="append", metavar="KEY[=V1,V2]", help="Exclude PHZs by tag")
    b.add_argument("--no-authorizations", action="store_true", help="Don't record pending cross-account authorizations")
    b.add_argument("--owner-cache", metavar="FILE", default=os.getenv("VPCE_OWNER_CACHE"),
                   help="Local VPC -> owner map, filled by tools/ou_vpcs and phz_review (default: ~/.cache/aws-net-tools/vpc-owners.json)")
    b.add_argument("--no-owner-cache", action="store_true", help="Don't read or write the local VPC owner map")
    b.add_argument("--backup-dir", default=root_default, help=root_help)
    b.add_argument("--json", action="store_true", help="Print the summary as JSON")
    b.add_argument("--no-html", action="store_true", help="Don't write the HTML report")
    b.add_argument("--reports-dir", default=reports_default, help=reports_help)
    add_script_profile_args(b)

    r = sub.add_parser("restore-plan", help="Generate a bash script of AWS CLI commands that restores PHZs from a backup")
    r.add_argument("backup", help="Backup directory, one zone file, or latest / previous")
    r.add_argument("--zone", action="append", default=[], metavar="ID|NAME", help="Only these zones from the backup (repeatable / comma-separated)")
    r.add_argument("--into", metavar="ZONE_ID", help="Refill this existing zone instead of creating a new one (one zone only)")
    r.add_argument("--account", help="With latest / previous: the account whose backups to use")
    r.add_argument("--cli-phz-profile", help="Default profile for PHZ-owner commands (default: the account's -adm profile, if any)")
    r.add_argument("--backup-dir", default=root_default, help=root_help)
    add_script_profile_args(r)
    r.add_argument("--out", "-o", metavar="FILE", help="Write the script to FILE (mode 0700) instead of stdout")
    r.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    r.add_argument("-q", "--quiet", action="store_true", help="Warnings/errors only")

    h = sub.add_parser("report", help="Write the HTML report of each zone in a backup")
    h.add_argument("backup", help="Backup directory, one zone file, or latest / previous")
    h.add_argument("--zone", action="append", default=[], metavar="ID|NAME", help="Only these zones from the backup (repeatable / comma-separated)")
    h.add_argument("--account", help="With latest / previous: the account whose backups to use")
    h.add_argument("--backup-dir", default=root_default, help=root_help)
    h.add_argument("--reports-dir", default=reports_default, help=reports_help)
    add_script_profile_args(h)
    h.add_argument("--out", "-o", metavar="FILE", help="One zone only: write its report to FILE instead (no timestamped copy)")
    h.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    h.add_argument("-q", "--quiet", action="store_true", help="Warnings/errors only")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.verbose, args.quiet)
    try:
        if args.command == "backup":
            args.zone = [normalize_zone_id(z) for raw in args.zone for z in split_csv(raw)]
            return run_backup(args)
        if args.command == "report":
            return run_report(args)
        return run_restore_plan(args)
    except (ValueError, LookupError, PermissionError, FileExistsError) as e:
        log.error("%s", e)
        return 2
    except ClientError as e:
        log_client_error(e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
