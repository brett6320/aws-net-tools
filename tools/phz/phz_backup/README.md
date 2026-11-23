# phz_backup

Back up Route 53 private hosted zones and generate the AWS CLI commands that restore them. Part of the
[PHZ suite](../README.md); accounts, credentials and profile derivation work as described there.

Each zone backup holds:

- **Zone:** ID, name and comment.
- **Tags.**
- **Record sets:** every record set exactly as `ListResourceRecordSets` returns it (routing policies, alias
  targets, health check IDs and so on).
- **VPC associations:** region, VPC ID and the VPC's owner account, where known.
- **Pending cross-account authorizations** (`ListVPCAssociationAuthorizations`).

The tool is read-only against AWS. `restore-plan` and `report` work offline from the backup files;
restore scripts are only printed for you to review and run.

Every backup also writes an [HTML report](#html-report) (skip it with `--no-html`).

## Usage

```bash
# Back up every PHZ in the account (or select with --zone / --zone-name / --zone-tag); writes the HTML report too
python tools/phz/phz_backup/phz_backup.py backup --profile hub

# HTML report of an existing backup
python tools/phz/phz_backup/phz_backup.py report latest

# Emergency: the zone was deleted. Script that recreates it from the newest backup
python tools/phz/phz_backup/phz_backup.py restore-plan latest --zone corp.internal -o corp.restore.sh
bash corp.restore.sh

# The zone still exists but records were lost or damaged: refill it in place
python tools/phz/phz_backup/phz_backup.py restore-plan latest --zone corp.internal \
  --into Z0123456789ABCDEFGHIJ -o corp.refill.sh
```

Backups are written to `backups/phz/<account>/<timestamp>/`: one `<zone-id>_<name>.json` per zone and a
`manifest.json`. A backup can be named by its directory, by one zone file, or as `latest` / `previous`
(add `--account` when the root holds backups of several accounts). The root is `./backups/phz`, or
`--backup-dir` / `VPCE_BACKUP_DIR`. Backups never overwrite each other.

Keep copies somewhere other than the account they protect (the backup files are plain JSON, safe to put
in an S3 bucket or a repository; they hold no secrets).

## HTML report

A self-contained page (no external resources, dark/light toggle) with:

- **Summary cards:** zones, record sets, VPC associations, cross-account associations, unknown VPC owners
  (highlighted when any) and pending authorizations.
- **Zones table**, linking to each zone's section.
- **Per zone:** account, comment and tags; VPC associations with owner account, marked same account,
  cross-account or unknown owner; pending authorizations; every record set with type, TTL, value (alias
  targets shown as such) and routing (set ID, weight, latency region, failover, geolocation, multivalue,
  health check), with a filter box; and the zone's **restore script** (the same one `restore-plan` writes
  for that zone) with Copy and Download buttons. Nothing runs from the page.

`backup` writes it to `reports/<account>/phz-backup.html`, overwritten on every run, with a timestamped
copy in `reports/<YYYY-MM-DD>/<account>/phz-backup_<HHMMSS>.html`. The root is `--reports-dir` or
`VPCE_REPORTS_DIR`. `report BACKUP` writes the same report for any backup, or to `--out FILE`.

The report embeds every record, so treat it like the backup itself: keep it with the backups, outside
the account it protects, for when the console isn't an option.

## The restore script

`restore-plan` writes a bash script that needs only bash, sed and the AWS CLI v2. For each zone, in order:

1. **Create the zone** with `create-hosted-zone`, using a VPC from the backup that the PHZ account owns
   (Route 53 needs one at creation). The new zone ID is captured and used by every later command. If no
   VPC in the backup is known to be owned by the PHZ account, the script stops until you set
   `CREATE_VPC_ID_<ZONE>` / `CREATE_VPC_REGION_<ZONE>`, and ends with a commented command to remove that
   VPC again. With `--into ZONE_ID` this step is skipped and the existing zone is used.
2. **Tags** with `change-tags-for-resource`.
3. **Record sets** with `change-resource-record-sets` (`UPSERT`), in batches well inside the API limits.
   The apex SOA and NS records come with the new zone and are skipped. Aliases that point into the zone
   itself are rewritten to the new zone ID and created after their targets. Records made by a traffic
   policy instance are listed as comments; recreate the instance instead. Health checks are separate
   resources: the script lists the IDs the records need.
4. **VPC associations**, after the records, so a VPC never sees a half-filled zone. Same-account VPCs are
   associated directly. Cross-account VPCs get the full handshake: the PHZ owner authorizes, the VPC owner
   associates, the PHZ owner deletes the authorization. Pending authorizations from the backup are
   recreated.
5. **Check:** prints the zone's record set and VPC counts next to the backup's.

Profiles are variables at the top of the script: `PHZ_PROFILE` for the PHZ owner and `PROFILE_<account>`
for each VPC owner account. They default to the account's `-adm` profile when exactly one is in your AWS
config (`--cli-phz-profile` overrides the PHZ one); export a variable to override it, or leave it empty to
use the default credential chain. A VPC whose owner was unknown at backup time gets a
`PROFILE_VPC_<ID>` variable that must be set before the script runs.

With `--into`, records are upserted, so records added since the backup are kept, and association commands
that fail (usually because the VPC is still associated) print a note instead of stopping the script.

### VPC owners

`GetHostedZone` doesn't say which account owns each associated VPC, and a cross-account VPC needs the
authorization handshake. `backup` takes owners from the local VPC owner map (filled by
[`ou_vpcs`](../../ou_vpcs/) and [`phz_review`](../phz_review/)), then from `DescribeVpcs` in the PHZ
account, which sees its own VPCs and VPCs shared with it. The summary shows how many stayed unknown. Run
`ou_vpcs` for the OUs involved first to resolve them all.

## Options

| Command | Option | Meaning |
|---|---|---|
| `backup` | `--zone`, `--zone-name`, `--zone-tag`, `--exclude-zone-tag` | Select zones (default: every PHZ in the account) |
| | `--no-authorizations` | Don't read pending authorizations |
| | `--owner-cache FILE`, `--no-owner-cache` | VPC owner map location, or don't use it |
| | `--backup-dir DIR` | Backups root |
| | `--json` | Print the summary (and backup and report paths) as JSON |
| | `--no-html` | Don't write the HTML report |
| | `--reports-dir DIR` | HTML report root |
| `restore-plan` | `BACKUP` | Backup directory, zone file, `latest` or `previous` |
| | `--zone ID\|NAME` | Only these zones (default: every zone in the backup) |
| | `--into ZONE_ID` | Refill an existing zone instead of creating one (one zone only) |
| | `--account` | With `latest` / `previous`: whose backups |
| | `--cli-phz-profile` | Default `PHZ_PROFILE` in the script |
| | `-o FILE` | Write the script to FILE (mode 0700) |
| `report` | `BACKUP`, `--zone`, `--account` | As for `restore-plan` |
| | `--reports-dir DIR` / `-o FILE` | Where to write the report |

Exit codes: 0 ok, 1 AWS error, 2 bad input.

## IAM permissions

`backup`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "route53:ListHostedZones",
        "route53:GetHostedZone",
        "route53:ListResourceRecordSets",
        "route53:ListTagsForResources",
        "route53:ListVPCAssociationAuthorizations",
        "ec2:DescribeVpcs",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

Running a restore script needs, in the PHZ account, `route53:CreateHostedZone`,
`route53:ChangeTagsForResource`, `route53:ChangeResourceRecordSets`,
`route53:AssociateVPCWithHostedZone`, `route53:CreateVPCAssociationAuthorization`,
`route53:DeleteVPCAssociationAuthorization`, `route53:ListResourceRecordSets`, `route53:GetHostedZone` and
`ec2:DescribeVpcs`; in each VPC owner account, `route53:AssociateVPCWithHostedZone` and `ec2:DescribeVpcs`.
