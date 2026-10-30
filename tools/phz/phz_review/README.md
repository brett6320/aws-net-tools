# phz_review

Reviews Route 53 private hosted zones and their VPC associations, in both directions. Read-only. Every output includes the owner account of each zone and VPC.

With `-o html` it writes an interactive report with sortable, filterable tables and a **migration planner** that prepares the AWS CLI commands to move VPCs to a different PHZ, including cross-account authorizations (see [HTML report](#html-report)).

| Subcommand | Answers | Runs against |
|---|---|---|
| `zones` | What PHZs does the PHZ account have, and how many VPCs is each associated with? | PHZ account |
| `by-vpc` | Which PHZs (owned by **any** account) is this VPC associated with? | VPC owner account (`ListHostedZonesByVPC`) |
| `by-zone` | Which VPCs is this PHZ associated with, and which have pending cross-account authorizations? | PHZ account |

## Usage

```bash
python phz_review.py zones   [--zone ID] [--zone-name GLOB] [--zone-tag K=V] [--include-public] [--authorizations] [--wide] [--no-resolve-owners]
python phz_review.py by-vpc  --vpc ID|ARN [--vpc ID|ARN ...] [--vpc-region REGION]
python phz_review.py by-zone [--zone ID] [--zone-name GLOB] [--zone-tag K=V] [--no-authorizations] [--no-resolve-owners]

# any subcommand: interactive HTML report
python phz_review.py <subcommand> ... -o html [--out FILE | --reports-dir DIR]
```

### Options

| Flag | Description |
|---|---|
| `--zone ID\|ARN` | Hosted zone ID, `/hostedzone/ID`, or ARN (repeatable) |
| `--zone-name GLOB` | Zone name glob, e.g. `'*.us-east-1.amazonaws.com'` |
| `--zone-tag KEY[=V1,V2]` / `--exclude-zone-tag` | Zone tag filters (same syntax as `vpce_list --tag`) |
| `--vpc ID\|ARN` | `by-vpc`: VPC(s) to look up; ARNs may span accounts (each is queried as its own owner, via `--role-name` if needed) |
| `--authorizations` | `zones`: add pending cross-account authorizations (always on with `-o html`) |
| `--no-authorizations` | `by-zone`: skip listing authorizations |
| `--no-resolve-owners` | `zones`, `by-zone`: skip looking up VPC owner accounts. By default they are looked up from the PHZ account, which sees its own and RAM-shared VPCs; others show `unknown` (`--resolve-owners` is still accepted) |
| `--wide` | `zones`: add VPC list, VPC owner accounts, comment, tags |
| `-o table\|json\|csv\|html`, `--json` | Output format |
| `--out FILE` | `html`: write the report here |
| `--reports-dir DIR` | `html`: reports go to `DIR/<YYYY-MM-DD>/<account>/phz-review_<subcommand>.html` (default `./reports`, env `VPCE_REPORTS_DIR`) |
| account/profile flags | See the [suite README](../README.md#accounts-and-credentials) |

Account columns: `zones` has `account` (the PHZ owner) and, in `--wide`/JSON, `vpc_owners`; `by-vpc` has `vpc_account` and `zone_owner`; `by-zone` has `zone_owner`, `vpc_owner` and `cross_account` (empty when the VPC owner is unknown).

In `by-zone`, `status` is `associated`, `authorized` (authorization still exists for an associated VPC, which is stale), or `authorized-pending` (authorized but not yet associated).

### Examples

```bash
# All endpoint PHZs in the hub, with association counts and pending authorizations
python phz_review.py zones --profile hub --zone-name '*.amazonaws.com' --authorizations

# Which PHZs does a spoke VPC resolve through? (run as the spoke)
python phz_review.py by-vpc --profile spoke --vpc vpc-0123456789abcdef0

# Several spokes in different accounts, by ARN, via an assumed role
python phz_review.py by-vpc --profile org-admin --role-name NetworkReadOnly \
  --vpc arn:aws:ec2:us-east-1:111111111111:vpc/vpc-0aaaaaaaaaaaaaaa0 \
  --vpc arn:aws:ec2:us-east-1:333333333333:vpc/vpc-0bbbbbbbbbbbbbbb0

# Reverse: which VPCs are on the SSM PHZ, and which accounts own them?
python phz_review.py by-zone --profile hub --zone-name ssm.us-east-1.amazonaws.com

# HTML report of every PHZ in the hub, with the migration planner
python phz_review.py zones --profile hub -o html
```

## HTML report

`-o html` writes one self-contained file (no external assets) and prints its path. It has:

- **Summary**: zones, associations, VPCs, accounts, cross-account associations, pending and stale authorizations, VPCs whose owner is unknown.
- **Private hosted zones**: name, ID, owner account, VPC count, records, comment, tags. Search, filter by owner, click a header to sort (shift-click adds a second sort key). **Use as target** picks the zone in the planner.
- **Associations**: one row per PHZ and VPC with both owner accounts, cross-account flag and status. Search and filter by zone, either owner account, region, cross-account and status; sort by any column.
- **Migration planner**: tick associated rows (the VPCs to move, and the PHZ to move them off), choose a target PHZ from the report or enter any other one (zone ID, name, owner account), and the page prepares a bash script. Commands are grouped into steps, each headed with the account that must run it, and you can add a `--profile` per account. Copy it or download it as `phz-migration.sh`. Nothing runs from the page.

The planner follows Route 53's rules:

| Situation | What the plan does |
|---|---|
| VPC owner ≠ target PHZ owner | Step 1: the target PHZ owner runs `create-vpc-association-authorization` (skipped if the report shows one already). The VPC owner then associates, and the authorization is deleted at the end (optional) |
| Target has a different name from the old PHZ | Associate the new PHZ first, then disassociate the old one, so there is no gap |
| Target has the **same name** as the old PHZ | A VPC can't have two PHZs with the same name (`ConflictingDomainExists`), so each VPC's old PHZ is disassociated right before the new one is associated, back to back, with a warning about the brief gap. Another same-name PHZ on the VPC that isn't selected is an error |
| Disassociation would remove a PHZ's last VPC | Skipped with a reason (Route 53 rejects it). For a same-name move, that VPC is blocked |
| VPC owner unknown | The planner asks for the account before generating commands |
| Leftover authorizations on the old PHZ | Deleted by the old PHZ owner (optional), so the VPC can't re-associate |

Disassociation runs as the VPC owner by default, or as the old PHZ owner. Reports from `by-vpc` don't show every VPC on a zone or any authorizations, so the planner warns that it can't check for last VPCs or existing authorizations; use `zones` or `by-zone` in the PHZ account for a complete picture.

## Requirements / Installation / Configuration

Python 3.11+, `pip install -r requirements.txt`. See [`.env.example`](../.env.example).

## Platform Notes

- **macOS**: System PKI truststore used automatically via Security.framework.
- **Windows**: Windows Certificate Store used automatically. Credentials at `%USERPROFILE%\.aws\credentials`.
- **Linux**: System CA bundle used via `truststore`. Ensure `ca-certificates` is installed.

## IAM Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "route53:ListHostedZones",
        "route53:GetHostedZone",
        "route53:ListTagsForResources",
        "route53:ListHostedZonesByVPC",
        "route53:ListVPCAssociationAuthorizations",
        "ec2:DescribeVpcs",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

`ListHostedZonesByVPC` is needed in the VPC owner account; the rest in the PHZ account (`ec2:DescribeVpcs` there looks up VPC owner accounts; skip it with `--no-resolve-owners`).

## Output

Table, CSV or JSON on stdout; logs on stderr.
