# vpc_participants

[![vpc_participants tests](https://github.com/brett6320/aws-net-tools/actions/workflows/tests-vpc_participants.yml/badge.svg?branch=main)](https://github.com/brett6320/aws-net-tools/actions/workflows/tests-vpc_participants.yml) ![Tests](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrett6320%2Faws-net-tools%2Fbadges%2Fvpc_participants-tests.json) ![Coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrett6320%2Faws-net-tools%2Fbadges%2Fvpc_participants-coverage.json) ![Python 3.11 | 3.12 | 3.13](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-3776AB?logo=python&logoColor=white)

Shows who a VPC is shared with: the account that owns it, and every RAM principal (account, OU or organization) that its subnets are shared to.

1. **VPC → owner**: the VPC owner map that [`ou_vpcs`](../ou_vpcs/README.md) writes (`~/.cache/aws-net-tools/vpc-owners.json`) gives the owner account, Region, account name and OU. Run `ou_vpcs` for the VPC's OU first.
2. **Owner → profile**: the profile in `~/.aws/config` whose `sso_account_id`, `aws_account_id` or `role_arn` account matches, with the same rules as `ou_vpcs`. Profiles ending in **`-priv`**, **`-adm`**, **`-cpar`** or **`-ro`** (any case) are never used.
3. **Subnets → shares → principals**: as the owner, in the VPC's Region, `DescribeSubnets` for the VPC, then RAM `ListResources` (which shares contain those subnets), `GetResourceShares` (share names and status) and `GetResourceShareAssociations` (each share's principals and association status).
4. **OU and organization principals → accounts**: with `--org-profile`, Organizations lists every active account in the OU and the OUs below it (or the whole organization). Without it, the accounts come from the VPC owner map, which only knows accounts that own a VPC, and only the OU each account sits in directly: a share to a parent OU with no such account directly in it can't be expanded (its `members_source` is `unknown`, `member_count` shows `?`, and a warning says to pass `--org-profile`). The `members_source` column says which was used.

The tool is **read-only**: it never changes AWS resources. Python 3.11+ / boto3.

## Install

Set up the shared virtual environment as described in the [repository README](../../README.md#getting-started), or install this tool on its own:

```bash
pip install -r tools/vpc_participants/requirements.txt
cp tools/vpc_participants/.env.example tools/vpc_participants/.env   # optional defaults
```

## Usage

```bash
# Fill the VPC owner map first (once, or when accounts or VPCs change)
python tools/ou_vpcs/ou_vpcs.py --profile org-mgmt --ou ou-ab12-11111111

# Owner and participants of one VPC
python tools/vpc_participants/vpc_participants.py vpc-0abc1234def567890

# Several VPCs, OU principals expanded with Organizations, as JSON
python tools/vpc_participants/vpc_participants.py vpc-0abc1234def567890,vpc-0123456789abcdef0 \
    --org-profile org-mgmt --json
```

| Flag | Env var | Meaning |
|---|---|---|
| `VPC_ID ...` | | VPC(s) to look up; repeat or comma-separate. Required |
| `--regions` | | Only look for the VPCs in these Regions. Needed when a VPC ID is in the owner map in several Regions |
| `--cache FILE` | `VPC_PART_CACHE`, then `OU_VPCS_CACHE` | VPC owner map (default `~/.cache/aws-net-tools/vpc-owners.json`, `%LOCALAPPDATA%\aws-net-tools\` on Windows) |
| `--profile` | `AWS_PROFILE` | Preferred profile when several map to an owner account |
| `--account-profile ACCOUNT=PROFILE` | | Profile for an owner account when none or several map to it; repeat or comma-separate |
| `--org-profile` | `VPC_PART_ORG_PROFILE`, then `OU_VPCS_ORG_PROFILE` | Profile for Organizations (management or delegated-administrator account). Expands OU and organization principals, and names accounts the owner map doesn't know. If its calls fail, the owner map is used |
| `--all-statuses` | | Also list principals whose association is `DISASSOCIATED`, `DISASSOCIATING` or `FAILED`, and shares that aren't `ACTIVE` |
| `-o table\|csv\|json`, `--json` | | Output format (default `table`) |
| `-v` / `-q` | | Debug logging / warnings only |

`VPC_PART_PROFILE_EXCLUDE_SUFFIXES` overrides the profile suffixes that are never used.

## Output

Logs and the summary go to stderr; the rows go to stdout. Each VPC has one `owner` row, followed by one `participant` row per principal its subnets are shared with. A VPC with no shared subnets has only its owner row.

| Column | Meaning |
|---|---|
| `vpc_id`, `region`, `vpc_name` | The VPC, its Region and `Name` tag (from the owner map). CSV and JSON also have `owner` |
| `role` | `owner` or `participant` |
| `principal`, `principal_type` | Account ID, OU ARN or organization ARN, and `account`, `ou`, `organization` or `other` |
| `principal_name` | Account name, OU path (e.g. `Root/Prod`) or `organization o-...`, from the owner map or Organizations |
| `status` | Association status, e.g. `ASSOCIATED` or `ASSOCIATING` (several when the principal is in several shares). `error` on an owner row whose VPC couldn't be read |
| `shares` | Names of the resource shares (the ARN when a share has no name). JSON also has `share_arns` |
| `subnets` | Owner row: every subnet in the VPC. Participant row: the subnets shared with that principal |
| `member_count` (table) / `members` | Accounts an OU or organization principal covers. CSV and JSON also have `members_source` (`organizations`, `catalog` or `unknown`) |
| `external` (CSV, JSON) | RAM marks the principal as outside the organization |
| `error` | Why the VPC couldn't be read (shown in the table only when there is one) |

Warnings are logged for an `other` principal (such as an IAM role) or an external one, since subnet sharing is normally only within the organization, and for shared subnets whose RAM resource status isn't `AVAILABLE`.

Exit codes: `0` every VPC read, `1` some VPCs couldn't be read (the others' rows are still printed), `2` bad input (unknown VPC, VPC in several Regions, unreadable owner map).

## IAM permissions

Owner account profile:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "ec2:DescribeSubnets",
      "ram:ListResources",
      "ram:GetResourceShares",
      "ram:GetResourceShareAssociations"
    ],
    "Resource": "*"
  }]
}
```

Organizations profile (optional; `DescribeOrganization` and `ListRoots` are only used for organization principals):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "organizations:DescribeAccount",
      "organizations:DescribeOrganizationalUnit",
      "organizations:ListParents",
      "organizations:ListAccountsForParent",
      "organizations:ListOrganizationalUnitsForParent",
      "organizations:DescribeOrganization",
      "organizations:ListRoots"
    ],
    "Resource": "*"
  }]
}
```

## Tests

```bash
cd tools/vpc_participants
pip install -r requirements-dev.txt
python -m pytest
```

EC2, RAM and Organizations are in-memory fakes. No AWS credentials are needed.
