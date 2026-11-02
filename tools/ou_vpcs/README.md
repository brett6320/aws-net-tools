# ou_vpcs

[![ou_vpcs tests](https://github.com/brett6320/aws-net-tools/actions/workflows/tests-ou_vpcs.yml/badge.svg?branch=main)](https://github.com/brett6320/aws-net-tools/actions/workflows/tests-ou_vpcs.yml) ![Tests](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrett6320%2Faws-net-tools%2Fbadges%2Fou_vpcs-tests.json) ![Coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrett6320%2Faws-net-tools%2Fbadges%2Fou_vpcs-coverage.json) ![Python 3.11 | 3.12 | 3.13](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-3776AB?logo=python&logoColor=white)

Lists every VPC owned by the accounts in one or more AWS Organizations OUs:

1. **OU → accounts**: AWS Organizations, using one profile for the management or delegated-administrator account. OUs below the given OU are included unless you pass `--no-recurse`.
2. **Account → profile**: the profile in `~/.aws/config` whose `sso_account_id`, `aws_account_id` or `role_arn` account matches. Profiles ending in **`-priv`** or **`-cpar`** are never used.
3. **Profile → VPCs**: one `DescribeVpcs` per account and Region, filtered to VPCs the account owns. Regions default to `us-east-1` and `ca-central-1`.

Every VPC found is also saved to the **local VPC owner map** that [`phz_review`](../phz/phz_review/README.md) uses (`~/.cache/aws-net-tools/vpc-owners.json`). Running `ou_vpcs` first means `phz_review` doesn't have to look those owners up.

The tool is **read-only**: it never changes AWS resources. Python 3.11+ / boto3.

## Install

Set up the shared virtual environment as described in the [repository README](../../README.md#getting-started), or install this tool on its own:

```bash
pip install -r tools/ou_vpcs/requirements.txt
cp tools/ou_vpcs/.env.example tools/ou_vpcs/.env   # optional defaults
```

## Usage

```bash
# Every VPC in the Prod OU and the OUs below it, us-east-1 and ca-central-1
python tools/ou_vpcs/ou_vpcs.py --profile org-mgmt-ro --ou ou-ab12-11111111

# Two OUs, other Regions, CSV
python tools/ou_vpcs/ou_vpcs.py --profile org-mgmt-ro --ou ou-ab12-11111111,ou-ab12-22222222 \
    --regions us-east-1,us-west-2 -o csv > vpcs.csv

# The whole organization, as JSON (root ID or organization ID)
python tools/ou_vpcs/ou_vpcs.py --profile org-mgmt-ro --ou r-ab12 --json
python tools/ou_vpcs/ou_vpcs.py --profile org-mgmt-ro --ou o-abcde12345 --json
```

| Flag | Env var | Meaning |
|---|---|---|
| `--ou OU_ID` | `OU_VPCS_OU` | OU (`ou-xxxx-xxxxxxxx`), root (`r-xxxx`) or organization (`o-xxxxxxxxxx`); repeat or comma-separate. Required |
| `--profile` | `OU_VPCS_ORG_PROFILE`, then `AWS_PROFILE` | Profile for the Organizations calls (management or delegated-administrator account) |
| `--regions` | `OU_VPCS_REGIONS` | Regions to scan in each account; repeat or comma-separate (default `us-east-1,ca-central-1`) |
| `--no-recurse` | | Only accounts directly in the OU |
| `--account-profile ACCOUNT=PROFILE` | | Profile for an account when none or several map to it; repeat or comma-separate |
| `--cache FILE` | `OU_VPCS_CACHE`, then `VPCE_OWNER_CACHE` | VPC owner map (default `~/.cache/aws-net-tools/vpc-owners.json`, `%LOCALAPPDATA%\aws-net-tools\` on Windows) |
| `--no-cache` | | Don't write the VPC owner map |
| `-o table\|csv\|json`, `--json` | | Output format (default `table`) |
| `-v` / `-q` | | Debug logging / warnings only |

A root or organization ID means every account in the organization. An organization ID must be the organization the `--profile` account belongs to; any other is rejected (exit code `2`). It is then resolved to the organization's root.

Only active accounts are listed; suspended and closed accounts are skipped.

### Profiles for member accounts

For each account, in order:

1. `--account-profile ACCOUNT=PROFILE`, if given
2. the profiles that map to the account, minus any ending in `-priv` or `-cpar` (override the suffixes with `OU_VPCS_PROFILE_EXCLUDE_SUFFIXES`):
   - `--profile`, if it maps to the account
   - otherwise the only one, or the single read-only one (`-ro`, `-readonly`, `-read-only`) when there are several
   - still several, or none: the account is skipped with a warning

No role is assumed. The tool checks the account behind each profile (`sts:GetCallerIdentity`) and skips the account if it doesn't match.

## Output

Logs and the summary go to stderr; the rows go to stdout.

| Column | Meaning |
|---|---|
| `ou_path` | e.g. `Root/Prod/Web`. The JSON also has `ou_id` |
| `account`, `account_name` | Owner account and its name in Organizations |
| `region`, `vpc_id`, `name` | Region, VPC ID and `Name` tag |
| `cidrs` | Associated IPv4 CIDRs, primary first, the rest sorted. The JSON also has `cidr` (primary) and `state` |
| `is_default` | Default VPC |

Exit codes: `0` all accounts and Regions scanned, `1` Organizations error, `2` bad input, `3` some accounts or Regions skipped (rows for the rest are still printed and saved).

## VPC owner map

Each VPC is stored under `<region>/<vpc-id>` with its owner `account`, `source: "ou_vpcs"`, the date it was last changed (`seen`), and `account_name`, `ou_id`, `ou_path`, `name` and `cidrs`. `phz_review` reads the `account` field and keeps the rest when it adds its own entries. Entries never expire. Re-running is idempotent: the same scan prints the same rows, and an entry (and the file) is only rewritten when something about the VPC changed, not when AWS returns things in a different order.

The file is written owner-only (`0600`) outside the repository. `.gitignore` excludes `vpc-owners*.json` in case `--cache` points inside it.

## IAM permissions

Organizations profile (`DescribeOrganization` and `ListRoots` are only used for an organization ID):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "organizations:ListAccountsForParent",
      "organizations:ListOrganizationalUnitsForParent",
      "organizations:ListParents",
      "organizations:DescribeOrganizationalUnit",
      "organizations:DescribeOrganization",
      "organizations:ListRoots"
    ],
    "Resource": "*"
  }]
}
```

Each member account profile: `ec2:DescribeVpcs`.

## Tests

```bash
cd tools/ou_vpcs
pip install -r requirements-dev.txt
python -m pytest
```

Organizations runs under moto; member accounts are in-memory fakes. No AWS credentials are needed.
