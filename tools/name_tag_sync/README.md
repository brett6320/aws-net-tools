# name_tag_sync

[![name_tag_sync tests](https://github.com/brett6320/aws-net-tools/actions/workflows/tests-name_tag_sync.yml/badge.svg?branch=main)](https://github.com/brett6320/aws-net-tools/actions/workflows/tests-name_tag_sync.yml) ![Tests](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrett6320%2Faws-net-tools%2Fbadges%2Fname_tag_sync-tests.json) ![Coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrett6320%2Faws-net-tools%2Fbadges%2Fname_tag_sync-coverage.json) ![Python 3.11 | 3.12 | 3.13](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-3776AB?logo=python&logoColor=white)

Copies `Name` tags from the account that owns shared VPCs and subnets to a participant account.

When subnets are shared through RAM, the participant sees the VPC and those subnets but not the owner's tags. Each account's tags on a shared resource belong to that account alone, so in the participant's console they show up unnamed. This tool fills in those missing names from the owner's tags.

**Dry run by default.** It writes nothing unless you pass `--apply`, and even then it asks before each resource. Python 3.11+ / boto3.

## Safety rules

- **The owner is the account EC2 reports.** Ownership comes from each resource's `OwnerId`, not from the profile it was read with. Every VPC or subnet both accounts can see must be owned by the `--owner-profile` account. If one is owned by any other account, the run stops with an error (exit `3`) before any change. That includes the `--participant-profile` account and a third account that shares a VPC with both. It also stops if the two accounts disagree on a resource's owner, or both profiles are the same account. Use `--vpc-ids` to leave out VPCs a third account shares with both.
- **The owner account's tags are never changed.** Writes go only through `--participant-profile`, and only to resources that the other account owns.
- **A `Name` tag with a value is never changed.** Only a missing `Name` tag or an empty one (`""`) is filled in. A whitespace-only name counts as a value and is left alone.
- **Each resource is confirmed.** `--apply` prompts `[y/N/q]` for every resource at the terminal. There is no "yes to all". It refuses to run when stdin or stderr isn't a terminal. EOF or Ctrl-C at a prompt means quit.
- **Everything is re-checked just before each write:**
  - the participant profile still authenticates as the same account;
  - both accounts still see the original owner;
  - the participant's `Name` is still missing or empty;
  - the owner's `Name` is still the value you confirmed.

  If the owner or the participant's account changed, the run stops (exit `3`). If a `Name` changed, that resource is skipped. Ctrl-C during a write also stops the run, and the table still shows what was done.
- **Only the one `Name` tag is written, on one resource per call.**

EC2 has no conditional tagging. A tag that someone changes between the re-check and the write, a fraction of a second later, can't be detected.

In the table and prompts, control characters, bidi overrides, zero-width characters and line separators in tag values are shown escaped (e.g. `\x1b`, `\u202e`), so they can't rewrite the terminal. The value written is the original.

## Install

Set up the shared virtual environment as described in the [repository README](../../README.md#getting-started), or install this tool on its own:

```bash
pip install -r tools/name_tag_sync/requirements.txt
cp tools/name_tag_sync/.env.example tools/name_tag_sync/.env   # optional defaults
```

## Usage

```bash
# Dry run: what would be tagged, in the participant profile's Region
python tools/name_tag_sync/name_tag_sync.py --owner-profile network-owner --participant-profile app-team

# Several Regions, one VPC, and check that each tag would be allowed (CreateTags DryRun, writes nothing)
python tools/name_tag_sync/name_tag_sync.py --owner-profile network-owner --participant-profile app-team \
    --regions us-east-1,us-west-2 --vpc-ids vpc-0abc1234def567890 --check-permissions

# Write, confirming each resource
python tools/name_tag_sync/name_tag_sync.py --owner-profile network-owner --participant-profile app-team --apply
```

| Flag | Env var | Meaning |
|---|---|---|
| `--owner-profile` | `NTS_OWNER_PROFILE` | Profile for the account that owns the shared VPCs. Read only, never written to. Required |
| `--participant-profile` | `NTS_PARTICIPANT_PROFILE` | Profile for the participant account whose missing `Name` tags are filled in. Required |
| `--regions` | | Regions to read; repeat or comma-separate (default: the participant profile's Region) |
| `--vpc-ids` | | Only these VPCs and their subnets; repeat or comma-separate |
| `--check-permissions` | | For each planned tag, call `CreateTags` with `DryRun=True` through the participant to see whether it would be allowed. Writes nothing. Useful because a shared resource's ARN carries the owner's account ID, so participant IAM policies or SCPs scoped to their own account deny the write |
| `--apply` | | Write the planned tags, confirming each resource |
| `-o table\|csv\|json`, `--json` | | Output format (default `table`) |
| `-v` / `-q` | | Debug logging / warnings only (prompts still show) |

## Output

Logs and prompts go to stderr; the rows go to stdout. With `-o table`, the plan is printed before the prompts and the planned resources again afterwards with their results. With CSV or JSON, the rows are printed once at the end.

| Column | Meaning |
|---|---|
| `region`, `type`, `resource_id`, `vpc_id` | The resource (`vpc` or `subnet`) and its VPC. CSV and JSON also have `cidr` |
| `owner`, `target` (CSV, JSON) | Owner account (`OwnerId`), and the participant account that would be tagged |
| `owner_name`, `participant_name` | The `Name` tag each account sees: `(none)` when there's no tag, `""` when it is empty |
| `action` | `set`, or `skip:` with the reason: `name already set`, `name is whitespace`, `names match`, `owner has no name` |
| `permission` | `--check-permissions`: `allowed`, `denied: ...` or `error: ...`. With `--apply`, resources that are denied aren't asked |
| `result` | `--apply`: `tagged`, `declined`, `skipped: ...` (a re-check failed), `error: ...`, `interrupted (check its Name tag)`, `not asked (quit)`, `not asked (denied)` or `not asked (stopped)` |

Exit codes:

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | A Region couldn't be read, a write failed, was skipped by a re-check or was interrupted, or `--check-permissions` found tags that wouldn't be allowed |
| `2` | Bad input, or `--apply` without a terminal |
| `3` | Owner mismatch: a shared resource isn't owned by the `--owner-profile` account, the two accounts disagree on its owner, both profiles are the same account, or the participant profile's account changed during the run. Nothing was changed, or with `--apply`, nothing more after it |

## IAM permissions

Owner profile:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["ec2:DescribeVpcs", "ec2:DescribeSubnets"],
    "Resource": "*"
  }]
}
```

Participant profile. `CreateTags` is needed only for `--apply` and `--check-permissions`. Its resources are in the owner's account:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": ["ec2:DescribeVpcs", "ec2:DescribeSubnets"], "Resource": "*"},
    {
      "Effect": "Allow",
      "Action": "ec2:CreateTags",
      "Resource": ["arn:aws:ec2:*:<OWNER_ACCOUNT>:vpc/*", "arn:aws:ec2:*:<OWNER_ACCOUNT>:subnet/*"],
      "Condition": {"ForAllValues:StringEquals": {"aws:TagKeys": ["Name"]}}
    }
  ]
}
```

## Tests

```bash
cd tools/name_tag_sync
pip install -r requirements-dev.txt
python -m pytest
```

EC2 is an in-memory fake that keeps each account's tags on shared resources separately. No AWS credentials are needed.
