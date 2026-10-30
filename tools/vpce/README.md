# VPC Endpoint Tools

[![vpce tests](https://github.com/brett6320/aws-net-tools/actions/workflows/tests-vpce.yml/badge.svg?branch=main)](https://github.com/brett6320/aws-net-tools/actions/workflows/tests-vpce.yml) ![Tests](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrett6320%2Faws-net-tools%2Fbadges%2Fvpce-tests.json) ![Coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrett6320%2Faws-net-tools%2Fbadges%2Fvpce-coverage.json) ![Python 3.11 | 3.12 | 3.13](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-3776AB?logo=python&logoColor=white)

Tools for running **centralized VPC endpoints**: a hub VPC hosts interface endpoints (private DNS disabled), and a Route 53 private hosted zone (PHZ) per service DNS name (e.g. `ssm.us-east-1.amazonaws.com`) is associated with spoke VPCs, often in other accounts.

This suite has one tool, `vpce_list`. To review or change PHZ to VPC associations, use the [`phz`](../phz/README.md) suite (`phz_review`, `phz_assoc`), which shares this suite's account options and `VPCE_` environment variables. For the other tools in this repository, see the [repository README](../../README.md).

`vpce_list` is **read-only**: it never changes AWS resources.

| Tool | Purpose |
|---|---|
| [`vpce_list`](vpce_list/README.md) | Enumerate VPC endpoints, filter by tag / service / VPC / type / state, optionally correlate with PHZs |

Python 3.11+ / boto3.

## Install

Set up the shared virtual environment as described in the [repository README](../../README.md#getting-started), or install this suite on its own:

```bash
pip install -r tools/vpce/requirements.txt
cp tools/vpce/.env.example tools/vpce/.env   # optional defaults
```

`.env` is read from this directory, or from the nearest parent directory that has one (such as the repository root). The directory you run a tool from doesn't matter.

## Accounts and credentials

Account options:

| Flag | Env var | Meaning |
|---|---|---|
| `--account` | `VPCE_ACCOUNT` | One account for **both** VPCs and PHZs |
| `--vpc-account` | `VPCE_VPC_ACCOUNT` | Account that owns the VPC(s); overrides `--account` |
| `--phz-account` | `VPCE_PHZ_ACCOUNT` | Account that owns the PHZ(s); overrides `--account` |
| `--profile` | `AWS_PROFILE` | Base credentials for both sides |
| `--vpc-profile` / `--phz-profile` | `VPCE_VPC_PROFILE` / `VPCE_PHZ_PROFILE` | Per-side credentials; fall back to `--profile` |
| `--role-name` | `VPCE_ROLE_NAME` | If the profile's account differs from the requested account, assume `arn:aws:iam::<account>:role/<role-name>` |
| `--external-id` | `VPCE_EXTERNAL_ID` | ExternalId for the assumed role |

### Profile derivation

When an account is known (from `--account` / `--vpc-account` / `--phz-account` or a VPC ARN), the tools find its profile in `~/.aws/config` / `~/.aws/credentials` by matching `sso_account_id`, `aws_account_id`, or the account in `role_arn`. Credentials for an account are resolved in this order:

1. `--vpc-profile` / `--phz-profile`, if given
2. with `--role-name`: assume the role from `--profile` (no derivation)
3. the derived profile:
   - profiles ending in **`-priv`** or **`-cpar`** are never used (override with `VPCE_PROFILE_EXCLUDE_SUFFIXES`, comma-separated)
   - if `--profile` / `AWS_PROFILE` maps to the account, it is kept
   - otherwise, with several candidates, the single read-only one (`-ro`, `-readonly`, `-read-only`) wins
   - still several → error listing them; pass `--vpc-profile` / `--phz-profile`
4. `--profile` / default credential chain

This also covers VPC ARNs that point at other accounts: each account gets its own derived profile. The account behind the credentials is always checked. If it doesn't match the requested account, the tool stops with an error instead of querying the wrong account.

## VPC input

VPCs can be given as IDs or ARNs, repeated or comma-separated:

```
--vpc vpc-0123456789abcdef0
--vpc arn:aws:ec2:us-west-2:111111111111:vpc/vpc-0fedcba9876543210
--vpc vpc-0aaa...,vpc-0bbb...
```

An ARN carries its own region and account. A bare ID uses `--vpc-region` (or `--region`) and `--vpc-account` (or `--account`, or the caller's account). If an ARN's account conflicts with an explicit `--vpc-account`, the tool rejects it.

## Quick examples

```bash
# Endpoints tagged Central=true in the hub account, with matching PHZs
python tools/vpce/vpce_list/vpce_list.py --profile hub --tag Central=true --with-phz

# Then attach the matching PHZs to spoke VPCs with tools/phz/phz_assoc
```

## IAM permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeVpcEndpoints",
        "ec2:DescribeVpcEndpointServices",
        "ec2:DescribeVpcs",
        "route53:ListHostedZones",
        "route53:GetHostedZone",
        "route53:ListTagsForResources",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

Add `sts:AssumeRole` on the target role ARNs when using `--role-name`.

## Platform Notes

- **macOS**: System PKI truststore used automatically via Security.framework (`truststore`). No extra cert config needed.
- **Windows**: Windows Certificate Store used automatically. Credentials at `%USERPROFILE%\.aws\credentials`. Run with `python tools\vpce\vpce_list\vpce_list.py`.
- **Linux**: System CA bundle used via `truststore`. Ensure `ca-certificates` is installed (`apt install ca-certificates` / `yum install ca-certificates`); if it's missing the tools warn and fall back to certifi.

## Development

```bash
pip install -r tools/vpce/requirements-dev.txt
cd tools/vpce && python -m pytest
```

Tests use [moto](https://github.com/getmoto/moto).
