# VPC Endpoint Tools

Tools for running **centralized VPC endpoints**: a hub VPC hosts interface endpoints (private DNS disabled), and a Route 53 private hosted zone (PHZ) per service DNS name (e.g. `ssm.us-east-1.amazonaws.com`) is associated with spoke VPCs, often in other accounts.

The three tools in this suite share the code in `lib/`. This page covers what they have in common. For the other tools in this repository, see the [repository README](../../README.md).

All tools are **read-only**: they never change AWS resources. `phz_assoc` prints the commands for you to review and run.

| Tool | Purpose |
|---|---|
| [`vpce_list`](vpce_list/README.md) | Enumerate VPC endpoints, filter by tag / service / VPC / type / state, optionally correlate with PHZs |
| [`phz_review`](phz_review/README.md) | List PHZs and their VPCs; find PHZs associated with a VPC (`by-vpc`) and VPCs associated with a PHZ (`by-zone`) |
| [`phz_assoc`](phz_assoc/README.md) | Generate AWS CLI commands to associate / disassociate PHZs and VPCs, including cross-account authorizations |

All tools are Python 3.11+ / boto3.

## Install

Set up the shared virtual environment as described in the [repository README](../../README.md#getting-started), or install this suite on its own:

```bash
pip install -r tools/vpce/requirements.txt
cp tools/vpce/.env.example tools/vpce/.env   # optional defaults
```

`.env` is read from this directory, or from the nearest parent directory that has one (such as the repository root). The directory you run a tool from doesn't matter.

## Accounts and credentials

Every tool takes the same account options:

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

Derived profiles are only used for the tools' own read calls. Generated `phz_assoc` scripts include a `--profile` only when you pass one explicitly (see that tool's README).

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

# Which PHZs is this spoke VPC associated with (any owner account)?
python tools/vpce/phz_review/phz_review.py by-vpc --profile spoke \
  --vpc arn:aws:ec2:us-east-1:111111111111:vpc/vpc-0123456789abcdef0

# Which VPCs are associated with (or authorized for) the endpoint PHZs?
python tools/vpce/phz_review/phz_review.py by-zone --profile hub --zone-tag Purpose=vpce

# Generate the cross-account association script (hub owns PHZs, spoke owns VPC)
python tools/vpce/phz_assoc/phz_assoc.py associate \
  --phz-account 222222222222 --phz-profile hub \
  --vpc-account 111111111111 --vpc-profile spoke \
  --zone-tag Purpose=vpce --vpc vpc-0123456789abcdef0 --out spoke.plan.sh
```

## Cross-account association flow

Route 53 needs a three-step handshake when the PHZ and the VPC are in different accounts:

1. **PHZ owner**: `aws route53 create-vpc-association-authorization`
2. **VPC owner**: `aws route53 associate-vpc-with-hosted-zone`
3. **PHZ owner**: `aws route53 delete-vpc-association-authorization` (recommended cleanup; the association remains)

Disassociation can be run by either account (`--disassociate-as vpc|phz`). Route 53 does not allow removing the last VPC from a PHZ, so `phz_assoc` skips that step and tells you why.

## IAM permissions (union of all tools)

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
        "route53:ListHostedZonesByVPC",
        "route53:ListVPCAssociationAuthorizations",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

Add `sts:AssumeRole` on the target role ARNs when using `--role-name`. Whoever runs a generated `phz_assoc` script needs the write permissions listed in [its README](phz_assoc/README.md#iam-permissions).

## Platform Notes

- **macOS**: System PKI truststore used automatically via Security.framework (`truststore`). No extra cert config needed.
- **Windows**: Windows Certificate Store used automatically. Credentials at `%USERPROFILE%\.aws\credentials`. Run scripts with `python tools\vpce\<tool>\<tool>.py`; generated `.sh` plans need Git Bash/WSL, or use `--format json`.
- **Linux**: System CA bundle used via `truststore`. Ensure `ca-certificates` is installed (`apt install ca-certificates` / `yum install ca-certificates`); if it's missing the tools warn and fall back to certifi.

## Development

```bash
pip install -r tools/vpce/requirements-dev.txt
cd tools/vpce && python -m pytest
```

Tests use [moto](https://github.com/getmoto/moto). moto does not implement Route 53 VPC association authorizations, so cross-account planning is covered by unit tests of the planner (`tests/test_phz_assoc_plan.py`), not end-to-end.
