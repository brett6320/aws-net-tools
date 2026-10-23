# aws-vpce-tools

Tools for running **centralized VPC endpoints**: a hub VPC hosts interface endpoints (private DNS disabled), and a Route 53 private hosted zone (PHZ) per service DNS name (e.g. `ssm.us-east-1.amazonaws.com`) is associated with spoke VPCs, often in other accounts.

| Tool | Purpose | Mutates? |
|---|---|---|
| [`tools/vpce_list`](tools/vpce_list/README.md) | Enumerate VPC endpoints, filter by tag / service / VPC / type / state, optionally correlate with PHZs | No |
| [`tools/phz_review`](tools/phz_review/README.md) | List PHZs and their VPCs; find PHZs associated with a VPC (`by-vpc`) and VPCs associated with a PHZ (`by-zone`) | No |
| [`tools/phz_assoc`](tools/phz_assoc/README.md) | Generate AWS CLI commands to associate / disassociate PHZs and VPCs, including cross-account authorizations | Only with `--execute` |

All tools are Python 3.11+ / boto3.

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env   # optional defaults
```

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

If the credentials resolve to a different account than the one requested and no `--role-name` is given, the tool stops with an error instead of querying the wrong account.

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
python tools/vpce_list/vpce_list.py --profile hub --tag Central=true --with-phz

# Which PHZs is this spoke VPC associated with (any owner account)?
python tools/phz_review/phz_review.py by-vpc --profile spoke \
  --vpc arn:aws:ec2:us-east-1:111111111111:vpc/vpc-0123456789abcdef0

# Which VPCs are associated with (or authorized for) the endpoint PHZs?
python tools/phz_review/phz_review.py by-zone --profile hub --zone-tag Purpose=vpce

# Generate the cross-account association script (hub owns PHZs, spoke owns VPC)
python tools/phz_assoc/phz_assoc.py associate \
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
      "Sid": "Read",
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
        "route53:GetChange",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AssociateExecuteOnly",
      "Effect": "Allow",
      "Action": [
        "route53:CreateVPCAssociationAuthorization",
        "route53:DeleteVPCAssociationAuthorization",
        "route53:AssociateVPCWithHostedZone",
        "route53:DisassociateVPCFromHostedZone",
        "ec2:DescribeVpcs"
      ],
      "Resource": "*"
    }
  ]
}
```

Add `sts:AssumeRole` on the target role ARNs when using `--role-name`.

## Platform Notes

- **macOS**: System PKI truststore used automatically via Security.framework (`truststore`). No extra cert config needed.
- **Windows**: Windows Certificate Store used automatically. Credentials at `%USERPROFILE%\.aws\credentials`. Run scripts with `python tools\...\tool.py`; generated `.sh` plans need Git Bash/WSL, or use `--format json`.
- **Linux**: System CA bundle used via `truststore`. Ensure `ca-certificates` is installed (`apt install ca-certificates` / `yum install ca-certificates`); if it's missing the tools warn and fall back to certifi.

## Development

```bash
pip install -r requirements-dev.txt
pytest
```

Tests use [moto](https://github.com/getmoto/moto). moto does not implement Route 53 VPC association authorizations, so cross-account planning is covered by unit tests of the planner (`tests/test_phz_assoc_plan.py`), not end-to-end.
