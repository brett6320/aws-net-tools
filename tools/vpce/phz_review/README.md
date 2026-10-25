# phz_review

Reviews Route 53 private hosted zones and their VPC associations, in both directions. Read-only.

| Subcommand | Answers | Runs against |
|---|---|---|
| `zones` | What PHZs does the PHZ account have, and how many VPCs is each associated with? | PHZ account |
| `by-vpc` | Which PHZs (owned by **any** account) is this VPC associated with? | VPC owner account (`ListHostedZonesByVPC`) |
| `by-zone` | Which VPCs is this PHZ associated with, and which have pending cross-account authorizations? | PHZ account |

## Usage

```bash
python phz_review.py zones   [--zone ID] [--zone-name GLOB] [--zone-tag K=V] [--include-public] [--authorizations] [--wide]
python phz_review.py by-vpc  --vpc ID|ARN [--vpc ID|ARN ...] [--vpc-region REGION]
python phz_review.py by-zone [--zone ID] [--zone-name GLOB] [--zone-tag K=V] [--no-authorizations] [--resolve-owners]
```

### Options

| Flag | Description |
|---|---|
| `--zone ID\|ARN` | Hosted zone ID, `/hostedzone/ID`, or ARN (repeatable) |
| `--zone-name GLOB` | Zone name glob, e.g. `'*.us-east-1.amazonaws.com'` |
| `--zone-tag KEY[=V1,V2]` / `--exclude-zone-tag` | Zone tag filters (same syntax as `vpce_list --tag`) |
| `--vpc ID\|ARN` | `by-vpc`: VPC(s) to look up; ARNs may span accounts (each is queried as its own owner, via `--role-name` if needed) |
| `--authorizations` | `zones`: add pending cross-account authorizations |
| `--no-authorizations` | `by-zone`: skip listing authorizations |
| `--resolve-owners` | `by-zone`: look up VPC owner accounts from the PHZ account (works for its own and RAM-shared VPCs; others show `external/unknown`) |
| `--wide` | `zones`: add VPC list, comment, tags |
| `-o table\|json\|csv`, `--json` | Output format |
| account/profile flags | See the [root README](../../README.md#accounts-and-credentials) |

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

# Reverse: which VPCs are on the SSM PHZ?
python phz_review.py by-zone --profile hub --zone-name ssm.us-east-1.amazonaws.com --resolve-owners
```

## Requirements / Installation / Configuration

Python 3.11+, `pip install -r requirements.txt`. See [`.env.example`](../../.env.example).

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

`ListHostedZonesByVPC` (and `ec2:DescribeVpcs`) are needed in the VPC owner account; the rest in the PHZ account.

## Output

Table, CSV or JSON on stdout; logs on stderr.
