# vpce_list

Enumerates VPC endpoints (EC2 `DescribeVpcEndpoints`) across one or more regions with tag, service, VPC, type and state filters. With `--with-phz`, interface endpoints are matched to private hosted zones whose name matches the endpoint service's private DNS name, which is how the centralized-endpoint pattern is usually wired. Read-only.

## Usage

```bash
python vpce_list.py [options]
```

### Options

| Flag | Description |
|---|---|
| `--tag KEY[=V1,V2]` | Include filter. Repeat to AND; values within one flag are OR'd; `*`/`?` wildcards OK; `KEY` alone = key exists |
| `--exclude-tag KEY[=V1,V2]` | Drop endpoints matching this filter |
| `--vpc ID\|ARN` | Limit to VPC(s). An ARN's region is added to the scan |
| `--service PATTERN` | `ssm` matches `com.amazonaws.<region>.ssm` (not `ssmmessages`); globs like `*ssm*` also work |
| `--type TYPE` | `Interface`, `Gateway`, `GatewayLoadBalancer`, `Resource`, `ServiceNetwork` |
| `--state STATE` | `available`, `pending`, `rejected`, ... |
| `--regions r1,r2` | Regions to scan (default `--region`) |
| `--with-phz` | Add `service_dns` and `phz` columns (PHZs looked up in the PHZ account) |
| `--wide` | Add owner, subnets, DNS name, tags columns |
| `-o table\|json\|csv`, `--json` | Output format (default table) |
| `--account`, `--vpc-account`, `--phz-account`, `--profile`, `--vpc-profile`, `--phz-profile`, `--role-name` | See the [suite README](../README.md#accounts-and-credentials). Profiles are derived from account IDs when not given. Endpoints are read from the VPC-side account |
| `--region` | Default region |
| `-v` / `-q` | Debug / warnings-only logging |

### Examples

```bash
# All available interface endpoints tagged Central=true, prod or stage
python vpce_list.py --profile hub --tag Central=true --tag Env=prod,stage --type Interface --state available

# Everything except endpoints tagged Temporary, across two regions, as CSV
python vpce_list.py --regions us-east-1,us-west-2 --exclude-tag Temporary -o csv > endpoints.csv

# Endpoints in a VPC given by ARN, assuming a role into that account
python vpce_list.py --profile org-admin --role-name NetworkReadOnly \
  --vpc arn:aws:ec2:us-east-1:222222222222:vpc/vpc-0123456789abcdef0

# Correlate with PHZs that live in a separate DNS account
python vpce_list.py --vpc-profile hub --phz-profile dns --with-phz
```

## Requirements

- Python 3.11+
- AWS credentials configured (profile, env vars, or IAM role)

## Installation

```bash
pip install -r requirements.txt
```

## Configuration

See [`.env.example`](../.env.example): `AWS_PROFILE`, `AWS_REGION`, `VPCE_ACCOUNT`, `VPCE_VPC_ACCOUNT`, `VPCE_PHZ_ACCOUNT`, `VPCE_VPC_PROFILE`, `VPCE_PHZ_PROFILE`, `VPCE_ROLE_NAME`, `VPCE_EXTERNAL_ID`.

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
        "ec2:DescribeVpcEndpoints",
        "ec2:DescribeVpcEndpointServices",
        "route53:ListHostedZones",
        "route53:GetHostedZone",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

The Route 53 actions and `ec2:DescribeVpcEndpointServices` are only needed with `--with-phz`.

## Output

Table (default), CSV or JSON on stdout. JSON always includes every field (subnets, DNS name, tags). Logs go to stderr, so `--json` output can be piped straight to `jq`.
