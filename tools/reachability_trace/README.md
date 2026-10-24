# Reachability Trace

CLI for AWS VPC Reachability Analyzer (EC2 Network Insights). Creates paths between any supported
source and destination, runs analyses, prints hop-by-hop summaries, and exports traces to a single
self-contained HTML file with an icon-based path diagram and full component detail.

**Ports are applied at the source.** Source IP, source port range, and destination port range are
sent as `FilterAtSource`, so the packet header is defined where the traffic originates. That header
is checked against the source's outbound security group and network ACL rules, then carried (and
transformed by NAT, load balancers, and so on) hop by hop, so inbound rules downstream see the same
flow. The top-level `SourceIp` and `DestinationPort` fields are never used; the API doesn't allow them
together with `FilterAtSource`.

## Usage

```bash
# Dry-run (default: prints the API requests, makes no changes)
python reachability.py create -s i-0abc... -d i-0def... --dest-port 5432

# Create path + run analysis, wait, export HTML
python reachability.py create --execute -s i-0abc... -d i-0def... \
    --protocol tcp --dest-port 5432 --source-port 1024-65535 --source-ip 10.0.1.15 \
    --name app-to-db --export app-to-db.html

# IP address destination
python reachability.py create --apply -s eni-0abc... --dest-ip 8.8.8.8 -p udp --dest-port 53 --wait

# Re-run an existing path through a specific transit gateway
python reachability.py analyze nip-0123... --execute \
    --filter-in arn:aws:ec2:us-east-1:111122223333:transit-gateway/tgw-0abc... --wait

# Inspect / export
python reachability.py paths
python reachability.py analyses --path-id nip-0123...
python reachability.py show nia-0123...
python reachability.py export nia-0123... nia-0456... -o traces.html --json-out traces.json
python reachability.py export --from-json traces.json -o traces.html   # offline re-render

# Cleanup (dry-run unless --execute)
python reachability.py delete-path nip-0123... --with-analyses --execute
python reachability.py delete-analysis nia-0123... --execute

# Supported types
python reachability.py types
```

### Commands

| Command | Mutates | Description |
|---|---|---|
| `types` | no | List supported source/destination and intermediate types |
| `create` | yes | Create a path, then start an analysis (skip with `--no-analyze`) |
| `analyze PATH_ID` | yes | Start a new analysis on an existing path |
| `paths` | no | List paths (`--json`) |
| `analyses` | no | List analyses, optionally for one path (`--json`) |
| `show ANALYSIS_ID` | no | Print a hop-by-hop summary (`--json` for the raw bundle) |
| `export ID... -o FILE` | no | Write self-contained HTML. `--from-json` re-renders saved bundles |
| `delete-path` / `delete-analysis` | yes | Delete resources |

### Options

| Flag | Description |
|---|---|
| `--execute` / `--apply` | Apply changes (default: dry-run) |
| `--profile NAME` | AWS profile (overrides `AWS_PROFILE`). Never included in exports |
| `--region REGION` | AWS region (overrides `AWS_REGION`; falls back to the profile's region) |
| `-s/--source` | Source ID or ARN (use an ARN for cross-account resources) |
| `-d/--dest` | Destination ID or ARN |
| `--dest-ip` | Destination IPv4 (alone, or to pick one IP on `--dest`) |
| `--source-ip` | Source IPv4, applied at source |
| `-p/--protocol` | `tcp` (default) or `udp` |
| `--dest-port` / `--source-port` | Port or range (`443`, `1024-65535`), applied at source |
| `--name`, `--tag K=V` | Path tags |
| `--filter-in ARN` / `--filter-out ARN` | Include/exclude an intermediate component (repeatable) |
| `--additional-account ID` | Extra account for cross-account analysis (repeatable) |
| `--analysis-name` | Name tag for the analysis |
| `--wait`, `--timeout N` | Wait for the analysis to finish |
| `--export FILE.html`, `--json-out FILE.json` | Wait, then export |
| `--check-permissions` | In dry-run, call the API with `DryRun=True` to check IAM permissions |
| `-v` / `-q` | Debug / warnings-only logging |

### Supported types

| Source / destination | ID prefix |
|---|---|
| EC2 instance | `i-` |
| Internet gateway | `igw-` |
| Network interface | `eni-` |
| Transit gateway | `tgw-` |
| Transit gateway attachment | `tgw-attach-` |
| Virtual private gateway | `vgw-` |
| VPC endpoint service | `vpce-svc-` |
| VPC endpoint | `vpce-` |
| VPC peering connection | `pcx-` |
| IP address (destination only) | `--dest-ip` |

Intermediate components for `--filter-in` / `--filter-out` (ARNs): load balancers, NAT gateways,
Network Firewall firewalls, transit gateways, transit gateway attachments, VPC peering connections.

## HTML export

One `.html` file with no external assets: inline CSS and inline SVG icons, light and dark mode,
print-friendly. Multiple analyses go in one file with a jump bar. For each analysis it shows:

- **Path**: ID/ARN, source and destination (with icons), protocol, filter at source/destination, created date, tags
- **Analysis**: ID/ARN, status, reachable/not-reachable badge, status and warning messages, filter-in/out ARNs,
  additional and suggested accounts, tags
- **Forward and return path diagrams**: one icon card per component with its sequence number, type, ID, name, and a
  short rule/route hint. Click a card to jump to its details
- **Component details**: VPC, subnet, attached-to, source/destination VPC, transit gateway, inbound/outbound packet
  headers, security group rule, network ACL rule, route table route, TGW route and policy entry, ELB listener,
  Network Firewall stateless/stateful rules, additional details, and per-component explanations
- **Explanations**: each explanation code with the AWS description and every field returned. Blocking components
  are outlined in red
- **Alternate path hints** and the **raw API JSON**

The export includes only data returned by the EC2 API. The AWS profile name and credentials are never written.

## Requirements

- Python 3.11+
- AWS credentials configured (profile, env vars, SSO, or IAM role)

## Installation

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
```

## Configuration

Copy `.env.example` to `.env` and fill in values:

| Variable | Default | Description |
|---|---|---|
| `AWS_PROFILE` | (default chain) | AWS profile name |
| `AWS_REGION` | profile region | Target region |
| `RA_WAIT_TIMEOUT` | `600` | Seconds to wait for analyses |

## Platform Notes

- **macOS**: System PKI truststore used automatically via Security.framework. No extra cert config needed.
- **Windows**: System Certificate Store used automatically. Credentials at `%USERPROFILE%\.aws\credentials`.
- **Linux**: System CA bundle used via `truststore`. Ensure `ca-certificates` is installed.

## IAM Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:CreateNetworkInsightsPath",
        "ec2:StartNetworkInsightsAnalysis",
        "ec2:DescribeNetworkInsightsPaths",
        "ec2:DescribeNetworkInsightsAnalyses",
        "ec2:DeleteNetworkInsightsPath",
        "ec2:DeleteNetworkInsightsAnalysis",
        "ec2:CreateTags",
        "ec2:Describe*",
        "elasticloadbalancing:Describe*",
        "network-firewall:Describe*",
        "network-firewall:List*",
        "tiros:CreateQuery",
        "tiros:GetQueryAnswer",
        "tiros:GetQueryExplanation"
      ],
      "Resource": "*"
    }
  ]
}
```

Read-only use (`paths`, `analyses`, `show`, `export`) only needs the `Describe*` actions.
AWS charges for each analysis run. See AWS pricing.

## Output

- Mutating commands log `[DRY-RUN]` with the exact API request JSON unless `--execute`/`--apply` is passed,
  in which case they log `[EXECUTE]`.
- `show`/`--wait` print a hop-by-hop summary to stdout. `--json` prints raw API data.
- Exit codes: `0` success, `1` validation or AWS error, `2` analysis finished with status `failed`.

## Tests

```bash
pip install -r requirements-dev.txt
pytest tests
```

Tests cover input validation, `FilterAtSource` request building, dry-run safety (no API calls), icon
classification, and HTML rendering against the fixtures in `tests/fixtures/`.
