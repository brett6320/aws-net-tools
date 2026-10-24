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

![Reachable trace export](docs/images/reachable-overview.png)

> Screenshots in this README are simulated: they are exports rendered from the synthetic fixtures in
> `tests/fixtures/` (placeholder account `111122223333`), not from a live AWS account.

## Usage

HTML reports are written by default. Each analysis gets its own file under the reports folder,
organized by date and account:

```text
reports/
└── 2026-10-23/                                      # analysis start date (UTC)
    └── 111122223333/                                # account that owns the analysis (from its ARN)
        ├── app-to-db-5432_nia-0fedcba9876543210.html  # <Name tag>_<analysis-id>.html
        └── nia-0ccc000000000ccc3.html                 # no Name tag
```

- The root is `./reports` relative to the current directory. Change it with `--reports-dir` or `RA_REPORTS_DIR`.
- The file name uses the analysis `Name` tag, then the path `Name` tag, then just the analysis ID.
- The account is read from the analysis ARN, never from your local AWS profile. Re-exporting an analysis
  overwrites the same file.
- `create`/`analyze` wait for the analysis to finish and then write the report. `--export FILE` writes to that
  file instead. `--no-report` skips the report and returns as soon as the analysis starts (unless `--wait`
  or `--json-out` is also given).
- `export` without `-o` writes one report per analysis into the reports folder. `-o FILE` writes one combined
  file.
- `reports/` is git-ignored.


```bash
# Dry-run (default: prints the API requests, makes no changes)
python reachability.py create -s i-0abc... -d i-0def... --dest-port 5432

# Create path + run analysis, wait, write HTML report to reports/<date>/<account>/
python reachability.py create --execute -s i-0abc... -d i-0def... \
    --protocol tcp --dest-port 5432 --source-port 1024-65535 --source-ip 10.0.1.15 \
    --name app-to-db

# IP address destination, report written to a specific file instead
python reachability.py create --apply -s eni-0abc... --dest-ip 8.8.8.8 -p udp --dest-port 53 --export dns.html

# Re-run an existing path through a specific transit gateway, no report, don't wait
python reachability.py analyze nip-0123... --execute \
    --filter-in arn:aws:ec2:us-east-1:111122223333:transit-gateway/tgw-0abc... --no-report

# Inspect / export
python reachability.py paths
python reachability.py analyses --path-id nip-0123...
python reachability.py show nia-0123...
python reachability.py export nia-0123... nia-0456...                  # one report each, in reports/
python reachability.py export nia-0123... nia-0456... -o traces.html --json-out traces.json   # one combined file
python reachability.py export --from-json traces.json                  # offline re-render into reports/

# Cleanup (dry-run unless --execute)
python reachability.py delete-path nip-0123... --with-analyses --execute
python reachability.py delete-analysis nia-0123... --execute

# Supported types
python reachability.py types
```

Global options (`--profile`, `--region`, `-v`, `-q`) go **after** the subcommand, for example
`python reachability.py show nia-0123... --profile prod -q`.

Run the script from this directory or by path. It imports the sibling `ra_*.py` modules.

### Example summary output

`show`, and `create`/`analyze` with `--wait`, print a hop-by-hop summary (from `tests/fixtures/`):

```text
Analysis nia-0fedcba9876543210  (path nip-0123456789abcdef0)
  i-0src00000000000a1 -> i-0dst00000000000b2  TCP
  filter@source: src=10.0.1.15:1024-65535 dst=any:5432
  Status: succeeded  Result: REACHABLE
  Forward path:
    1. EC2 instance                 i-0src00000000000a1 (app-server-1)
    2. Network interface            eni-0src0000000000a1
    3. Security group               sg-0app00000000000a1 (app-sg)  [egress All All (0-65535) 10.0.0.0/16]
    4. Network ACL                  acl-0a0000000000000a1  [rule 100 egress ALLOW All All 0.0.0.0/0]
    5. Route table                  rtb-0a0000000000000a1 (app-rt)  [10.0.0.0/16 -> local]
    6. Network ACL                  acl-0b0000000000000b2  [rule 110 ingress ALLOW TCP 5432 10.0.1.0/24]
    7. Security group               sg-0db000000000000b2 (db-sg)  [ingress TCP 5432 10.0.1.0/24]
    8. Network interface            eni-0dst0000000000b2
    9. EC2 instance                 i-0dst00000000000b2 (db-1)
  Return path:
    1. Network interface            eni-0dst0000000000b2
    2. Network ACL                  acl-0b0000000000000b2  [rule 120 egress ALLOW TCP 1024-65535 10.0.1.0/24]
    3. Route table                  rtb-0b0000000000000b2 (db-rt)  [10.0.0.0/16 -> local]
    4. Network ACL                  acl-0a0000000000000a1  [rule 100 ingress ALLOW All All 0.0.0.0/0]
    5. Network interface            eni-0src0000000000a1

Analysis nia-0bad000000000bad1  (path nip-0aaaabbbbccccdddd)
  eni-0src0000000000a1 -> tgw-attach-0abc123def4567890  TCP
  filter@source: src=any:All dst=any:443
  Status: succeeded  Result: NOT REACHABLE
  Warning: Some components could not be fully analyzed.
  Explanation: SUBNET_ACL_RESTRICTION acl-0a0000000000000a1 egress
  Explanation: NO_ROUTE_TO_DESTINATION rtb-0a0000000000000a1
```

### Commands

| Command | Mutates | Description |
|---|---|---|
| `types` | no | List supported source/destination and intermediate types |
| `create` | yes | Create a path, start an analysis, wait, write the report (`--no-analyze` creates the path only) |
| `analyze PATH_ID` | yes | Start a new analysis on an existing path, wait, write the report |
| `paths` | no | List paths (`--json`) |
| `analyses` | no | List analyses (newest first), optionally for one path (`--path-id`, `--json`) |
| `show ANALYSIS_ID` | no | Print a hop-by-hop summary (`--json` for the raw bundle) |
| `export ID...` | no | Write one HTML report per analysis to the reports folder, or one combined file with `-o FILE`. `--from-json` re-renders saved bundles offline. `--wait` waits for running analyses first |
| `delete-path` / `delete-analysis` | yes | Delete resources. `delete-path --with-analyses` also deletes the path's analyses |

### Options

| Flag | Description |
|---|---|
| `--execute` / `--apply` | Apply changes (default: dry-run) |
| `--profile NAME` | AWS profile (overrides `AWS_PROFILE`). Never included in exports |
| `--region REGION` | AWS region (default `AWS_REGION`, then `AWS_DEFAULT_REGION`, then the profile's region; errors if none) |
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
| `--wait`, `--timeout N` | Wait for the analysis to finish (`create`/`analyze` default `RA_WAIT_TIMEOUT` or 600s; `export --timeout` default 600s) |
| `--reports-dir DIR` | Reports root (default `RA_REPORTS_DIR` or `./reports`). Files go to `DIR/<YYYY-MM-DD>/<account-id>/` |
| `--export FILE.html` | `create`/`analyze`: write the report to this file instead of the reports folder |
| `--no-report` | `create`/`analyze`: skip the HTML report, and don't wait unless `--wait`/`--json-out` is given |
| `-o/--output FILE.html` | `export`: write one combined file instead of per-analysis reports |
| `--json-out FILE.json` | Also save the path+analysis JSON bundle(s) (`create`/`analyze` wait first) |
| `--title TEXT` | Page title for the HTML export (default "Reachability Trace") |
| `--check-permissions` | In dry-run, call the API with `DryRun=True` to check IAM permissions (`create`/`analyze`) |
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

| Light | Dark |
|---|---|
| ![Light mode](docs/images/reachable-overview.png) | ![Dark mode](docs/images/reachable-overview-dark.png) |

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

Return path: shown whenever AWS returns return-path components. Each hop shows the reversed packet
header and the rules that admit the reply traffic, such as the ephemeral-port NACL rule below:

![Return path diagram and component details](docs/images/return-path.png)

Not reachable: explanation codes with the AWS description and every field returned.

![Not reachable trace with explanations](docs/images/not-reachable.png)

Internet gateway → Network Load Balancer → instance, showing per-hop packet headers and address translation:

![IGW to NLB path](docs/images/igw-nlb-path.png)

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

Copy `.env.example` to `.env` and fill in values. `.env` is searched for starting in this directory and
then its parent directories. CLI flags override `.env` values.

| Variable | Default | Description |
|---|---|---|
| `AWS_PROFILE` | (default chain) | AWS profile name |
| `AWS_REGION` | profile region | Target region |
| `AWS_DEFAULT_REGION` | — | Region fallback when `AWS_REGION` is unset |
| `RA_WAIT_TIMEOUT` | `600` | Default `--timeout` for `create` and `analyze` (not `export`) |
| `RA_REPORTS_DIR` | `reports` | Root folder for HTML reports |

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
  in which case they log `[EXECUTE]`. Dry-runs make no API calls, except `--check-permissions` and
  `delete-path --with-analyses`, which lists the path's analyses.
- Logs go to stderr. Results (summaries, listings, `--json`) go to stdout, so `--json` output can be piped.
- `show` and finished `create`/`analyze` runs print a hop-by-hop summary to stdout. `--json` prints raw API data.
- Each written report is logged as `Wrote HTML export <path>`.
- Dry-runs of `create`/`analyze` log where the report would go (`reports/<date>/<account>/<analysis>.html`).
- Exit codes: `0` success, `1` validation, credential, lookup, timeout, or AWS error, `2` analysis finished
  with status `failed` (argparse usage errors also exit `2`).

## Tests

```bash
pip install -r requirements-dev.txt
pytest tests
```

Tests cover input validation, `FilterAtSource` request building, dry-run safety (no API calls), icon
classification, and HTML rendering against the fixtures in `tests/fixtures/`.

### Regenerating the screenshots

The images in `docs/images/` are headless-Chrome captures of fixture exports, with the theme forced through
the page's `data-theme` attribute:

```bash
python reachability.py export --from-json tests/fixtures/reachable.json -o /tmp/r.html --title "Reachability trace"
sed 's/<html lang="en">/<html lang="en" data-theme="light">/' /tmp/r.html > /tmp/r-light.html   # or data-theme="dark"
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new --hide-scrollbars \
  --force-device-scale-factor=1 --window-size=1300,1000 \
  --screenshot=docs/images/reachable-overview.png file:///tmp/r-light.html
```

`return-path.png` is a crop of a full-page capture of the same export (`--window-size=1300,<page height>`), cropped
with `sips --cropOffset <y> 0 -c 1100 1300` to start at the Return path card.
