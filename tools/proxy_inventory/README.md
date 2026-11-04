# proxy_inventory

[![proxy_inventory tests](https://github.com/brett6320/aws-net-tools/actions/workflows/tests-proxy_inventory.yml/badge.svg?branch=main)](https://github.com/brett6320/aws-net-tools/actions/workflows/tests-proxy_inventory.yml) ![Tests](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrett6320%2Faws-net-tools%2Fbadges%2Fproxy_inventory-tests.json) ![Coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrett6320%2Faws-net-tools%2Fbadges%2Fproxy_inventory-coverage.json) ![Python 3.11 | 3.12 | 3.13](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-3776AB?logo=python&logoColor=white)

Shows which applications (by their **AppCatID** tag) live in which VPC, so you know whom to contact to test
before you change a VPC. It lists every resource in each VPC that could send traffic through an egress proxy,
with all of its tags.

1. **VPCs**: read from the local VPC owner map that [`ou_vpcs`](../ou_vpcs/README.md) writes
   (`~/.cache/aws-net-tools/vpc-owners.json`). Run `ou_vpcs` first, then narrow the VPCs with `--ou`, `--account`, `--exclude-account`, `--regions` or `--vpc`.
2. **Account → profile**: the same as `ou_vpcs`. It uses the profile in `~/.aws/config` that maps to the account ID, never one ending in
   **`-priv`** or **`-cpar`**, and checks it with `sts:GetCallerIdentity`.
3. **Resources**: each VPC owner account is read for the resource types below, limited to its VPCs. Every network
   interface in those VPCs is listed too.
4. **Shared VPCs**: interfaces owned by other accounts (other than excluded types) show that those accounts run workloads in the VPC (RAM-shared subnets).
   Those participant accounts are then read with their own profiles, limited to the shared VPCs. Turn this off with `--no-participants`.

The tool is **read-only**: it never changes AWS resources. Python 3.11+ / boto3.

## What counts as proxy-capable

| Included | How it's found |
|---|---|
| EC2 instances (also EKS, ECS, EMR and Batch nodes) | `DescribeInstances` by VPC (including secondary interfaces), pending / running / stopping / stopped |
| Lambda functions | `ListFunctions`, functions whose VPC config is in the VPC |
| ECS services and standalone tasks | `awsvpc` networking (Fargate or EC2). Bridge or host-mode tasks are covered by their EC2 hosts |
| WorkSpaces | `DescribeWorkspaces`, by subnet |
| AppStream fleets | `DescribeFleets`, by VPC config |
| Glue jobs (opt-in: `--include glue`) | jobs using a Glue connection in the VPC (connections are listed with `HidePassword`) |
| MWAA environments | `GetEnvironment` network config |
| App Runner services (opt-in: `--include apprunner`) | services whose egress goes through a VPC connector in the VPC |

Excluded, because they don't originate traffic that a proxy would carry: VPC endpoints, NAT and transit gateways, load
balancers, RDS, ElastiCache, Redshift, OpenSearch, EFS, FSx, MSK, MQ, DMS, Route 53 Resolver endpoints, the EKS control plane
and Directory Service.

**Unattributed interfaces**: interfaces in the VPCs that belong to no listed resource and to no excluded type are shown
in their own table, with a likely service guessed from their description (EKS pods, CodeBuild, SageMaker, workloads in a
participant account that couldn't be read ...). This makes sure nothing is silently missed.

**Opt-in services**: Glue and App Runner are read only with `--include glue,apprunner`, because finding their VPCs
takes `glue:GetConnections` and `apprunner:ListVpcConnectors`. Without them, their interfaces are listed as unattributed
(likely service `Glue` / `App Runner`), and the report's header says which services weren't read.

Services that aren't offered in a Region (e.g. App Runner in `ca-central-1`) are skipped without a call.

## Install

Set up the shared virtual environment as described in the [repository README](../../README.md#getting-started), or install this tool on its own:

```bash
pip install -r tools/proxy_inventory/requirements.txt
cp tools/proxy_inventory/.env.example tools/proxy_inventory/.env   # optional defaults
```

## Usage

```bash
# Fill the VPC owner map, then inventory every VPC in it
python tools/ou_vpcs/ou_vpcs.py --profile org-mgmt-ro --ou ou-ab12-11111111
python tools/proxy_inventory/proxy_inventory.py

# Only the Prod OU and the OUs below it, in us-east-1
python tools/proxy_inventory/proxy_inventory.py --ou Root/Prod --regions us-east-1

# Every VPC except those of two accounts
python tools/proxy_inventory/proxy_inventory.py --exclude-account 111111111111,222222222222

# Also read Glue jobs and App Runner services
python tools/proxy_inventory/proxy_inventory.py --include glue,apprunner

# One VPC, written to a chosen file, plus JSON with every tag
python tools/proxy_inventory/proxy_inventory.py --vpc vpc-0abc12345def67890 --out vpc.html --json-out vpc.json
```

| Flag | Env var | Meaning |
|---|---|---|
| `--cache FILE` | `PROXY_INV_CACHE`, then `OU_VPCS_CACHE` | VPC owner map (default `~/.cache/aws-net-tools/vpc-owners.json`, `%LOCALAPPDATA%\aws-net-tools\` on Windows) |
| `--ou OU` | `PROXY_INV_OU` | An OU ID (exactly that OU) or an OU path such as `Root/Prod` (that OU and every OU below it); repeat or comma-separate |
| `--account ID` | | Only VPCs owned by these accounts |
| `--exclude-account ID` | `PROXY_INV_EXCLUDE_ACCOUNTS` | Never read these accounts: neither their VPCs nor as shared-VPC participants (their interfaces in other VPCs show as unattributed); repeat or comma-separate |
| `--regions` | `PROXY_INV_REGIONS` | Only VPCs in these Regions |
| `--vpc VPC_ID` | | Only these VPCs |
| `--profile` | `AWS_PROFILE` | Preferred profile when several map to an account |
| `--account-profile ACCOUNT=PROFILE` | | Profile for an account when none or several map to it; repeat or comma-separate |
| `--key-tag TAG` | `PROXY_INV_KEY_TAG` | The application tag, matched in any case (default `AppCatID`) |
| `--include SERVICE` | `PROXY_INV_INCLUDE` | Also read these opt-in services: `glue`, `apprunner`; repeat or comma-separate |
| `--no-participants` | | Don't read participant accounts of shared VPCs |
| `--workers N` | `PROXY_INV_WORKERS` | Accounts read in parallel (default 4) |
| `--reports-dir DIR` | `PROXY_INV_REPORTS_DIR` | Reports root (default `./reports`) |
| `--out FILE` | | Write the report here instead, plus a timestamped copy next to it |
| `--json-out FILE` | | Also write every row, with all tags as a dict, as JSON |
| `--title` | | Report title |
| `-v` / `-q` | | Debug logging / warnings only |

Profiles for each account are chosen in the same way as in [`ou_vpcs`](../ou_vpcs/README.md#profiles-for-member-accounts).
`PROXY_INV_PROFILE_EXCLUDE_SUFFIXES` overrides `-priv,-cpar`.

## Output

The report is written to `reports/<scope>/proxy-inventory.html` and overwritten on every run, with a timestamped copy
in `reports/<YYYY-MM-DD>/<scope>/proxy-inventory_<HHMMSS>.html`. The scope is the account ID when all VPCs have one
owner, otherwise `multi-account`. The report's path is printed on stdout, and logs go to stderr.

The report has these tables:

| Table | Contents |
|---|---|
| **AppCatIDs by VPC** | One row per AppCatID per VPC: resource count, types, accounts and IDs. Shows whom to contact before changing a VPC. `(missing)` gathers the resources without the tag. A summary lists the VPCs per AppCatID |
| **Resources** | Every resource: AppCatID and where it came from, type, ID, name, state, account, VPC, subnets, private IPs, details and **all tags**. A tag-key filter finds resources carrying a given tag |
| **VPCs read** | Every selected VPC: the VPC's own AppCatID tag, resource count, AppCatIDs, unattributed interfaces, and `gone` for VPCs no longer in AWS |
| **Unattributed network interfaces** | See above |
| **Not read** | Accounts, Regions and services that couldn't be read. A denied service (e.g. WorkSpaces blocked by an SCP) is listed but doesn't count as incomplete, because its interfaces still show as unattributed. Any other error (throttling, an unexpected response) does count |

The AppCatID tag is matched in any case (`AppCatID`, `appcatid` ...). An ECS service or task without the tag takes its
cluster's, shown as `inherited from ECS cluster`.

Every table sorts (click a header, shift-click for a secondary sort), filters (search box, dropdowns, or click a cell) and
downloads the filtered rows as CSV. **Download HTML (this view)** saves a copy of the whole report that opens on the
current filters, search and sort of every table. The copy keeps all the data, so the recipient can clear the filters.
Filters are also kept in the URL, so a view can be bookmarked.

Exit codes: `0` everything read, `2` bad input (no owner map, no VPC matches, unknown `--include` service), `3` some accounts, Regions, participant
accounts or services couldn't be read for a reason other than access denied (the report covers the rest).

`-v` shows this tool's debug logging only: AWS SDK logging stays at warnings, because it would print whole API
responses (Lambda environment variables, for example).

## Configuration

Copy `.env.example` to `.env` (in this folder or any parent). CLI flags override `.env`, which overrides the defaults.

## IAM permissions

Read-only, in every account read:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "sts:GetCallerIdentity",
      "ec2:DescribeInstances", "ec2:DescribeNetworkInterfaces", "ec2:DescribeSubnets", "ec2:DescribeVpcs",
      "lambda:ListFunctions", "lambda:ListTags",
      "ecs:ListClusters", "ecs:DescribeClusters", "ecs:ListServices", "ecs:DescribeServices", "ecs:ListTasks", "ecs:DescribeTasks",
      "workspaces:DescribeWorkspaces", "workspaces:DescribeTags",
      "appstream:DescribeFleets", "appstream:ListTagsForResource",
      "airflow:ListEnvironments", "airflow:GetEnvironment"
    ],
    "Resource": "*"
  }]
}
```

Only with `--include glue`: `glue:GetConnections`, `glue:GetJobs`, `glue:GetTags`. Only with `--include apprunner`:
`apprunner:ListVpcConnectors`, `apprunner:ListServices`, `apprunner:DescribeService`, `apprunner:ListTagsForResource`.

A missing service permission only leaves that service out, and the report's "Not read" table lists it.

## Platform notes

- **macOS**: the system trust store is used automatically through Security.framework. No extra certificate configuration is needed.
- **Windows**: the Windows Certificate Store is used automatically. Credentials are in `%USERPROFILE%\.aws\credentials`.
- **Linux**: the system CA bundle is used through `truststore`. Make sure `ca-certificates` is installed.

## Tests

```bash
pip install -r tools/proxy_inventory/requirements-dev.txt
cd tools/proxy_inventory && python -m pytest
```

The tests use `moto` for EC2, Lambda and ECS, and stub clients for WorkSpaces, AppStream, Glue, MWAA and App Runner.
They never read your AWS config or your VPC owner map.
