# AWS Network Tools

[![CodeQL](https://github.com/brett6320/aws-net-tools/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/brett6320/aws-net-tools/actions/workflows/codeql.yml) [![Tests](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrett6320%2Faws-net-tools%2Fbadges%2Ftotal-tests.json)](#tests-and-ci) [![Coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrett6320%2Faws-net-tools%2Fbadges%2Ftotal-coverage.json)](#tests-and-ci) ![Python 3.11 | 3.12 | 3.13](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-3776AB?logo=python&logoColor=white) [![License: custom](https://img.shields.io/badge/license-custom-lightgrey)](LICENSE) ![Dependabot](https://img.shields.io/badge/dependabot-enabled-025E8C?logo=dependabot)

Command-line tools for investigating AWS networks: tracing paths, finding who owns an address, showing which
Direct Connect path AWS prefers, backing up Direct Connect configuration, reviewing firewall policy, security groups, NACLs and prefix lists, and running centralized VPC endpoints. All but the
`vpce` tools write self-contained HTML reports you can share or attach to a ticket.

## Tools

**Paths, routes and addresses**

| Tool | AWS service | What it does |
|---|---|---|
| [`reachability_trace`](tools/reachability_trace/) | VPC Reachability Analyzer | Create and run traces between any supported source and destination, including across accounts, with ports applied at the source. Reports show every hop and mark exactly where a blocked path breaks |
| [`ipam_locate`](tools/ipam_locate/) | VPC IPAM | Find the account, Region, VPC, subnet and resource behind an IP or CIDR, or the most specific parent pool CIDR, with the full IPAM hierarchy |
| [`dx_route`](tools/dx_route/) | Direct Connect | `show ip bgp` / `show ip route` in Cisco IOS syntax for any prefix: which VIF AWS uses toward on-premises, every active and inactive path with its AS path, communities and local preference, and why each path lost |
| [`dx_backup`](tools/dx_backup/) | Direct Connect | Back up every connection, LAG, VIF, BGP peer, Direct Connect gateway association and allowed prefix, plus each VIF's advertised and accepted routes. Diff backups against each other or live, and generate the AWS CLI commands to restore one (never run). BGP auth keys are stored only as fingerprints |

**Firewall policy, security groups, NACLs and prefix lists**

| Tool | AWS service | What it does |
|---|---|---|
| [`firewall`](tools/firewall/) (suite of 10) | Firewall Manager, EC2 | Read-only reviews of Firewall Manager policies (rule parity, NACL policy vs live NACLs, compliance, policy snapshots and drift), NACL shadowed rules, security group inventory, access gaps, migration checks and quotas, and prefix list capacity and drift |
| [`sg_effect`](tools/sg_effect/) | EC2 security groups | For one security group: every resource that uses it, each resource's net inbound and outbound access across all of its groups, and what the resource would lose if the group were removed. The HTML report adds a rule removal scenario. Flags rules that are redundant everywhere |
| [`pl_review`](tools/pl_review/) | EC2 managed prefix lists | Before growing a managed prefix list: every security group that references it, in any account, and whether the proposed `MaxEntries` would push any of them over the rule quota |

**Centralized VPC endpoints**

| Tool | AWS service | What it does |
|---|---|---|
| [`vpce`](tools/vpce/) (suite of 3) | VPC endpoints, Route 53 | List VPC endpoints with their private hosted zones (`vpce_list`), review PHZ to VPC associations (`phz_review`), and generate the AWS CLI commands to associate or disassociate PHZs and VPCs across accounts (`phz_assoc`) |

The tools work well together. For example:
- Use `ipam_locate` to find who owns an unknown address, then `reachability_trace` to check whether traffic
  can reach it.
- Use `dx_route` to see which Direct Connect VIF AWS uses for an on-premises prefix, and why, and
  `dx_backup` to see what changed in the Direct Connect configuration since the last backup.
- Use `sg_effect` before deleting a security group rule, to see which resources would actually lose access.
- Use `firewall/prefix_list_audit` to find prefix lists near capacity, then `pl_review` to check whether one
  can grow.

| Reachability trace | IPAM locate |
|---|---|
| ![Reachability trace report](tools/reachability_trace/docs/images/reachable-overview.png) | ![IPAM locate report](tools/ipam_locate/docs/images/located-instance.png) |
| **Security group access tester** (`firewall/sg_rule_inventory`) | **Prefix list review** (`pl_review`) |
| ![Security group rule inventory access tester](tools/firewall/docs/images/sg-rule-inventory-tester.png) | ![Prefix list review report](tools/pl_review/docs/images/report.png) |

> The screenshots are simulated. They are rendered from synthetic test fixtures and samples (made-up account
> IDs and resource IDs).

## Getting started

Requires Python 3.11+ and AWS credentials.

```bash
git clone <repository-url> && cd <repository-folder>
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt                       # shared runtime dependencies for every tool
pip install -r tools/vpce/requirements-dev.txt        # optional: pytest and moto, for running the tests

python tools/ipam_locate/ipam_locate.py 10.1.1.25 --profile network-admin --region us-east-1
python tools/reachability_trace/reachability.py types
python tools/dx_route/dx_route.py show ip bgp summary --region us-east-1
python tools/dx_backup/dx_backup.py backup --region us-east-1
python tools/firewall/sg_quota_audit.py --help
```

Every tool and suite also has its own `requirements.txt`, so it can be installed on its own. Each README
covers usage, options, output, configuration and IAM permissions.

## Shared conventions

| Area | Convention |
|---|---|
| **Safety** | Nothing changes AWS resources except `reachability_trace`'s `create`, `analyze` and `delete-*` commands. Those are dry-run by default: they log `[DRY-RUN]` with the exact request and need `--execute` or `--apply`. `phz_assoc` and `dx_backup restore-plan` only print the commands for you to review and run |
| **Credentials** | `--profile` (or `AWS_PROFILE`) and `--region` (or `AWS_REGION`) select the account and Region; otherwise the standard boto3 credential chain is used. The `firewall`, `vpce`, `pl_review` and `dx_route` tools can also find each account's profile in your local AWS config by account ID. Profiles ending in `-priv` or `-cpar` are never picked automatically, and `pl_review` only uses profiles whose names start with `hcli-` |
| **Configuration** | Each tool or suite reads a `.env` file (see its `.env.example`) from its own directory, or from the nearest parent directory that has one (such as the repository root). The directory you run a tool from doesn't matter. CLI flags override `.env`, which overrides defaults |
| **TLS** | The OS certificate store is used through `truststore` (macOS, Windows, Linux), so corporate TLS inspection works without extra configuration |

Where each tool writes, and what it expects:

| Tool | Output | Variable prefix | Exit codes |
|---|---|---|---|
| `reachability_trace` | HTML in `reports/<date>/<account>/` | `RA_` | 0 ok, 1 error, 2 analysis failed |
| `ipam_locate` | HTML in `reports/<date>/<account>/` | `IPAM_` | 0 ok, 1 error |
| `dx_route` | stdout: Cisco-style output; HTML in `reports/<date>/<scope>/` | `DXR_` | 0 ok, 1 error, 2 no route |
| `dx_backup` | JSON backups in `backups/<account>/<timestamp>/`; diff HTML in `reports/<date>/<account>/`; restore plan: shell script | `DXB_` | 0 ok, 1 error, 2 changes found |
| `firewall/*` | HTML, CSV and JSON in `reports/<tool>/<date>/` | `FMM_`, `SG_`, `PL_` | 0 nothing found, 1 findings, 2 fatal |
| `sg_effect` | stdout: text or JSON; HTML in `reports/<date>/<account>/` | `SGE_` | 0 ok, 1 error, 2 a `--remove-rule` scenario loses access |
| `pl_review` | HTML, JSON, Markdown and CSV in `reports/<date>/` | `PL_REVIEW_` | 0 ok, 1 at risk, 2 fatal, 3 partly evaluated |
| `vpce/*` | stdout: table, JSON or CSV (`phz_assoc`: shell script or JSON plan) | `VPCE_` | 0 ok, 1 error, 2 bad input |

The `reports/` and `backups/` roots are relative to the current directory and are git-ignored.

## Tests and CI

Each tool and suite has its own GitHub Actions workflow. It runs the tests on Python 3.11, 3.12 and 3.13
whenever that tool's folder changes, and on every pull request that touches it. Each run's summary page lists
the test count, failures, duration and coverage for every Python version. CodeQL scans the code on every
pull request and weekly, and Dependabot proposes dependency updates weekly.

| Tool | Status | Tests | Coverage |
|---|---|---|---|
| [`reachability_trace`](tools/reachability_trace/) | [![reachability_trace tests](https://github.com/brett6320/aws-net-tools/actions/workflows/tests-reachability_trace.yml/badge.svg?branch=main)](https://github.com/brett6320/aws-net-tools/actions/workflows/tests-reachability_trace.yml) | ![Tests](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrett6320%2Faws-net-tools%2Fbadges%2Freachability_trace-tests.json) | ![Coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrett6320%2Faws-net-tools%2Fbadges%2Freachability_trace-coverage.json) |
| [`ipam_locate`](tools/ipam_locate/) | [![ipam_locate tests](https://github.com/brett6320/aws-net-tools/actions/workflows/tests-ipam_locate.yml/badge.svg?branch=main)](https://github.com/brett6320/aws-net-tools/actions/workflows/tests-ipam_locate.yml) | ![Tests](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrett6320%2Faws-net-tools%2Fbadges%2Fipam_locate-tests.json) | ![Coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrett6320%2Faws-net-tools%2Fbadges%2Fipam_locate-coverage.json) |
| [`dx_route`](tools/dx_route/) | [![dx_route tests](https://github.com/brett6320/aws-net-tools/actions/workflows/tests-dx_route.yml/badge.svg?branch=main)](https://github.com/brett6320/aws-net-tools/actions/workflows/tests-dx_route.yml) | ![Tests](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrett6320%2Faws-net-tools%2Fbadges%2Fdx_route-tests.json) | ![Coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrett6320%2Faws-net-tools%2Fbadges%2Fdx_route-coverage.json) |
| [`dx_backup`](tools/dx_backup/) | [![dx_backup tests](https://github.com/brett6320/aws-net-tools/actions/workflows/tests-dx_backup.yml/badge.svg?branch=main)](https://github.com/brett6320/aws-net-tools/actions/workflows/tests-dx_backup.yml) | ![Tests](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrett6320%2Faws-net-tools%2Fbadges%2Fdx_backup-tests.json) | ![Coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrett6320%2Faws-net-tools%2Fbadges%2Fdx_backup-coverage.json) |
| [`firewall`](tools/firewall/) | [![firewall tests](https://github.com/brett6320/aws-net-tools/actions/workflows/tests-firewall.yml/badge.svg?branch=main)](https://github.com/brett6320/aws-net-tools/actions/workflows/tests-firewall.yml) | ![Tests](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrett6320%2Faws-net-tools%2Fbadges%2Ffirewall-tests.json) | ![Coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrett6320%2Faws-net-tools%2Fbadges%2Ffirewall-coverage.json) |
| [`sg_effect`](tools/sg_effect/) | [![sg_effect tests](https://github.com/brett6320/aws-net-tools/actions/workflows/tests-sg_effect.yml/badge.svg?branch=main)](https://github.com/brett6320/aws-net-tools/actions/workflows/tests-sg_effect.yml) | ![Tests](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrett6320%2Faws-net-tools%2Fbadges%2Fsg_effect-tests.json) | ![Coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrett6320%2Faws-net-tools%2Fbadges%2Fsg_effect-coverage.json) |
| [`pl_review`](tools/pl_review/) | [![pl_review tests](https://github.com/brett6320/aws-net-tools/actions/workflows/tests-pl_review.yml/badge.svg?branch=main)](https://github.com/brett6320/aws-net-tools/actions/workflows/tests-pl_review.yml) | ![Tests](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrett6320%2Faws-net-tools%2Fbadges%2Fpl_review-tests.json) | ![Coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrett6320%2Faws-net-tools%2Fbadges%2Fpl_review-coverage.json) |
| [`vpce`](tools/vpce/) | [![vpce tests](https://github.com/brett6320/aws-net-tools/actions/workflows/tests-vpce.yml/badge.svg?branch=main)](https://github.com/brett6320/aws-net-tools/actions/workflows/tests-vpce.yml) | ![Tests](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrett6320%2Faws-net-tools%2Fbadges%2Fvpce-tests.json) | ![Coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrett6320%2Faws-net-tools%2Fbadges%2Fvpce-coverage.json) |

The test and coverage badges show the latest run on `main` on Python 3.13. The workflow publishes them to
the `badges` branch, so no external service is involved. The totals at the top add up the test counts and
average the coverage across tools.

To run the tests locally, from the tool or suite directory:

```bash
pip install -r requirements-dev.txt
python -m pytest                 # add --cov=. for a coverage report
```

They use fixtures, in-memory fakes or moto, so no AWS credentials are needed.

## Repository layout

```text
tools/
├── <tool>/                # a single tool
│   ├── <tool>.py          # CLI entry point
│   ├── *.py               # core logic and rendering (some tools are a single file)
│   ├── requirements.txt   # runtime dependencies (requirements-dev.txt adds test tools)
│   ├── .env.example
│   ├── README.md
│   ├── docs/              # optional: screenshots, and the script and fixtures/samples that render them
│   └── tests/
└── <suite>/               # several tools that share code
    ├── lib/               # shared code
    ├── README.md          # what the suite's tools have in common, with links to each tool's page
    ├── .env.example
    ├── requirements.txt
    └── ...                # the tools, as <tool>.py files (firewall) or <tool>/ folders (vpce)
```

New tools go under `tools/` with the same layout and conventions, plus a row in the tables above.

`firewall` and `vpce` were merged in from the `aws-firewall-tools` and `aws-vpce-tools` repositories with their
history, so `git log --follow` works on their files. `pl_review` came from a standalone project with no version
history.

## License

Free to use, modify and redistribute. All copies and derivative works must credit the author. Commercial use
while supporting clients (consulting, contracting, managed services and similar) requires a separate written
license from the author. See [LICENSE](LICENSE) for the full terms.
