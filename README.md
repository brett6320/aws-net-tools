# AWS Network Tools

Command-line tools for investigating AWS networks: tracing paths, finding who owns an address, and
producing self-contained HTML reports you can share or attach to a ticket.

| Tool | AWS service | What it does |
|---|---|---|
| [`reachability_trace`](tools/reachability_trace/) | VPC Reachability Analyzer | Create and run traces between any supported source and destination, including across accounts, with ports applied at the source. Reports show every hop and mark exactly where a blocked path breaks |
| [`ipam_locate`](tools/ipam_locate/) | VPC IPAM | Find the account, Region, VPC, subnet and resource behind an IP or CIDR, or the most specific parent pool CIDR, with the full IPAM hierarchy |

The tools work well together. Use `ipam_locate` to find who owns an unknown address, then
`reachability_trace` to check whether traffic can reach it.

| Reachability trace | IPAM locate |
|---|---|
| ![Reachability trace report](tools/reachability_trace/docs/images/reachable-overview.png) | ![IPAM locate report](tools/ipam_locate/docs/images/located-instance.png) |

> The screenshots are simulated. They are rendered from synthetic test fixtures (made-up account IDs and
> resource IDs).

## Getting started

```bash
git clone <repository-url> && cd <repository-folder>
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt                       # shared runtime dependencies for every tool
pip install -r tools/reachability_trace/requirements-dev.txt   # optional: pytest, for running tests

python tools/ipam_locate/ipam_locate.py 10.1.1.25 --profile network-admin --region us-east-1
python tools/reachability_trace/reachability.py types
```

Each tool also has its own `requirements.txt`, so it can be installed on its own. Each tool's README
covers usage, options, its report, configuration and IAM permissions.

## Shared conventions

Every tool follows the same rules, so what you learn in one applies to the others.

| Area | Convention |
|---|---|
| **Safety** | Commands that change AWS resources are dry-run by default. They log `[DRY-RUN]` with the exact request and need `--execute` or `--apply`. Read-only commands and tools never change anything |
| **Credentials** | `--profile` (or `AWS_PROFILE`) and `--region` select the account and Region; otherwise the standard boto3 credential chain is used (env vars, SSO, IAM role). The profile name and credentials are **never** written to reports or JSON |
| **Configuration** | Each tool reads a `.env` file (see its `.env.example`), searched for in the current directory, then its parents. CLI flags override `.env`, which overrides defaults. Tool-specific variables are prefixed (`RA_*`, `IPAM_*`) |
| **Reports** | Self-contained HTML (inline CSS/SVG, no external resources), written by default to `reports/<YYYY-MM-DD>/<account-id>/`. Change the root with `--reports-dir`, or write one file with `-o`/`--export`. `reports/` is git-ignored |
| **Themes** | Dark by default. `--theme light\|auto` (or the tool's `*_THEME` variable), plus an in-page toggle. Printing always uses the light theme |
| **Offline re-rendering** | `--json-out` saves the raw API data; `--from-json` re-renders it later with no AWS calls |
| **Output** | Logs go to stderr; summaries, listings and `--json` go to stdout, so they can be piped. `-v` debug, `-q` warnings only |
| **TLS** | The OS certificate store is used through `truststore` (macOS, Windows, Linux), so corporate TLS inspection works without extra configuration |
| **Tests** | `python -m pytest tests` in each tool directory. Tests use fixtures or in-memory fakes; no AWS credentials are needed |

## Repository layout

```text
tools/
└── <tool>/
    ├── <tool>.py          # CLI entry point
    ├── *.py               # core logic (API calls, matching) and HTML rendering
    ├── requirements.txt   # runtime dependencies (requirements-dev.txt adds pytest)
    ├── .env.example
    ├── README.md
    ├── docs/              # make_screenshots.py and images/ for the README
    └── tests/             # pytest suite and fixtures/
```

New tools go under `tools/` with the same layout and conventions, plus a row in the table above.

## License

Free to use, modify and redistribute. All copies and derivative works must credit the author. Commercial use
while supporting clients (consulting, contracting, managed services and similar) requires a separate written
license from the author. See [LICENSE](LICENSE) for the full terms.
