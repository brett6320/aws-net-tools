# Prefix List Review

Reviews every security group (SG) associated with an AWS Managed Prefix List (PL), including SGs in other accounts that consume the PL via AWS RAM sharing. For each SG it computes the weighted rule count per direction, expanding every referenced prefix list to its `MaxEntries` (that is how AWS charges PL references against the SG rule quota), and reports whether growing the target PL to a proposed length would push any SG over the rule limit. Read-only; it never mutates anything.

## How it works

1. Discovers local profiles matching the naming policy: start with `hcli-`, do not end with `-priv` or `-cpar`.
2. Finds the profile whose account owns the PL (or uses `--profile`). Sessions are created just in time: one `DescribeManagedPrefixLists` call reveals `OwnerId`, then the owner's profile is looked up without touching the network.
3. Pulls `get_managed_prefix_list_associations` from the owner account to list every associated SG and its owning account.
4. Maps each owning account to a valid profile, resolved lazily and only for accounts that actually appear: memory → persisted cache → `~/.aws/config` (`sso_account_id`, or the account in `role_arn`) → `sts:GetCallerIdentity` as last resort. Profiles for accounts with no associated SGs are never opened.
5. Weighs each rule: plain CIDR / SG reference = 1; customer-managed prefix list reference = that PL's `MaxEntries`; AWS-managed prefix list reference = its [documented weight](https://docs.aws.amazon.com/vpc/latest/userguide/working-with-aws-managed-prefix-lists.html) (S3 = 1, DynamoDB = 1, CloudFront = 55, ...). Unknown lists with no `MaxEntries` fall back to current entry count with a warning. The target PL is re-weighed at `--proposed-length`.
6. Flags any direction whose proposed weight exceeds `--limit`.

## Usage

```bash
python tools/pl_review/pl_review.py --pl pl-0123456789abcdef0 --proposed-length 150
python tools/pl_review/pl_review.py --pl pl-0123456789abcdef0 --profile hcli-network-ro --proposed-length 150 --limit 100
python tools/pl_review/pl_review.py --pl pl-0123456789abcdef0 --json --no-write
```

Python API (all kwargs):

```python
from pl_review import review_prefix_list
report = review_prefix_list(pl="pl-0123...", profile="hcli-network-ro", proposed_length=150, limit=100)
print(report.at_risk_count)
```

### Options

| Flag | Description |
|---|---|
| `--pl ID` | Managed prefix list id (required) |
| `--profile NAME` | Profile that owns/sees the PL; auto-discovered if omitted. Must match naming policy |
| `--proposed-length N` | Proposed `MaxEntries` for the PL (default: current value) |
| `--limit N` | Per-direction SG rule quota (default 100) |
| `--region REGION` | Region of the PL and SGs (default `us-east-1`) |
| `--profiles A B ...` | Restrict scan to these profiles |
| `--out-dir DIR` | Report root (default `reports`) |
| `--formats LIST` | Comma-separated formats to write: `json,md,csv` (default all) |
| `--json` | Print JSON instead of table |
| `--no-write` | Skip writing the report file |
| `--cache-path FILE` | Persist metadata cache to this file (default: in-memory only) |
| `--cache-ttl SECS` | Cache TTL, default 7 days; `0` never expires |
| `--no-cache` | Bypass and do not write the cache |
| `-v` / `--debug` | Debug logging: every API call with start/end + elapsed, progress counters, SSO token activity |
| `-q` | Warnings only |

Exit code: `0` no SG at risk, `1` at least one SG would exceed the limit, `2` fatal AWS error, `3` no SG at risk but some could not be evaluated.

Authorization failures are non-fatal per account: if a profile is denied `DescribeSecurityGroups` / `DescribeSecurityGroupRules`, that account's SGs appear as error rows (`not evaluated`), the remaining accounts are still analyzed, and the reports are still written. Only `GetManagedPrefixListAssociations` being denied on the owner profile is fatal, since nothing can be discovered without it.

## Output

Reports are organized by date and written in three formats by default:

```
<out-dir>/<YYYY-MM-DD>/<pl-id>_<HHMMSS>.json   # full structured report
<out-dir>/<YYYY-MM-DD>/<pl-id>_<HHMMSS>.md     # summary header + table, at-risk statuses bolded
<out-dir>/<YYYY-MM-DD>/<pl-id>_<HHMMSS>.csv    # one row per SG per direction (error SGs = one row)
```

Select a subset with `--formats json,csv` or `PL_REVIEW_FORMATS`. The table on stdout is sorted with at-risk SGs first.

Columns: `RULES` raw rule count, `NOW` current weighted count, `PROP` weighted count at the proposed length, `ROOM` remaining headroom under the limit, `STATUS` one of `ok`, `OVER NOW`, `EXCEEDS`.

Accounts that own associated SGs but have no valid local profile are listed under `accounts_without_profile`, and their SGs appear with an error row.

## Firewall Manager (FMM) security groups

SGs replicated by AWS Firewall Manager are detected by the `FMManaged` / `FMPolicyId` tags or the `FMManagedSecurityGroup<policy>` name. They are marked `[FM]` on stdout, carry `fm_managed` / `fm_policy_id` columns in CSV, Markdown and JSON, and are rolled up per policy (`fm_policies` in JSON, "Firewall Manager policies" table in Markdown): replica count, accounts, at-risk count, and the highest proposed weight seen in any replica. Replicas of one policy share the same rules, so one at-risk replica usually means the whole policy needs the quota raised or the rules trimmed.

## Cache

Constructs that are globally or regionally unique are cached in memory for the run. Pass `--cache-path FILE` (or set `PL_REVIEW_CACHE_PATH`) to persist the cache as JSON so repeat runs against frequently used prefix lists skip redundant API calls. A persisted cache must not be committed: keep it under `.cache/` or outside the repo (the repository `.gitignore` covers `.cache/` and `*cache*.json`).

| Key | Scope | Cached |
|---|---|---|
| `account:<profile>` | global | account id from `sts:GetCallerIdentity` |
| `pl:<region>:<pl-id>` | regional | name, owner, `MaxEntries`, address family, state |
| `sg:<region>:<sg-id>` | regional | name, VPC, owner |

Never cached: SG rules, PL entries, PL associations, and the target PL itself (its `MaxEntries` is the subject under review, so it is always fetched fresh). Other referenced PLs use the cached `MaxEntries`; pass `--no-cache` or lower `--cache-ttl` if those lists are being resized too.

## Testing

```bash
pip install -r tools/pl_review/requirements-dev.txt
cd tools/pl_review && PYTHONPATH=. python tests/test_pl_review.py
```

The test is a plain script (it doesn't run under pytest).

Uses `moto`; `get_managed_prefix_list_associations` is stubbed because moto does not implement it.

## Requirements

- Python 3.11+
- `pip install -r requirements.txt`, or the shared virtual environment described in the [repository README](../../README.md#getting-started)
- Copy `.env.example` to `.env` if you want defaults for region/limit/output dir. `.env` is read from this tool's directory, or from the nearest parent directory that has one (such as the repository root).

## IAM Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "sts:GetCallerIdentity",
      "ec2:DescribeManagedPrefixLists",
      "ec2:GetManagedPrefixListEntries",
      "ec2:GetManagedPrefixListAssociations",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSecurityGroupRules"
    ],
    "Resource": "*"
  }]
}
```

`GetManagedPrefixListAssociations` only returns cross-account associations when run from the PL owner account.

## Platform Notes

- **macOS**: System PKI truststore used automatically via Security.framework.
- **Windows**: System Certificate Store used automatically. Credentials at `%USERPROFILE%\.aws\credentials`.
- **Linux**: System CA bundle used via `truststore`. Ensure `ca-certificates` is installed.
