"""Account attribution for paths, analyses, and path components.

Pure helpers (no AWS calls) shared by the CLI and the HTML exporter. Account IDs
come only from ARNs and fields returned by the EC2 API.
"""
from __future__ import annotations

from typing import Any, Iterable

ROLE_OWNER = "Analysis owner"
ROLE_SOURCE = "Source"
ROLE_DEST = "Destination"
ROLE_ADDITIONAL = "Additional (requested)"
ROLE_SUGGESTED = "Suggested by AWS"
ROLE_FILTER = "Filter component"
ROLE_EXPLANATION = "In explanations"
ROLE_ORDER = [ROLE_OWNER, ROLE_SOURCE, ROLE_DEST, ROLE_ADDITIONAL, ROLE_SUGGESTED, ROLE_FILTER, ROLE_EXPLANATION]


def arn_account(arn: str | None) -> str | None:
    """Return the 12-digit account ID from an ARN, or None."""
    if not arn or not arn.startswith("arn:"):
        return None
    parts = arn.split(":", 5)
    if len(parts) == 6 and parts[4].isdigit():
        return parts[4]
    return None


def path_owner(path: dict[str, Any], analysis: dict[str, Any] | None = None) -> str | None:
    analysis = analysis or {}
    return arn_account(analysis.get("NetworkInsightsAnalysisArn")) or arn_account(path.get("NetworkInsightsPathArn"))


def source_account(path: dict[str, Any]) -> str | None:
    return arn_account(path.get("SourceArn")) or arn_account(path.get("Source"))


def destination_account(path: dict[str, Any]) -> str | None:
    return arn_account(path.get("DestinationArn")) or arn_account(path.get("Destination"))


def component_account(pc: dict[str, Any]) -> str | None:
    """Account that owns a path component: its own ARN, else its VPC/subnet/attachment."""
    for key in ("Component", "AttachedTo", "Subnet", "Vpc"):
        acct = arn_account((pc.get(key) or {}).get("Arn"))
        if acct:
            return acct
    return None


def related_accounts(path: dict[str, Any], extra_arns: Iterable[str] | None = None) -> list[str]:
    """Accounts referenced by the path's endpoints and any filter ARNs, excluding the path owner.

    These are the accounts Reachability Analyzer needs in AdditionalAccounts to
    describe resources it can't see from the owner account.
    """
    owner = path_owner(path)
    found: list[str] = []
    for arn in [path.get("SourceArn"), path.get("DestinationArn"), *(extra_arns or [])]:
        acct = arn_account(arn)
        if acct and acct != owner and acct not in found:
            found.append(acct)
    return found


def account_summary(path: dict[str, Any], analysis: dict[str, Any]) -> dict[str, Any]:
    """Summarize which accounts take part in a path/analysis and in what role.

    Returns {"owner", "source", "destination", "cross_account", "accounts"}, where
    "accounts" maps account ID -> {"roles": [..], "forward": n, "return": n}, in
    first-seen order (owner, source, destination, then path order).
    """
    accounts: dict[str, dict[str, Any]] = {}

    def add(acct: str | None, role: str | None = None) -> None:
        if not acct:
            return
        entry = accounts.setdefault(acct, {"roles": [], "forward": 0, "return": 0})
        if role and role not in entry["roles"]:
            entry["roles"].append(role)

    owner = path_owner(path, analysis)
    src = source_account(path)
    dst = destination_account(path)
    add(owner, ROLE_OWNER)
    add(src, ROLE_SOURCE)
    add(dst, ROLE_DEST)
    for direction, key in (("forward", "ForwardPathComponents"), ("return", "ReturnPathComponents")):
        for pc in analysis.get(key) or []:
            acct = component_account(pc)
            add(acct)
            if acct:
                accounts[acct][direction] += 1
    for acct in analysis.get("AdditionalAccounts") or []:
        add(acct, ROLE_ADDITIONAL)
    for acct in analysis.get("SuggestedAccounts") or []:
        add(acct, ROLE_SUGGESTED)
    for arn in (analysis.get("FilterInArns") or []) + (analysis.get("FilterOutArns") or []):
        add(arn_account(arn), ROLE_FILTER)
    for x in analysis.get("Explanations") or []:
        add(x.get("ComponentAccount") or arn_account((x.get("Component") or {}).get("Arn")), ROLE_EXPLANATION)

    for entry in accounts.values():
        entry["roles"].sort(key=ROLE_ORDER.index)

    # Cross-account: the owner, endpoints, and traversed components span more than one
    # account. Accounts that were only requested or suggested don't count.
    involved = {a for a in (owner, src, dst) if a} | {a for a, e in accounts.items() if e["forward"] or e["return"]}
    return {
        "owner": owner,
        "source": src,
        "destination": dst,
        "cross_account": len(involved) > 1,
        "accounts": accounts,
    }
