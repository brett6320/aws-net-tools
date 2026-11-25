"""Copy Name tags from the owner of a shared VPC or subnet to the participant account's view of it.

When a VPC's subnets are shared through RAM, the participant account sees the VPC and those
subnets, but not the owner's tags: each account's tags on a shared resource are its own. This
module reads the VPCs and subnets both accounts can see and plans to copy the owner's ``Name``
tag to the participant only where the participant has no ``Name`` tag or an empty one.

The owner of each resource is the ``OwnerId`` EC2 reports, never the profile it was read with.
Safety rules, enforced here and re-checked immediately before every write:

* every resource the two accounts share must be owned by the ``--owner-profile`` account; if one is
  owned by any other account (the participant or a third account sharing with both), nothing is
  changed and :class:`OwnerMismatch` is raised;
* never tag a resource in the account that owns it (writes only ever go through the participant);
* never change a ``Name`` tag that has a value (only a missing tag or exactly ``""``);
* only ever write the single ``Name`` tag, on one resource at a time, with the value the user saw.
"""
from __future__ import annotations

import logging
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Iterator

from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

log = logging.getLogger("name_tag_sync")

BOTO_CONFIG = Config(retries={"max_attempts": 5, "mode": "adaptive"})
NAME = "Name"

ACCOUNT_RE = re.compile(r"^\d{12}$")
REGION_RE = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-\d$")
VPC_RE = re.compile(r"^vpc-[0-9a-f]{8,17}$")

# Plan actions
SET = "set"
SKIP_POPULATED = "skip: name already set"
SKIP_WHITESPACE = "skip: name is whitespace"
SKIP_SAME = "skip: names match"
SKIP_NO_SOURCE = "skip: owner has no name"


class SafetyError(RuntimeError):
    """A write would break a safety rule; nothing was written for this resource."""


class OwnerMismatch(SafetyError):
    """A shared resource isn't owned by the --owner-profile account. The run stops; nothing more is written."""


# --------------------------------------------------------------------------- input


def split_csv(values: Iterable[str] | None) -> list[str]:
    out: list[str] = []
    for raw in values or []:
        for item in raw.split(","):
            if item.strip() and item.strip() not in out:
                out.append(item.strip())
    return out


def check_regions(regions: list[str]) -> list[str]:
    for r in regions:
        if not REGION_RE.match(r):
            raise ValueError(f"--regions: '{r}' is not a Region name")
    return regions


def check_vpc_ids(vpc_ids: list[str]) -> list[str]:
    for v in vpc_ids:
        if not VPC_RE.match(v):
            raise ValueError(f"--vpc-ids: '{v}' is not a VPC ID")
    return vpc_ids


# --------------------------------------------------------------------------- helpers


def _error(e: Exception) -> str:
    if isinstance(e, ClientError):
        err = e.response.get("Error", {})
        return f"{err.get('Code')}: {err.get('Message')}"
    return str(e)


def _code(e: Exception) -> str:
    return e.response.get("Error", {}).get("Code", "") if isinstance(e, ClientError) else ""


def _pages(client: Any, op: str, key: str, **kw: Any) -> Iterator[dict[str, Any]]:
    for page in client.get_paginator(op).paginate(**kw):
        yield from page.get(key) or []


def name_tag(tags: Iterable[dict[str, str]] | None) -> str | None:
    """The Name tag's value, or None when there is no Name tag (``""`` is an empty tag, not a missing one)."""
    for t in tags or []:
        if t.get("Key") == NAME:
            return t.get("Value", "")
    return None


def is_unset(value: str | None) -> bool:
    """True only for a missing Name tag or an empty one. Whitespace counts as a value, so it is left alone."""
    return value is None or value == ""


def _safe_char(ch: str) -> str:
    # Cc: control (ANSI escapes, CR/LF); Cf: format (bidi overrides, zero-width); Zl/Zp: line/paragraph separators
    if unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp"):
        return f"\\x{ord(ch):02x}" if ord(ch) < 0x100 else f"\\u{ord(ch):04x}"
    return ch


def show(value: str | None) -> str:
    """A tag value made safe for the terminal: control, format (bidi, zero-width) and line-separator
    characters are shown escaped. Only for display; the original value is what gets written.
    """
    if value is None:
        return "(none)"
    if value == "":
        return '""'
    text = "".join(_safe_char(c) for c in value)
    return f'"{text}"' if text != text.strip() else text


# --------------------------------------------------------------------------- accounts


@dataclass
class Account:
    """One side of the pair: the profile it was given as, the account it authenticates as, and its session."""
    label: str  # "owner" or "participant", as given on the command line
    profile: str
    account: str
    session: Any


def caller_account(session: Any, region: str | None = None) -> str:
    acct = str(session.client("sts", region_name=region, config=BOTO_CONFIG).get_caller_identity()["Account"])
    if not ACCOUNT_RE.match(acct):
        raise ValueError(f"unexpected account ID {acct!r}")
    return acct


def identify(label: str, profile: str, session: Any) -> Account:
    return Account(label, profile, caller_account(session), session)


# --------------------------------------------------------------------------- read


@dataclass(frozen=True)
class View:
    """A VPC or subnet as one account sees it."""
    kind: str  # "vpc" or "subnet"
    resource_id: str
    vpc_id: str
    owner: str  # OwnerId reported by EC2
    name: str | None  # this account's Name tag (None when missing)
    cidr: str = ""


def read_views(session: Any, region: str, vpc_ids: list[str] | None = None) -> dict[str, View]:
    """Every VPC and subnet one account can see in one Region, by resource ID."""
    ec2 = session.client("ec2", region_name=region, config=BOTO_CONFIG)
    kw = {"Filters": [{"Name": "vpc-id", "Values": vpc_ids}]} if vpc_ids else {}
    out: dict[str, View] = {}
    for v in _pages(ec2, "describe_vpcs", "Vpcs", **kw):
        out[v["VpcId"]] = View("vpc", v["VpcId"], v["VpcId"], str(v.get("OwnerId", "")), name_tag(v.get("Tags")),
                               v.get("CidrBlock", ""))
    for s in _pages(ec2, "describe_subnets", "Subnets", **kw):
        out[s["SubnetId"]] = View("subnet", s["SubnetId"], s.get("VpcId", ""), str(s.get("OwnerId", "")),
                                  name_tag(s.get("Tags")), s.get("CidrBlock", ""))
    return out


# --------------------------------------------------------------------------- plan


@dataclass
class Item:
    region: str
    kind: str
    resource_id: str
    vpc_id: str
    cidr: str
    owner: str  # actual owner (OwnerId)
    target: str  # participant account whose tag would be written
    source_name: str | None
    target_name: str | None
    action: str
    permission: str = ""  # --check-permissions: "allowed", "denied: ...", "error: ..."
    result: str = ""  # --apply

    def row(self) -> dict[str, Any]:
        return {"region": self.region, "type": self.kind, "resource_id": self.resource_id, "vpc_id": self.vpc_id,
                "cidr": self.cidr, "owner": self.owner, "target": self.target, "owner_name": self.source_name,
                "participant_name": self.target_name, "action": self.action,
                "permission": self.permission, "result": self.result}


def decide(source: str | None, target: str | None) -> str:
    if not is_unset(target):
        if target == source:
            return SKIP_SAME
        return SKIP_WHITESPACE if not target.strip() else SKIP_POPULATED
    return SKIP_NO_SOURCE if is_unset(source) else SET


def plan_region(region: str, owner: Account, o_views: dict[str, View], participant: Account,
                p_views: dict[str, View]) -> list[Item]:
    """Resources both accounts can see, and what to do with each.

    Raises OwnerMismatch when one of them isn't owned by the owner account (owned by the participant,
    or by a third account that shares it with both), or when the two accounts disagree on who owns it.
    """
    items: list[Item] = []
    for rid in sorted(set(o_views) & set(p_views), key=lambda r: (o_views[r].vpc_id, o_views[r].kind != "vpc", r)):
        vo, vp = o_views[rid], p_views[rid]
        if vo.owner != vp.owner:
            raise OwnerMismatch(f"{region} {rid}: owner account sees owner {vo.owner}, participant sees {vp.owner}")
        if vo.owner == participant.account:
            raise OwnerMismatch(
                f"{region} {rid} is owned by {participant.account} (--participant-profile {participant.profile}), "
                f"not {owner.account} (--owner-profile {owner.profile}); nothing changed")
        if vo.owner != owner.account:
            raise OwnerMismatch(
                f"{region} {rid} is owned by {vo.owner}, not {owner.account} (--owner-profile {owner.profile}); "
                "nothing changed (use --vpc-ids to leave out VPCs another account shares with both)")
        items.append(Item(region, vo.kind, rid, vo.vpc_id, vo.cidr, vo.owner, participant.account, vo.name, vp.name,
                          decide(vo.name, vp.name)))
    return items


def build_plan(owner: Account, participant: Account, regions: list[str], vpc_ids: list[str] | None = None,
               reader: Callable[[Any, str, list[str] | None], dict[str, View]] = read_views
               ) -> tuple[list[Item], list[str]]:
    """The plan for every Region, and the Regions that couldn't be read. Raises OwnerMismatch."""
    if owner.account == participant.account:
        raise OwnerMismatch(f"--owner-profile {owner.profile} and --participant-profile {participant.profile} "
                            f"are both account {owner.account}")
    items: list[Item] = []
    errors: list[str] = []
    for region in regions:
        try:
            o_views = reader(owner.session, region, vpc_ids)
            p_views = reader(participant.session, region, vpc_ids)
        except (ClientError, BotoCoreError) as e:
            log.warning("Can't read %s: %s", region, _error(e))
            errors.append(f"{region}: {_error(e)}")
            continue
        found = plan_region(region, owner, o_views, participant, p_views)
        log.info("%s: %d shared VPC(s)/subnet(s), %d to tag", region, len(found), sum(i.action == SET for i in found))
        items.extend(found)
    return items, errors


# --------------------------------------------------------------------------- write


def _describe_one(session: Any, item: Item) -> tuple[str, str | None]:
    """(OwnerId, Name tag) of the resource as this session's account sees it right now."""
    ec2 = session.client("ec2", region_name=item.region, config=BOTO_CONFIG)
    if item.kind == "vpc":
        found = ec2.describe_vpcs(VpcIds=[item.resource_id]).get("Vpcs") or []
    else:
        found = ec2.describe_subnets(SubnetIds=[item.resource_id]).get("Subnets") or []
    if len(found) != 1:
        raise SafetyError(f"{item.resource_id} is no longer visible")
    return str(found[0].get("OwnerId", "")), name_tag(found[0].get("Tags"))


def _check_item(item: Item, owner: Account, participant: Account) -> None:
    """Static rules for an item about to be written. Raises SafetyError / OwnerMismatch."""
    if item.action != SET:
        raise SafetyError(f"{item.resource_id}: not planned for tagging ({item.action})")
    if item.owner != owner.account or item.target != participant.account:
        raise OwnerMismatch(f"{item.resource_id}: planned with owner {item.owner} -> {item.target}, "
                            f"not {owner.account} -> {participant.account}")
    if participant.account == item.owner:
        raise OwnerMismatch(f"{item.resource_id}: {participant.account} owns it; owner tags are never changed")
    if is_unset(item.source_name):
        raise SafetyError(f"{item.resource_id}: no owner Name to copy")


def recheck(item: Item, owner: Account, participant: Account) -> Any:
    """Re-read everything live just before a write and return the participant's EC2 client.

    Raises OwnerMismatch when the owner or identities changed, SafetyError when the item no longer
    qualifies (participant Name now set, or owner Name changed from what was shown).
    """
    _check_item(item, owner, participant)
    if (actual := caller_account(participant.session, item.region)) != participant.account:
        raise OwnerMismatch(f"--participant-profile {participant.profile} now authenticates as {actual}, "
                            f"not {participant.account}")
    p_owner, p_name = _describe_one(participant.session, item)
    o_owner, o_name = _describe_one(owner.session, item)
    for seen in (p_owner, o_owner):
        if seen != owner.account or seen == participant.account:
            raise OwnerMismatch(f"{item.resource_id}: owner is now {seen}, not {owner.account}; nothing changed")
    if not is_unset(p_name):
        raise SafetyError(f"{item.resource_id}: participant Name is now {show(p_name)}; not changed")
    if o_name != item.source_name:
        raise SafetyError(f"{item.resource_id}: owner Name changed to {show(o_name)} since it was shown; not changed")
    return participant.session.client("ec2", region_name=item.region, config=BOTO_CONFIG)


def apply_item(item: Item, owner: Account, participant: Account) -> None:
    """Write the owner's Name to the participant's view of one resource, after re-checking every rule.

    There is no conditional tagging in EC2, so a change made in the moment between the re-check and
    the write can't be detected. Raises SafetyError / OwnerMismatch (nothing written) or ClientError.
    """
    ec2 = recheck(item, owner, participant)
    ec2.create_tags(Resources=[item.resource_id], Tags=[{"Key": NAME, "Value": item.source_name}])


def check_permission(item: Item, owner: Account, participant: Account) -> str:
    """CreateTags with DryRun=True through the participant: "allowed", "denied: ..." or "error: ...". Writes nothing."""
    _check_item(item, owner, participant)
    ec2 = participant.session.client("ec2", region_name=item.region, config=BOTO_CONFIG)
    try:
        ec2.create_tags(Resources=[item.resource_id], Tags=[{"Key": NAME, "Value": item.source_name}], DryRun=True)
    except ClientError as e:
        if _code(e) == "DryRunOperation":
            return "allowed"
        if _code(e) in ("UnauthorizedOperation", "AccessDenied", "AccessDeniedException"):
            return f"denied: {_code(e)}"
        return f"error: {_error(e)}"
    except BotoCoreError as e:
        return f"error: {_error(e)}"
    return "error: DryRun call returned without DryRunOperation"
