"""Collection for sg_effect: one security group, everything that uses it, and every
group on those resources.

collect() reads:

  * the target security group;
  * every network interface (ENI) that has it, and who owns each one (an EC2
    instance, a load balancer, a Lambda function, an RDS database, a VPC endpoint...);
  * every other security group on those ENIs, and all of their rules;
  * the security groups whose rules reference the target group (they grant access to
    or from its members), their rules, and the resources that use them;
  * the entries of every prefix list those rules use, and the names of referenced
    groups and prefix lists.

The result is a JSON-serializable *bundle*, so a saved run re-analyzes offline. The
AWS profile is never written into it.
"""
from __future__ import annotations

import datetime as dt
import logging
import re
from typing import Iterable

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

log = logging.getLogger("sg_effect")

CHUNK = 200          # filter values per call


class ValidationError(ValueError):
    pass


def get_session(profile: str | None, region: str | None) -> boto3.Session:
    return boto3.Session(profile_name=profile, region_name=region)


def get_client(service: str, session: boto3.Session, region: str | None = None):
    config = Config(retries={"max_attempts": 5, "mode": "adaptive"})
    return session.client(service, region_name=region, config=config)


def _code(e: ClientError) -> str:
    return e.response.get("Error", {}).get("Code", "Error")


def _chunks(items: list, n: int = CHUNK) -> Iterable[list]:
    for i in range(0, len(items), n):
        yield items[i:i + n]


def _paginate(ec2, op: str, key: str, **params) -> list[dict]:
    return [x for page in ec2.get_paginator(op).paginate(**params) for x in page.get(key) or []]


def tag(tags: list[dict] | None, key: str = "Name") -> str | None:
    return next((t.get("Value") for t in tags or [] if t.get("Key") == key), None)


# ---------- who owns an ENI ----------

_DESC = [
    (re.compile(r"^ELB app/([^/]+)/"), "Application Load Balancer"),
    (re.compile(r"^ELB net/([^/]+)/"), "Network Load Balancer"),
    (re.compile(r"^ELB gwy/([^/]+)/"), "Gateway Load Balancer"),
    (re.compile(r"^ELB (\S+)$"), "Classic Load Balancer"),
    (re.compile(r"^AWS Lambda VPC ENI-(.+)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
     "Lambda function"),
    (re.compile(r"^AWS Lambda VPC ENI-(.+)$"), "Lambda function"),
    (re.compile(r"^VPC Endpoint Interface (vpce-[0-9a-f]+)"), "VPC endpoint"),
    (re.compile(r"^EFS mount target for (fs-[0-9a-f]+)"), "EFS file system"),
    (re.compile(r"^arn:aws[\w-]*:ecs:[^:]+:\d+:attachment/(\S+)"), "ECS task"),
    (re.compile(r"^Amazon EKS (\S+)"), "EKS cluster"),
    (re.compile(r"^ElastiCache (\S+)"), "ElastiCache"),
    (re.compile(r"^RDSNetworkInterface"), "RDS"),
    (re.compile(r"^DMSNetworkInterface"), "DMS"),
    (re.compile(r"^Interface for NAT Gateway (nat-[0-9a-f]+)"), "NAT gateway"),
    (re.compile(r"^Network Interface for Transit Gateway Attachment (tgw-attach-[0-9a-f]+)"),
     "Transit gateway attachment"),
    (re.compile(r"^Route 53 Resolver: (rslvr-\S+)"), "Route 53 Resolver endpoint"),
    (re.compile(r"^AWS created network interface for directory (d-[0-9a-f]+)"), "Directory Service"),
]
_TYPES = {"lambda": "Lambda function", "network_load_balancer": "Network Load Balancer",
          "gateway_load_balancer": "Gateway Load Balancer", "vpc_endpoint": "VPC endpoint",
          "load_balancer": "Load Balancer", "transit_gateway": "Transit gateway attachment",
          "api_gateway_managed": "API Gateway", "quicksight": "QuickSight",
          "global_accelerator_managed": "Global Accelerator", "gateway_load_balancer_endpoint": "GWLB endpoint",
          "natGateway": "NAT gateway", "efa": "EC2 (EFA)", "trunk": "ECS trunk ENI", "branch": "ECS task"}


def eni_owner(eni: dict) -> tuple[str, str]:
    """(kind, identity) for the resource behind an ENI. The identity groups ENIs of the
    same resource (an instance's ENIs, a load balancer's per-AZ ENIs)."""
    att = eni.get("Attachment") or {}
    if att.get("InstanceId") and not eni.get("RequesterManaged"):
        return "EC2 instance", att["InstanceId"]
    desc = eni.get("Description") or ""
    for rx, kind in _DESC:
        m = rx.match(desc)
        if m:
            return kind, (m.group(1) if m.groups() else eni["NetworkInterfaceId"])
    if att.get("InstanceId"):
        return "EC2 instance", att["InstanceId"]
    kind = _TYPES.get(eni.get("InterfaceType") or "")
    if kind:
        return kind, eni["NetworkInterfaceId"]
    return "Network interface", eni["NetworkInterfaceId"]


def _eni_record(e: dict) -> dict:
    kind, ident = eni_owner(e)
    return {
        "id": e["NetworkInterfaceId"],
        "kind": kind,
        "resource": ident,
        "description": e.get("Description") or None,
        "type": e.get("InterfaceType"),
        "status": e.get("Status"),
        "subnet": e.get("SubnetId"),
        "vpc": e.get("VpcId"),
        "az": e.get("AvailabilityZone"),
        "private_ips": [p.get("PrivateIpAddress") for p in e.get("PrivateIpAddresses") or [] if p.get("PrivateIpAddress")]
        or ([e["PrivateIpAddress"]] if e.get("PrivateIpAddress") else []),
        "public_ip": (e.get("Association") or {}).get("PublicIp"),
        "groups": [g["GroupId"] for g in e.get("Groups") or []],
        "requester_managed": bool(e.get("RequesterManaged")),
        "owner": e.get("OwnerId"),
    }


def _rule_record(r: dict) -> dict:
    ref = r.get("ReferencedGroupInfo") or {}
    if r.get("CidrIpv4") or r.get("CidrIpv6"):
        kind, peer = "cidr", r.get("CidrIpv4") or r.get("CidrIpv6")
    elif r.get("PrefixListId"):
        kind, peer = "pl", r["PrefixListId"]
    else:
        kind, peer = "sg", ref.get("GroupId")
    return {
        "id": r.get("SecurityGroupRuleId"),
        "group": r.get("GroupId"),
        "egress": bool(r.get("IsEgress")),
        "protocol": str(r.get("IpProtocol")),
        "from": r.get("FromPort"),
        "to": r.get("ToPort"),
        "peer_kind": kind,
        "peer": peer,
        "peer_account": ref.get("UserId"),
        "peer_vpc": ref.get("VpcId"),
        "peering": ref.get("VpcPeeringConnectionId"),
        "description": r.get("Description") or None,
    }


def _group_record(g: dict) -> dict:
    return {"id": g["GroupId"], "name": g.get("GroupName"), "description": g.get("Description"),
            "vpc": g.get("VpcId"), "owner": g.get("OwnerId"), "tag_name": tag(g.get("Tags"))}


# ---------- collection ----------

def _groups(ec2, ids: list[str], warnings: list[str]) -> dict[str, dict]:
    out = {}
    for chunk in _chunks(sorted(ids)):
        try:
            for g in _paginate(ec2, "describe_security_groups", "SecurityGroups", GroupIds=chunk):
                out[g["GroupId"]] = _group_record(g)
        except ClientError as e:
            # One unreadable group (another account's, or deleted) fails the whole call: retry singly.
            if len(chunk) == 1:
                warnings.append(f"{chunk[0]}: DescribeSecurityGroups failed: {_code(e)}")
                continue
            for gid in chunk:
                out.update(_groups(ec2, [gid], warnings))
    return out


def _rules(ec2, group_ids: list[str], warnings: list[str]) -> list[dict]:
    out = []
    for chunk in _chunks(sorted(group_ids)):
        try:
            out += [_rule_record(r) for r in _paginate(ec2, "describe_security_group_rules", "SecurityGroupRules",
                                                       Filters=[{"Name": "group-id", "Values": chunk}])]
        except ClientError as e:
            warnings.append(f"DescribeSecurityGroupRules failed for {', '.join(chunk)}: {_code(e)}")
    return out


def _enis(ec2, group_ids: list[str]) -> list[dict]:
    out = []
    for chunk in _chunks(sorted(group_ids)):
        out += [_eni_record(e) for e in _paginate(ec2, "describe_network_interfaces", "NetworkInterfaces",
                                                  Filters=[{"Name": "group-id", "Values": chunk}])]
    return out


def _referencing(ec2, sg: str, warnings: list[str]) -> list[str]:
    ids: set[str] = set()
    for name in ("ip-permission.group-id", "egress.ip-permission.group-id"):
        try:
            ids |= {g["GroupId"] for g in _paginate(ec2, "describe_security_groups", "SecurityGroups",
                                                    Filters=[{"Name": name, "Values": [sg]}])}
        except ClientError as e:
            warnings.append(f"Finding groups that reference {sg} ({name}) failed: {_code(e)}")
    return sorted(ids - {sg})


def _prefix_lists(ec2, ids: list[str], warnings: list[str]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    if not ids:
        return out
    try:
        for pl in _paginate(ec2, "describe_managed_prefix_lists", "PrefixLists", PrefixListIds=sorted(ids)):
            out[pl["PrefixListId"]] = {"id": pl["PrefixListId"], "name": pl.get("PrefixListName"),
                                       "family": pl.get("AddressFamily"), "entries": None}
    except ClientError as e:
        warnings.append(f"DescribeManagedPrefixLists failed: {_code(e)}")
    for pid in sorted(ids):
        rec = out.setdefault(pid, {"id": pid, "name": None, "family": None, "entries": None})
        try:
            rec["entries"] = sorted(e["Cidr"] for e in _paginate(ec2, "get_managed_prefix_list_entries", "Entries",
                                                                 PrefixListId=pid))
        except ClientError as e:
            warnings.append(f"{pid}: GetManagedPrefixListEntries failed: {_code(e)}; treated as an opaque peer")
    return out


def _instance_names(ec2, ids: list[str], warnings: list[str]) -> dict[str, str | None]:
    out = {}
    for chunk in _chunks(sorted(ids), 100):
        try:
            for page in ec2.get_paginator("describe_instances").paginate(InstanceIds=chunk):
                for res in page.get("Reservations") or []:
                    for i in res.get("Instances") or []:
                        out[i["InstanceId"]] = tag(i.get("Tags"))
        except ClientError as e:
            warnings.append(f"DescribeInstances failed: {_code(e)}; instance names not shown")
    return out


def collect(session, region: str, sg: str, account: str | None = None) -> dict:
    if not re.fullmatch(r"sg-[0-9a-f]{8,17}", sg or ""):
        raise ValidationError(f"Not a security group ID: {sg!r}")
    if not region:
        raise ValidationError("No region configured; pass --region or set AWS_REGION")
    ec2 = get_client("ec2", session, region)
    warnings: list[str] = []
    try:
        target = ec2.describe_security_groups(GroupIds=[sg]).get("SecurityGroups") or []
    except ClientError as e:
        if _code(e) in ("InvalidGroup.NotFound", "InvalidGroupId.Malformed"):
            raise ValidationError(f"Security group {sg} not found in {region}") from None
        raise
    if not target:
        raise ValidationError(f"Security group {sg} not found in {region}")

    enis = _enis(ec2, [sg])
    referencing = _referencing(ec2, sg, warnings)
    ref_enis = [e for e in _enis(ec2, referencing) if sg not in e["groups"]] if referencing else []
    group_ids = {sg} | {g for e in enis for g in e["groups"]} | set(referencing)
    rules = _rules(ec2, sorted(group_ids), warnings)
    peer_groups = {r["peer"] for r in rules if r["peer_kind"] == "sg" and r["peer"]}
    groups = _groups(ec2, sorted(group_ids | peer_groups | {g for e in ref_enis for g in e["groups"]}), warnings)
    pls = _prefix_lists(ec2, sorted({r["peer"] for r in rules if r["peer_kind"] == "pl"}), warnings)
    instances = sorted({e["resource"] for e in enis + ref_enis if e["kind"] == "EC2 instance"})
    names = _instance_names(ec2, instances, warnings) if instances else {}
    return {
        "tool": "sg_effect",
        "generated": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "region": region,
        "account": account or target[0].get("OwnerId"),
        "target": sg,
        "groups": groups,
        "rules": rules,
        "enis": enis,
        "referencing": referencing,
        "referencing_enis": ref_enis,
        "prefix_lists": pls,
        "instance_names": names,
        "warnings": warnings,
    }
