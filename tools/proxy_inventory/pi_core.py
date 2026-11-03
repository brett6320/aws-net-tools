"""Find the resources in each cached VPC that could send traffic through an egress proxy.

Input is the VPC owner map that ``ou_vpcs`` writes (~/.cache/aws-net-tools/vpc-owners.json).
Each VPC owner account is read with the profile that maps to its account ID in ~/.aws/config
(never one ending in -priv or -cpar), and every network interface in its VPCs is listed.
Interfaces owned by other accounts (participants in a shared VPC) lead to those accounts
being read too, limited to the shared VPCs. No role is assumed; nothing is changed.

Resource types (each limited to the selected VPCs):
  EC2 instances (also EKS, ECS, EMR and Batch nodes), Lambda functions, ECS services and
  standalone tasks with awsvpc networking, WorkSpaces, AppStream fleets, Glue jobs (through
  their connections), MWAA environments, App Runner services (through VPC connectors).
Interfaces that belong to none of these and to no excluded type (endpoints, NAT and transit
gateways, load balancers, databases ...) are listed as unattributed, so nothing is missed.
"""
from __future__ import annotations

import json
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

import botocore.session
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

log = logging.getLogger("proxy_inventory")

BOTO_CONFIG = Config(retries={"max_attempts": 5, "mode": "adaptive"})
DEFAULT_KEY_TAG = "AppCatID"
MISSING = "(missing)"
DEFAULT_EXCLUDE_SUFFIXES = ("-priv", "-cpar")
READ_ONLY_SUFFIXES = ("-ro", "-readonly", "-read-only")
CACHE_FILENAME = "vpc-owners.json"

ACCOUNT_RE = re.compile(r"^\d{12}$")
REGION_RE = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-\d$")
VPC_RE = re.compile(r"^vpc-[0-9a-f]{8,17}$")
OU_ID_RE = re.compile(r"^(?:ou-[0-9a-z]{4,32}-[0-9a-z]{8,32}|r-[0-9a-z]{4,32})$")
_ROLE_ARN_ACCOUNT = re.compile(r"^arn:[^:]+:iam::(\d{12}):")

# Error codes meaning "this principal may not call this service here" (vary by service).
DENIED_CODES = frozenset({
    "AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "UnauthorizedException", "AuthFailure",
    "OptInRequired", "SubscriptionRequiredException", "UnrecognizedClientException",
})
LIVE_INSTANCE_STATES = ["pending", "running", "stopping", "stopped"]


# --------------------------------------------------------------------------- input


def split_csv(values: Iterable[str] | None) -> list[str]:
    out: list[str] = []
    for raw in values or []:
        for item in raw.split(","):
            if item.strip() and item.strip() not in out:
                out.append(item.strip())
    return out


def parse_account_profiles(values: Iterable[str] | None) -> dict[str, str]:
    out = {}
    for raw in split_csv(values):
        acct, sep, profile = raw.partition("=")
        if not sep or not ACCOUNT_RE.match(acct.strip()) or not profile.strip():
            raise ValueError(f"--account-profile: '{raw}' is not ACCOUNT=PROFILE")
        out[acct.strip()] = profile.strip()
    return out


def default_cache_path() -> Path:
    if os.name == "nt" and os.getenv("LOCALAPPDATA"):
        base = Path(os.environ["LOCALAPPDATA"])
    else:
        base = Path(os.getenv("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / "aws-net-tools" / CACHE_FILENAME


@dataclass(frozen=True)
class Vpc:
    region: str
    vpc_id: str
    account: str
    account_name: str = ""
    ou_id: str = ""
    ou_path: str = ""
    name: str = ""
    cidrs: tuple[str, ...] = ()


def load_vpcs(path: Path) -> list[Vpc]:
    """Every VPC in the owner map. Raises FileNotFoundError / ValueError."""
    if not path.exists():
        raise FileNotFoundError(f"VPC owner map {path} not found; run ou_vpcs first (or pass --cache)")
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError) as e:
        raise ValueError(f"VPC owner map {path} is unreadable: {e}") from e
    out = []
    for key, e in data.items() if isinstance(data, dict) else []:
        region, _, vpc_id = key.partition("/")
        if not isinstance(e, dict) or not ACCOUNT_RE.match(str(e.get("account", ""))) or not VPC_RE.match(vpc_id):
            log.debug("Ignoring owner map entry %s", key)
            continue
        out.append(Vpc(region, vpc_id, e["account"], e.get("account_name", ""), e.get("ou_id", ""),
                       e.get("ou_path", ""), e.get("name", ""), tuple(e.get("cidrs") or ())))
    return sorted(out, key=lambda v: (v.ou_path, v.account, v.region, v.vpc_id))


def _ou_match(v: Vpc, ous: list[str]) -> bool:
    for o in ous:
        if OU_ID_RE.match(o):
            if v.ou_id == o:
                return True
        elif v.ou_path == o.rstrip("/") or v.ou_path.startswith(o.rstrip("/") + "/"):
            return True
    return False


def select_vpcs(vpcs: Iterable[Vpc], ous: list[str] | None = None, accounts: list[str] | None = None,
                regions: list[str] | None = None, vpc_ids: list[str] | None = None) -> list[Vpc]:
    """VPCs matching every filter given. An --ou is an OU ID (exact) or OU path (it and every OU below it).

    OU IDs match the OU a VPC's account sits in directly; use a path for "this OU and below".
    """
    for a in accounts or []:
        if not ACCOUNT_RE.match(a):
            raise ValueError(f"--account: '{a}' is not a 12-digit account ID")
    for r in regions or []:
        if not REGION_RE.match(r):
            raise ValueError(f"--regions: '{r}' is not a Region name")
    for v in vpc_ids or []:
        if not VPC_RE.match(v):
            raise ValueError(f"--vpc: '{v}' is not a VPC ID")
    return [v for v in vpcs
            if (not ous or _ou_match(v, ous)) and (not accounts or v.account in accounts)
            and (not regions or v.region in regions) and (not vpc_ids or v.vpc_id in vpc_ids)]


# --------------------------------------------------------------------------- profiles (as in ou_vpcs)


def exclude_suffixes() -> tuple[str, ...]:
    raw = os.getenv("PROXY_INV_PROFILE_EXCLUDE_SUFFIXES")
    if raw is None:
        return DEFAULT_EXCLUDE_SUFFIXES
    return tuple(s.strip() for s in raw.split(",") if s.strip())


def profile_account(cfg: dict[str, str]) -> str | None:
    for key in ("sso_account_id", "aws_account_id"):
        if cfg.get(key):
            return str(cfg[key]).strip()
    m = _ROLE_ARN_ACCOUNT.match(cfg.get("role_arn", ""))
    return m.group(1) if m else None


@lru_cache(maxsize=1)
def profile_accounts() -> dict[str, str]:
    """Profile name -> account ID, for profiles whose account is in ~/.aws/config or ~/.aws/credentials."""
    profiles = botocore.session.Session().full_config.get("profiles", {})
    return {name: acct for name, cfg in profiles.items() if (acct := profile_account(cfg))}


def resolve_profile(account: str, overrides: dict[str, str] | None = None, preferred: str | None = None) -> str:
    """The profile to read ``account`` with. Raises LookupError when there's none or several."""
    if overrides and account in overrides:
        return overrides[account]
    excluded = exclude_suffixes()
    cands = sorted(n for n, a in profile_accounts().items() if a == account and not n.endswith(excluded))
    if not cands:
        raise LookupError("no profile in ~/.aws/config maps to it")
    if preferred in cands:
        return preferred
    if len(cands) > 1:
        ro = [c for c in cands if c.endswith(READ_ONLY_SUFFIXES)]
        if len(ro) == 1:
            return ro[0]
        raise LookupError(f"several profiles map to it ({', '.join(cands)}); choose one with --account-profile")
    return cands[0]


# --------------------------------------------------------------------------- helpers


def _error(e: Exception) -> str:
    if isinstance(e, ClientError):
        err = e.response.get("Error", {})
        return f"{err.get('Code')}: {err.get('Message')}"
    return str(e)


def _chunks(items: list, n: int) -> Iterator[list]:
    for i in range(0, len(items), n):
        yield items[i:i + n]


def _pages(client: Any, op: str, key: str, **kw: Any) -> Iterator[Any]:
    """Every item under ``key``, with botocore's paginator or, where there is none, a NextToken loop."""
    if client.can_paginate(op):
        for page in client.get_paginator(op).paginate(**kw):
            yield from page.get(key) or []
        return
    call, token = getattr(client, op), None
    while True:
        page = call(**kw, **({"NextToken": token} if token else {}))
        yield from page.get(key) or []
        token = page.get("NextToken")
        if not token:
            return


def tag_dict(tags: Any) -> dict[str, str]:
    """Tags as a dict, from any of AWS's shapes: [{Key, Value}], [{key, value}] or a dict."""
    if isinstance(tags, dict):
        return {str(k): "" if v is None else str(v) for k, v in tags.items()}
    out = {}
    for t in tags or []:
        k = t.get("Key", t.get("key"))
        if k is not None:
            out[str(k)] = str(t.get("Value", t.get("value")) or "")
    return out


def key_tag_value(tags: dict[str, str], key: str) -> str:
    """The value of tag ``key``, matched without regard to case; "" when absent or blank."""
    want = key.lower()
    for k, v in tags.items():
        if k.lower() == want and v.strip():
            return v.strip()
    return ""


def partition_of(region: str) -> str:
    return "aws-us-gov" if region.startswith("us-gov-") else "aws-cn" if region.startswith("cn-") else "aws"


def available(session: Any, service: str, region: str) -> bool:
    """Whether ``service`` has an endpoint in ``region`` (botocore's endpoint data; no network call)."""
    try:
        return region in session.get_available_regions(service, partition_of(region))
    except Exception:  # noqa: BLE001 - unknown service data: let the call itself decide
        return True


# --------------------------------------------------------------------------- results


@dataclass
class Issue:
    account: str
    region: str
    scope: str  # "account", "region", a service name, or "participant"
    reason: str
    # Resources may be missing. False only for a denied service: its interfaces still show as unattributed.
    incomplete: bool = True


@dataclass
class Scan:
    resources: list[dict[str, Any]] = field(default_factory=list)
    enis: list[dict[str, Any]] = field(default_factory=list)
    vpcs: list[dict[str, Any]] = field(default_factory=list)
    issues: list[Issue] = field(default_factory=list)
    read: set[tuple[str, str, str, str]] = field(default_factory=set)  # (account, Region, VPC, collector) read

    def merge(self, other: "Scan") -> None:
        self.resources += other.resources
        self.enis += other.enis
        self.vpcs += other.vpcs
        self.issues += other.issues
        self.read |= other.read


def resource(rtype: str, rid: str, vpc_id: str, *, name: str = "", state: str = "", subnets: Iterable[str] = (),
             ips: Iterable[str] = (), detail: Iterable[str] = (), tags: Any = None, arn: str = "",
             eni_ids: Iterable[str] = (), inherited: tuple[str, Any] | None = None) -> dict[str, Any]:
    """One resource row (account, Region, key tag and VPC details are added by the caller).

    ``inherited`` = (source, tags): where the key tag comes from when the resource has none
    (e.g. an ECS task without propagated tags takes its service's or cluster's).
    """
    return {"type": rtype, "id": rid, "arn": arn, "vpc_id": vpc_id, "name": name, "state": state,
            "subnets": sorted(set(subnets)), "private_ips": sorted(set(i for i in ips if i)),
            "detail": [d for d in detail if d], "tags": tag_dict(tags), "eni_ids": sorted(set(eni_ids)),
            "inherited": (inherited[0], tag_dict(inherited[1])) if inherited else None}


# --------------------------------------------------------------------------- collectors
# Each takes (session, region, account, vpc_ids, subnet_vpc) and returns resource rows.


def subnet_map(ec2: Any, vpc_ids: list[str]) -> dict[str, str]:
    out = {}
    for chunk in _chunks(vpc_ids, 100):
        for s in _pages(ec2, "describe_subnets", "Subnets", Filters=[{"Name": "vpc-id", "Values": chunk}]):
            out[s["SubnetId"]] = s["VpcId"]
    return out


def _vpc_of(subnets: Iterable[str], subnet_vpc: dict[str, str]) -> str | None:
    return next((subnet_vpc[s] for s in subnets if s in subnet_vpc), None)


def ec2_instances(session, region, account, vpc_ids, subnet_vpc) -> list[dict]:
    ec2 = session.client("ec2", region_name=region, config=BOTO_CONFIG)
    found: dict[str, dict] = {}
    for chunk in _chunks(sorted(vpc_ids), 100):
        for f in ("vpc-id", "network-interface.vpc-id"):  # also instances whose secondary interface is in the VPC
            for r in _pages(ec2, "describe_instances", "Reservations",
                            Filters=[{"Name": f, "Values": chunk},
                                     {"Name": "instance-state-name", "Values": LIVE_INSTANCE_STATES}]):
                for i in r.get("Instances") or []:
                    found[i["InstanceId"]] = i
    rows = []
    for iid, i in sorted(found.items()):
        tags = tag_dict(i.get("Tags"))
        nis = i.get("NetworkInterfaces") or []
        hints = [f"EKS {tags['eks:cluster-name']}" if "eks:cluster-name" in tags else "",
                 "EMR" if "aws:elasticmapreduce:job-flow-id" in tags else "",
                 f"ASG {tags['aws:autoscaling:groupName']}" if "aws:autoscaling:groupName" in tags else ""]
        # One row per selected VPC the instance has an interface in.
        in_vpcs = {n.get("VpcId") for n in nis} | {i.get("VpcId")}
        for vpc in sorted(v for v in in_vpcs if v in vpc_ids):
            mine = [n for n in nis if n.get("VpcId") == vpc]
            rows.append(resource(
                "EC2 instance", iid, vpc, name=tags.get("Name", ""), state=(i.get("State") or {}).get("Name", ""),
                subnets=[n["SubnetId"] for n in mine if n.get("SubnetId")] or ([i["SubnetId"]] if i.get("SubnetId") else []),
                ips=[a.get("PrivateIpAddress") for n in mine for a in n.get("PrivateIpAddresses") or []] or [i.get("PrivateIpAddress")],
                detail=[i.get("InstanceType", ""), i.get("PlatformDetails", "")] + hints, tags=tags,
                arn=f"arn:{partition_of(region)}:ec2:{region}:{account}:instance/{iid}",
                eni_ids=[n["NetworkInterfaceId"] for n in mine]))
    return rows


def lambda_functions(session, region, account, vpc_ids, subnet_vpc) -> list[dict]:
    lam = session.client("lambda", region_name=region, config=BOTO_CONFIG)
    rows = []
    for f in _pages(lam, "list_functions", "Functions"):
        cfg = f.get("VpcConfig") or {}
        vpc = cfg.get("VpcId") or _vpc_of(cfg.get("SubnetIds") or [], subnet_vpc)
        if vpc not in vpc_ids:
            continue
        tags = lam.list_tags(Resource=f["FunctionArn"]).get("Tags") or {}
        rows.append(resource("Lambda function", f["FunctionName"], vpc, name=f["FunctionName"],
                             subnets=cfg.get("SubnetIds") or [], detail=[f.get("Runtime") or f.get("PackageType", "")],
                             tags=tags, arn=f["FunctionArn"]))
    return rows


def _task_eni(task: dict) -> tuple[str, str, str]:
    """(subnet, ENI ID, private IP) of an awsvpc task; empty strings otherwise."""
    for att in task.get("attachments") or []:
        if att.get("type") == "ElasticNetworkInterface":
            d = {x["name"]: x.get("value", "") for x in att.get("details") or []}
            return d.get("subnetId", ""), d.get("networkInterfaceId", ""), d.get("privateIPv4Address", "")
    return "", "", ""


def ecs_workloads(session, region, account, vpc_ids, subnet_vpc) -> list[dict]:
    ecs = session.client("ecs", region_name=region, config=BOTO_CONFIG)
    clusters = list(_pages(ecs, "list_clusters", "clusterArns"))
    ctags = {}
    for chunk in _chunks(clusters, 100):
        for c in ecs.describe_clusters(clusters=chunk, include=["TAGS"]).get("clusters") or []:
            ctags[c["clusterArn"]] = c.get("tags")
    rows = []
    for cl in clusters:
        cname = cl.rsplit("/", 1)[-1]
        batch = ["Batch"] if cname.startswith("AWSBatch") else []
        tasks = []
        for chunk in _chunks(list(_pages(ecs, "list_tasks", "taskArns", cluster=cl)), 100):
            tasks += ecs.describe_tasks(cluster=cl, tasks=chunk, include=["TAGS"]).get("tasks") or []
        by_group: dict[str, list[dict]] = {}
        for t in tasks:
            by_group.setdefault(t.get("group", ""), []).append(t)
        for chunk in _chunks(list(_pages(ecs, "list_services", "serviceArns", cluster=cl)), 10):
            for s in ecs.describe_services(cluster=cl, services=chunk, include=["TAGS"]).get("services") or []:
                net = ((s.get("networkConfiguration") or {}).get("awsvpcConfiguration") or {})
                vpc = _vpc_of(net.get("subnets") or [], subnet_vpc)
                if vpc not in vpc_ids:  # bridge/host networking: the EC2 hosts are listed instead
                    continue
                enis = [_task_eni(t) for t in by_group.get(f"service:{s['serviceName']}", [])]
                rows.append(resource(
                    "ECS service", f"{cname}/{s['serviceName']}", vpc, name=s["serviceName"],
                    state=f"{s.get('status', '')} {s.get('runningCount', 0)}/{s.get('desiredCount', 0)}".strip(),
                    subnets=net.get("subnets") or [], ips=[e[2] for e in enis],
                    detail=[s.get("launchType") or "capacity provider", s.get("taskDefinition", "").rsplit("/", 1)[-1]] + batch,
                    tags=s.get("tags"), arn=s["serviceArn"], eni_ids=[e[1] for e in enis if e[1]],
                    inherited=("ECS cluster", ctags.get(cl))))
        for t in tasks:
            if t.get("group", "").startswith("service:"):
                continue
            subnet, eni, ip = _task_eni(t)
            vpc = subnet_vpc.get(subnet)
            if vpc not in vpc_ids:
                continue
            tid = t["taskArn"].rsplit("/", 1)[-1]
            rows.append(resource(
                "ECS task", f"{cname}/{tid}", vpc, name=t.get("group", ""), state=t.get("lastStatus", ""),
                subnets=[subnet], ips=[ip], eni_ids=[eni] if eni else [],
                detail=[t.get("launchType", ""), t.get("taskDefinitionArn", "").rsplit("/", 1)[-1]] + batch,
                tags=t.get("tags"), arn=t["taskArn"], inherited=("ECS cluster", ctags.get(cl))))
    return rows


def workspaces(session, region, account, vpc_ids, subnet_vpc) -> list[dict]:
    ws = session.client("workspaces", region_name=region, config=BOTO_CONFIG)
    rows = []
    for w in _pages(ws, "describe_workspaces", "Workspaces"):
        vpc = subnet_vpc.get(w.get("SubnetId", ""))
        if vpc not in vpc_ids:
            continue
        tags = ws.describe_tags(ResourceId=w["WorkspaceId"]).get("TagList")
        rows.append(resource("WorkSpace", w["WorkspaceId"], vpc, name=w.get("ComputerName") or w.get("UserName", ""),
                             state=w.get("State", ""), subnets=[w["SubnetId"]], ips=[w.get("IpAddress")],
                             detail=[w.get("UserName", ""), w.get("BundleId", "")], tags=tags,
                             arn=f"arn:{partition_of(region)}:workspaces:{region}:{account}:workspace/{w['WorkspaceId']}"))
    return rows


def appstream_fleets(session, region, account, vpc_ids, subnet_vpc) -> list[dict]:
    asc = session.client("appstream", region_name=region, config=BOTO_CONFIG)
    rows = []
    for f in _pages(asc, "describe_fleets", "Fleets"):
        subnets = (f.get("VpcConfig") or {}).get("SubnetIds") or []
        vpc = _vpc_of(subnets, subnet_vpc)
        if vpc not in vpc_ids:
            continue
        tags = asc.list_tags_for_resource(ResourceArn=f["Arn"]).get("Tags")
        rows.append(resource("AppStream fleet", f["Name"], vpc, name=f.get("DisplayName") or f["Name"],
                             state=f.get("State", ""), subnets=subnets,
                             detail=[f.get("FleetType", ""), f.get("InstanceType", "")], tags=tags, arn=f["Arn"]))
    return rows


def glue_jobs(session, region, account, vpc_ids, subnet_vpc) -> list[dict]:
    glue = session.client("glue", region_name=region, config=BOTO_CONFIG)
    # HidePassword: never fetch connection passwords; only the subnet is used from a connection.
    conn_subnet = {}
    for c in _pages(glue, "get_connections", "ConnectionList", HidePassword=True):
        subnet = (c.get("PhysicalConnectionRequirements") or {}).get("SubnetId")
        if subnet in subnet_vpc:
            conn_subnet[c["Name"]] = subnet
    if not conn_subnet:
        return []
    rows = []
    for j in _pages(glue, "get_jobs", "Jobs"):
        conns = [c for c in (j.get("Connections") or {}).get("Connections") or [] if c in conn_subnet]
        for vpc in sorted({subnet_vpc[conn_subnet[c]] for c in conns} & set(vpc_ids)):
            arn = f"arn:{partition_of(region)}:glue:{region}:{account}:job/{j['Name']}"
            subnets = [conn_subnet[c] for c in conns if subnet_vpc[conn_subnet[c]] == vpc]
            rows.append(resource("Glue job", j["Name"], vpc, name=j["Name"], subnets=subnets,
                                 detail=[f"Glue {j.get('GlueVersion', '')}".strip(), "connections: " + ", ".join(conns)],
                                 tags=glue.get_tags(ResourceArn=arn).get("Tags"), arn=arn))
    return rows


def mwaa_environments(session, region, account, vpc_ids, subnet_vpc) -> list[dict]:
    mwaa = session.client("mwaa", region_name=region, config=BOTO_CONFIG)
    rows = []
    for name in _pages(mwaa, "list_environments", "Environments"):
        e = mwaa.get_environment(Name=name)["Environment"]
        subnets = (e.get("NetworkConfiguration") or {}).get("SubnetIds") or []
        vpc = _vpc_of(subnets, subnet_vpc)
        if vpc in vpc_ids:
            rows.append(resource("MWAA environment", name, vpc, name=name, state=e.get("Status", ""), subnets=subnets,
                                 detail=[f"Airflow {e.get('AirflowVersion', '')}".strip(), e.get("EnvironmentClass", "")],
                                 tags=e.get("Tags"), arn=e.get("Arn", "")))
    return rows


def apprunner_services(session, region, account, vpc_ids, subnet_vpc) -> list[dict]:
    ar = session.client("apprunner", region_name=region, config=BOTO_CONFIG)
    connectors = {}
    for c in _pages(ar, "list_vpc_connectors", "VpcConnectors"):
        vpc = _vpc_of(c.get("Subnets") or [], subnet_vpc)
        if vpc in vpc_ids:
            connectors[c["VpcConnectorArn"]] = (vpc, c.get("Subnets") or [], c.get("VpcConnectorName", ""))
    if not connectors:
        return []
    rows = []
    for summary in _pages(ar, "list_services", "ServiceSummaryList"):
        s = ar.describe_service(ServiceArn=summary["ServiceArn"])["Service"]
        egress = (s.get("NetworkConfiguration") or {}).get("EgressConfiguration") or {}
        if egress.get("VpcConnectorArn") not in connectors:
            continue
        vpc, subnets, cname = connectors[egress["VpcConnectorArn"]]
        rows.append(resource("App Runner service", s["ServiceName"], vpc, name=s["ServiceName"], state=s.get("Status", ""),
                             subnets=subnets, detail=[f"connector {cname}"], arn=s["ServiceArn"],
                             tags=ar.list_tags_for_resource(ResourceArn=s["ServiceArn"]).get("Tags")))
    return rows


# (label, botocore service name, collector)
COLLECTORS: tuple[tuple[str, str, Callable], ...] = (
    ("EC2", "ec2", ec2_instances),
    ("Lambda", "lambda", lambda_functions),
    ("ECS", "ecs", ecs_workloads),
    ("WorkSpaces", "workspaces", workspaces),
    ("AppStream", "appstream", appstream_fleets),
    ("Glue", "glue", glue_jobs),
    ("MWAA", "mwaa", mwaa_environments),
    ("App Runner", "apprunner", apprunner_services),
)


# --------------------------------------------------------------------------- network interfaces

# Interface types that never carry a workload that could use a proxy (both spellings AWS has used for NAT).
EXCLUDED_ENI_TYPES = frozenset({
    "vpc_endpoint", "natGateway", "nat_gateway", "transit_gateway", "network_load_balancer", "load_balancer",
    "gateway_load_balancer", "gateway_load_balancer_endpoint", "api_gateway_managed", "aws_codestar_connections_managed",
    "global_accelerator_managed", "iot_rules_managed", "quicksight", "ec2_instance_connect_endpoint",
})
EXCLUDED_REQUESTERS = frozenset({"amazon-elb", "amazon-rds", "amazon-elasticache", "amazon-redshift"})
# Description prefix -> service, for managed interfaces that aren't proxy clients.
EXCLUDED_DESCRIPTIONS = (
    ("ELB ", "Elastic Load Balancing"), ("RDSNetworkInterface", "RDS"), ("Route 53 Resolver", "Route 53 Resolver"),
    ("EFS mount target", "EFS"), ("ElastiCache", "ElastiCache"), ("Amazon Redshift", "Redshift"),
    ("Amazon EKS ", "EKS control plane"), ("DMSNetworkInterface", "DMS"), ("Interface for NAT Gateway", "NAT gateway"),
    ("VPC Endpoint Interface", "VPC endpoint"), ("AWS created network interface for directory", "Directory Service"),
    ("Network Load Balancer", "Elastic Load Balancing"), ("Amazon OpenSearch", "OpenSearch"),
    ("ES ", "OpenSearch"), ("Amazon MSK", "MSK"), ("Amazon MQ", "Amazon MQ"), ("FSx", "FSx"),
)
# Description keywords -> likely service, shown for unattributed interfaces.
GUESSES = (
    ("arn:aws:ecs:", "ECS task"), ("AWS Lambda VPC ENI", "Lambda"), ("aws-K8S-", "EKS (VPC CNI)"), ("Glue", "Glue"),
    ("AppStream", "AppStream"), ("WorkSpaces", "WorkSpaces"), ("Workspace", "WorkSpaces"), ("Airflow", "MWAA"),
    ("MWAA", "MWAA"), ("CodeBuild", "CodeBuild"), ("SageMaker", "SageMaker"), ("EMR", "EMR"),
    ("App Runner", "App Runner"), ("AppRunner", "App Runner"), ("Fargate", "Fargate"), ("Batch", "Batch"),
)


def eni_rows(ec2: Any, vpc_ids: list[str]) -> list[dict]:
    rows = []
    for chunk in _chunks(vpc_ids, 100):
        for n in _pages(ec2, "describe_network_interfaces", "NetworkInterfaces", Filters=[{"Name": "vpc-id", "Values": chunk}]):
            att = n.get("Attachment") or {}
            rows.append({
                "eni_id": n["NetworkInterfaceId"], "vpc_id": n.get("VpcId", ""), "subnet": n.get("SubnetId", ""),
                "eni_owner": n.get("OwnerId", ""), "interface_type": n.get("InterfaceType", ""),
                "description": n.get("Description", ""), "requester": n.get("RequesterId", ""),
                "requester_managed": bool(n.get("RequesterManaged")), "status": n.get("Status", ""),
                "instance_id": att.get("InstanceId", ""), "instance_owner": att.get("InstanceOwnerId", ""),
                "private_ips": sorted(a["PrivateIpAddress"] for a in n.get("PrivateIpAddresses") or [] if a.get("PrivateIpAddress")),
                "tags": tag_dict(n.get("TagSet")),
            })
    return rows


def excluded_as(eni: dict) -> str:
    """The non-proxy service an interface belongs to, or ""."""
    if eni["interface_type"] in EXCLUDED_ENI_TYPES:
        return eni["interface_type"]
    if eni["requester"] in EXCLUDED_REQUESTERS:
        return eni["requester"]
    for prefix, svc in EXCLUDED_DESCRIPTIONS:
        if eni["description"].startswith(prefix):
            return svc
    return ""


def guess_service(eni: dict) -> str:
    if eni["interface_type"] == "branch":
        return "ECS awsvpc trunking / EKS pod security groups"
    if eni["instance_id"]:
        return f"attached to {eni['instance_id']}"
    for kw, svc in GUESSES:
        if kw.lower() in eni["description"].lower():
            return svc
    return ""


# Likely service -> resource type, for managed interfaces that carry no resource ID: such an interface is
# accounted for when its owner account has a resource of that type in the same VPC.
GUESS_TYPES = {"Glue": "Glue job", "AppStream": "AppStream fleet", "WorkSpaces": "WorkSpace",
               "MWAA": "MWAA environment", "App Runner": "App Runner service", "ECS task": "ECS task"}


def classify_enis(enis: list[dict], resources: list[dict], read: set[tuple[str, str, str, str]] = frozenset()) -> list[dict]:
    """The interfaces that belong to no reported resource and no excluded type, with a likely service each.

    ``read``: (account, Region, VPC, collector) read successfully. Lambda interfaces (shared by the
    functions of a subnet / security group combination) are only taken as accounted for where Lambda was read.
    """
    by_eni = {e for r in resources for e in r["eni_ids"]}
    by_instance = {r["id"] for r in resources if r["type"] == "EC2 instance"}
    by_ip = {(r["vpc_id"], ip) for r in resources for ip in r["private_ips"]}
    by_type = {(r["account"], r["vpc_id"], r["type"]) for r in resources if "account" in r}
    out = []
    for n in enis:
        if (n["eni_id"] in by_eni or n["instance_id"] in by_instance
                or (n["interface_type"] == "lambda" and (n["eni_owner"], n["region"], n["vpc_id"], "Lambda") in read)
                or any((n["vpc_id"], ip) in by_ip for ip in n["private_ips"]) or excluded_as(n)):
            continue
        likely = guess_service(n)
        if (n["eni_owner"], n["vpc_id"], GUESS_TYPES.get(likely)) in by_type:
            continue
        if n["eni_owner"] and n["eni_owner"] != n.get("account"):
            # shared VPC: the workload lives in a participant account that couldn't be read
            likely = f"{likely} (participant account {n['eni_owner']})".strip()
        out.append({**n, "likely": likely})
    return out


# --------------------------------------------------------------------------- scanning


def _session_for_account(account: str, session_for: Callable[[str], Any], overrides, preferred,
                         region: str) -> tuple[Any, str]:
    profile = resolve_profile(account, overrides, preferred)
    session = session_for(profile)
    # A Regional STS endpoint, so GovCloud and China profiles work too.
    actual = session.client("sts", region_name=region, config=BOTO_CONFIG).get_caller_identity()["Account"]
    if actual != account:
        raise PermissionError(f"profile {profile} authenticates as {actual}")
    return session, profile


def scan_account(account: str, by_region: dict[str, list[str]], session_for: Callable[[str], Any],
                 overrides: dict[str, str] | None = None, preferred: str | None = None, *,
                 owner: bool = True, scope: str = "account") -> Scan:
    """Read one account: every collector in each Region, limited to ``by_region``'s VPC IDs.

    ``owner``: the account owns these VPCs, so also list their interfaces and VPC tags.
    A new boto3 Session is made here, so accounts can be scanned in parallel threads.
    """
    scan = Scan()
    try:
        session, profile = _session_for_account(account, session_for, overrides, preferred, min(by_region))
    except (LookupError, PermissionError, ClientError, BotoCoreError) as e:
        scan.issues.append(Issue(account, "", scope, _error(e)))
        log.warning("Skipping account %s: %s", account, _error(e))
        return scan
    log.info("Account %s: profile %s%s", account, profile, "" if owner else " (shared VPC participant)")
    for region, vpc_ids in sorted(by_region.items()):
        try:
            ec2 = session.client("ec2", region_name=region, config=BOTO_CONFIG)
            subnets = subnet_map(ec2, vpc_ids)
            if owner:
                scan.vpcs += vpc_details(ec2, account, region, vpc_ids)
                enis = eni_rows(ec2, vpc_ids)
                for n in enis:
                    n.update(account=account, region=region)
                scan.enis += enis
        except Exception as e:  # noqa: BLE001 - skip this Region, keep the rest of the run
            scan.issues.append(Issue(account, region, "region", _error(e)))
            log.warning("Skipping %s in %s: %s", account, region, _error(e))
            continue
        wanted = set(vpc_ids)
        for label, service, collect in COLLECTORS:
            if not available(session, service, region):
                log.debug("%s %s: %s isn't offered in this Region", account, region, label)
                continue
            try:
                rows = collect(session, region, account, wanted, subnets)
            except Exception as e:  # noqa: BLE001 - one service failing must not lose the rest of the run
                denied = isinstance(e, ClientError) and e.response.get("Error", {}).get("Code", "") in DENIED_CODES
                scan.issues.append(Issue(account, region, label, _error(e), incomplete=not denied))
                (log.info if denied else log.warning)("%s %s: %s not read: %s", account, region, label, _error(e))
                continue
            scan.read.update((account, region, v, label) for v in wanted)
            for r in rows:
                r.update(account=account, region=region)
            scan.resources += rows
            log.debug("%s %s: %d %s resource(s)", account, region, len(rows), label)
    return scan


def vpc_details(ec2: Any, account: str, region: str, vpc_ids: list[str]) -> list[dict]:
    """Tags of each VPC; cached VPCs that no longer exist come back with ``gone``."""
    seen = {}
    for chunk in _chunks(vpc_ids, 100):
        for v in _pages(ec2, "describe_vpcs", "Vpcs", Filters=[{"Name": "vpc-id", "Values": chunk}]):
            seen[v["VpcId"]] = tag_dict(v.get("Tags"))
    return [{"account": account, "region": region, "vpc_id": v, "tags": seen.get(v, {}), "gone": v not in seen}
            for v in vpc_ids]


def scan(vpcs: list[Vpc], session_for: Callable[[str], Any], overrides: dict[str, str] | None = None,
         preferred: str | None = None, workers: int = 4, participants: bool = True) -> Scan:
    """Scan the VPC owners, then (``participants``) the other accounts with interfaces in their VPCs."""
    owners: dict[str, dict[str, list[str]]] = {}
    for v in vpcs:
        owners.setdefault(v.account, {}).setdefault(v.region, []).append(v.vpc_id)
    total = Scan()

    def run(jobs: dict[str, dict[str, list[str]]], **kw) -> None:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            futures = [pool.submit(scan_account, a, regions, session_for, overrides, preferred, **kw)
                       for a, regions in sorted(jobs.items())]
            for f in futures:
                total.merge(f.result())

    run(owners)
    if participants:
        shared: dict[str, dict[str, set[str]]] = {}
        # A participant owns the interfaces of its workloads; the attachment's instance owner can be an AWS
        # service account (e.g. the EKS control plane), so it isn't used.
        for n in total.enis:
            other = n["eni_owner"]
            if ACCOUNT_RE.match(other or "") and other != n["account"] and not excluded_as(n):
                shared.setdefault(other, {}).setdefault(n["region"], set()).add(n["vpc_id"])
        if shared:
            log.info("Shared VPCs: %d participant account(s) to read", len(shared))
            run({a: {r: sorted(v) for r, v in regs.items()} for a, regs in shared.items()}, owner=False, scope="participant")
    return total
