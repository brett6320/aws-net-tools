"""Core Reachability Analyzer operations: input validation, path/analysis API calls.

Request builders (build_create_path_request, build_start_analysis_request) are pure:
they validate input and return the exact kwargs for the EC2 API, which lets the
CLI print them in dry-run mode and lets tests check them without AWS. The thin
API wrappers below them log every mutating call.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

import boto3
from botocore.config import Config

log = logging.getLogger(__name__)

# Resource types Reachability Analyzer accepts as a path source or destination.
# Ordered so longer, more specific ID prefixes match before shorter ones
# (tgw-attach- before tgw-, vpce-svc- before vpce-).
# key: (id prefix, ARN resource type, display name)
ENDPOINT_TYPES: dict[str, tuple[str, str, str]] = {
    "instance": ("i-", "instance", "EC2 instance"),
    "internet-gateway": ("igw-", "internet-gateway", "Internet gateway"),
    "network-interface": ("eni-", "network-interface", "Network interface"),
    "transit-gateway-attachment": ("tgw-attach-", "transit-gateway-attachment", "Transit gateway attachment"),
    "transit-gateway": ("tgw-", "transit-gateway", "Transit gateway"),
    "vpn-gateway": ("vgw-", "vpn-gateway", "Virtual private gateway"),
    "vpc-endpoint-service": ("vpce-svc-", "vpc-endpoint-service", "VPC endpoint service"),
    "vpc-endpoint": ("vpce-", "vpc-endpoint", "VPC endpoint"),
    "vpc-peering-connection": ("pcx-", "vpc-peering-connection", "VPC peering connection"),
}

# Intermediate components that can be used with --filter-in / --filter-out (ARNs only).
INTERMEDIATE_TYPES = [
    "Load balancers (elasticloadbalancing ... loadbalancer/...)",
    "NAT gateways (ec2 ... natgateway/nat-...)",
    "AWS Network Firewall firewalls (network-firewall ... firewall/...)",
    "Transit gateways (ec2 ... transit-gateway/tgw-...)",
    "Transit gateway attachments (ec2 ... transit-gateway-attachment/tgw-attach-...)",
    "VPC peering connections (ec2 ... vpc-peering-connection/pcx-...)",
]

PROTOCOLS = ("tcp", "udp")


class ValidationError(ValueError):
    """Raised when user-supplied path parameters are invalid."""


@dataclass
class PortRange:
    """Inclusive port range; a single port has from_port == to_port."""
    from_port: int
    to_port: int

    def to_api(self) -> dict[str, int]:
        return {"FromPort": self.from_port, "ToPort": self.to_port}

    def __str__(self) -> str:
        return str(self.from_port) if self.from_port == self.to_port else f"{self.from_port}-{self.to_port}"


@dataclass
class PathSpec:
    """User input for a path, before validation. Source/destination are IDs or ARNs."""
    source: str
    protocol: str
    destination: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    source_ports: PortRange | None = None
    destination_ports: PortRange | None = None
    name: str | None = None
    tags: dict[str, str] = field(default_factory=dict)


def get_session(profile: str | None, region: str | None) -> boto3.Session:
    """boto3 session for a named profile (or the default credential chain)."""
    return boto3.Session(profile_name=profile, region_name=region)


def get_client(service: str, session: boto3.Session):
    """Client with adaptive retries (backs off on throttling)."""
    config = Config(retries={"max_attempts": 3, "mode": "adaptive"})
    return session.client(service, config=config)


def parse_port_range(value: str | None) -> PortRange | None:
    """Parse '443' or '1024-65535' into a PortRange."""
    if value is None or value == "":
        return None
    parts = value.split("-")
    if len(parts) not in (1, 2) or not all(p.strip().isdigit() for p in parts):
        raise ValidationError(f"Invalid port or range {value!r}; use N or N-M")
    lo, hi = int(parts[0]), int(parts[-1])
    if not (0 <= lo <= 65535 and 0 <= hi <= 65535):
        raise ValidationError(f"Port out of range in {value!r}; must be 0-65535")
    if lo > hi:
        raise ValidationError(f"Invalid port range {value!r}; start greater than end")
    return PortRange(lo, hi)


def classify_endpoint(ref: str) -> str:
    """Return the ENDPOINT_TYPES key for a source/destination ID or ARN.

    ARNs are matched on their resource type (arn:...:instance/i-...); bare IDs on their
    prefix. Raises ValidationError for anything Reachability Analyzer can't use as an
    endpoint (security groups, subnets, ...)."""
    if ref.startswith("arn:"):
        parts = ref.split(":", 5)
        if len(parts) != 6 or "/" not in parts[5]:
            raise ValidationError(f"Malformed ARN {ref!r}")
        arn_type = parts[5].split("/", 1)[0]
        for key, (_, t, _) in ENDPOINT_TYPES.items():
            if t == arn_type:
                return key
        raise ValidationError(f"Unsupported resource type {arn_type!r} in ARN {ref!r}")
    for key, (prefix, _, _) in ENDPOINT_TYPES.items():
        if ref.startswith(prefix):
            return key
    raise ValidationError(
        f"Unsupported source/destination {ref!r}. Supported ID prefixes: "
        + ", ".join(p for p, _, _ in ENDPOINT_TYPES.values())
    )


def _validate_ipv4(value: str, label: str) -> str:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError as e:
        raise ValidationError(f"{label} {value!r} is not a valid IP address") from e
    if addr.version != 4:
        raise ValidationError(f"{label} {value!r}: Reachability Analyzer supports IPv4 only")
    return str(addr)


def validate_arns(arns: list[str] | None, label: str) -> list[str]:
    """Intermediate-component filters must be full ARNs (the API rejects bare IDs)."""
    out = []
    for a in arns or []:
        if not a.startswith("arn:") or len(a.split(":", 5)) != 6:
            raise ValidationError(f"{label} must be full ARNs; got {a!r}")
        out.append(a)
    return out


def validate_spec(spec: PathSpec) -> None:
    """Check a PathSpec in place (IPs are normalized). Raises ValidationError."""
    classify_endpoint(spec.source)
    if spec.destination:
        classify_endpoint(spec.destination)
    elif not spec.destination_ip:
        raise ValidationError("A destination resource or destination IP is required")
    if spec.protocol not in PROTOCOLS:
        raise ValidationError(f"Protocol must be one of {PROTOCOLS}")
    if spec.source_ip:
        spec.source_ip = _validate_ipv4(spec.source_ip, "Source IP")
    if spec.destination_ip:
        spec.destination_ip = _validate_ipv4(spec.destination_ip, "Destination IP")


def build_create_path_request(spec: PathSpec) -> dict[str, Any]:
    """Build CreateNetworkInsightsPath kwargs.

    Source IP and port ranges are applied as FilterAtSource so the packet header
    is defined where the traffic originates. That header is what gets evaluated
    against the source's outbound SG/NACL rules and carried (and transformed)
    hop by hop, so the inbound rules at the destination see the same flow.
    The API forbids SourceIp/DestinationPort when FilterAtSource is set, so those
    top-level fields are never used.
    """
    validate_spec(spec)
    req: dict[str, Any] = {"Source": spec.source, "Protocol": spec.protocol}
    if spec.destination:
        req["Destination"] = spec.destination
    if spec.destination_ip:
        req["DestinationIp"] = spec.destination_ip

    flt: dict[str, Any] = {}
    if spec.source_ip:
        flt["SourceAddress"] = spec.source_ip
    if spec.source_ports:
        flt["SourcePortRange"] = spec.source_ports.to_api()
    if spec.destination_ports:
        flt["DestinationPortRange"] = spec.destination_ports.to_api()
    if flt:
        req["FilterAtSource"] = flt

    tags = dict(spec.tags)
    if spec.name:
        tags["Name"] = spec.name
    if tags:
        req["TagSpecifications"] = [{
            "ResourceType": "network-insights-path",
            "Tags": [{"Key": k, "Value": v} for k, v in tags.items()],
        }]
    return req


def build_start_analysis_request(
    path_id: str,
    filter_in: list[str] | None = None,
    filter_out: list[str] | None = None,
    additional_accounts: list[str] | None = None,
    name: str | None = None,
) -> dict[str, Any]:
    """Build StartNetworkInsightsAnalysis kwargs: optional intermediate-component
    filters (ARNs), additional accounts for cross-account paths, and a Name tag."""
    req: dict[str, Any] = {"NetworkInsightsPathId": path_id}
    fin = validate_arns(filter_in, "--filter-in")
    fout = validate_arns(filter_out, "--filter-out")
    if fin and fout:
        raise ValidationError("--filter-in and --filter-out cannot be combined")
    if fin:
        req["FilterInArns"] = fin
    if fout:
        req["FilterOutArns"] = fout
    if additional_accounts:
        for acct in additional_accounts:
            if not (acct.isdigit() and len(acct) == 12):
                raise ValidationError(f"Invalid account ID {acct!r}")
        req["AdditionalAccounts"] = list(additional_accounts)
    if name:
        req["TagSpecifications"] = [{
            "ResourceType": "network-insights-analysis",
            "Tags": [{"Key": "Name", "Value": name}],
        }]
    return req


# ---------- EC2 API wrappers ----------

def create_path(ec2, request: dict[str, Any]) -> dict[str, Any]:
    """CreateNetworkInsightsPath. Returns the NetworkInsightsPath."""
    log.info("[EXECUTE] Creating network insights path %s -> %s",
             request["Source"], request.get("Destination") or request.get("DestinationIp"))
    path = ec2.create_network_insights_path(**request)["NetworkInsightsPath"]
    log.info("Created path %s", path["NetworkInsightsPathId"])
    return path


def start_analysis(ec2, request: dict[str, Any]) -> dict[str, Any]:
    """StartNetworkInsightsAnalysis. Returns the analysis in "running" state."""
    log.info("[EXECUTE] Starting analysis for path %s", request["NetworkInsightsPathId"])
    analysis = ec2.start_network_insights_analysis(**request)["NetworkInsightsAnalysis"]
    log.info("Started analysis %s", analysis["NetworkInsightsAnalysisId"])
    return analysis


def get_path(ec2, path_id: str) -> dict[str, Any]:
    """Describe one path. Raises LookupError if it doesn't exist."""
    log.debug("DescribeNetworkInsightsPaths %s", path_id)
    resp = ec2.describe_network_insights_paths(NetworkInsightsPathIds=[path_id])
    paths = resp.get("NetworkInsightsPaths", [])
    if not paths:
        raise LookupError(f"Path {path_id} not found")
    return paths[0]


def get_analysis(ec2, analysis_id: str) -> dict[str, Any]:
    """Describe one analysis (includes the full hop list and explanations)."""
    log.debug("DescribeNetworkInsightsAnalyses %s", analysis_id)
    resp = ec2.describe_network_insights_analyses(NetworkInsightsAnalysisIds=[analysis_id])
    items = resp.get("NetworkInsightsAnalyses", [])
    if not items:
        raise LookupError(f"Analysis {analysis_id} not found")
    return items[0]


def wait_for_analysis(ec2, analysis_id: str, timeout: int = 600, interval: int = 5) -> dict[str, Any]:
    """Poll until the analysis leaves "running" (succeeded or failed); TimeoutError after
    `timeout` seconds. Analyses usually finish in under a minute."""
    deadline = time.monotonic() + timeout
    while True:
        analysis = get_analysis(ec2, analysis_id)
        status = analysis.get("Status")
        if status != "running":
            log.info("Analysis %s finished: %s", analysis_id, status)
            return analysis
        if time.monotonic() >= deadline:
            raise TimeoutError(f"Analysis {analysis_id} still running after {timeout}s")
        log.info("Analysis %s running...", analysis_id)
        time.sleep(interval)


def iter_paths(ec2) -> Iterator[dict[str, Any]]:
    """All paths in the account/region (paginated)."""
    paginator = ec2.get_paginator("describe_network_insights_paths")
    for page in paginator.paginate():
        yield from page.get("NetworkInsightsPaths", [])


def iter_analyses(ec2, path_id: str | None = None) -> Iterator[dict[str, Any]]:
    """All analyses, or those for one path (paginated)."""
    paginator = ec2.get_paginator("describe_network_insights_analyses")
    params = {"NetworkInsightsPathId": path_id} if path_id else {}
    for page in paginator.paginate(**params):
        yield from page.get("NetworkInsightsAnalyses", [])


def delete_path(ec2, path_id: str) -> None:
    log.info("[EXECUTE] Deleting path %s", path_id)
    ec2.delete_network_insights_path(NetworkInsightsPathId=path_id)


def delete_analysis(ec2, analysis_id: str) -> None:
    log.info("[EXECUTE] Deleting analysis %s", analysis_id)
    ec2.delete_network_insights_analysis(NetworkInsightsAnalysisId=analysis_id)


# ---------- export helpers ----------

def _slug(text: str) -> str:
    """Filesystem-safe version of a Name tag for report file names."""
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-.")[:60]


def report_path(bundle: dict[str, Any], reports_dir: str | Path) -> Path:
    """Default report location: <reports_dir>/<YYYY-MM-DD>/<account-id>/[<name>_]<analysis-id>.html.

    The date is the analysis start date (UTC), so re-exporting an analysis lands in
    the same place. The account comes from the analysis ARN (the account that owns
    the analysis), never from the local AWS profile. A path-only bundle (no analysis)
    uses the path's creation date, ARN account, and path ID instead.
    """
    a = bundle.get("analysis") or {}
    p = bundle.get("path") or {}
    arn = a.get("NetworkInsightsAnalysisArn") or p.get("NetworkInsightsPathArn") or ""
    parts = arn.split(":")
    account = parts[4] if len(parts) > 5 and parts[4] else "unknown-account"

    started = a.get("StartDate") or (p.get("CreatedDate") if not a else None)
    if isinstance(started, str):
        try:
            started = dt.datetime.fromisoformat(started.replace("Z", "+00:00"))
        except ValueError:
            started = None
    if not isinstance(started, dt.datetime):
        started = dt.datetime.now(dt.timezone.utc)
    if started.tzinfo is None:
        started = started.replace(tzinfo=dt.timezone.utc)
    day = started.astimezone(dt.timezone.utc).strftime("%Y-%m-%d")

    aid = a.get("NetworkInsightsAnalysisId") or p.get("NetworkInsightsPathId") or "analysis"
    name = next((t.get("Value") for tags in (a.get("Tags"), p.get("Tags")) for t in tags or []
                 if t.get("Key") == "Name" and t.get("Value")), None)
    slug = _slug(name) if name else ""
    filename = f"{slug}_{aid}.html" if slug else f"{aid}.html"
    return Path(reports_dir) / day / account / filename


def build_bundle(path: dict[str, Any], analysis: dict[str, Any]) -> dict[str, Any]:
    """Assemble the export payload. Deliberately excludes the AWS profile and any
    session/credential details; only data returned by the EC2 API is included."""
    return {"path": path, "analysis": analysis}
