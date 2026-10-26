"""
Who owns a network interface: an EC2 instance, a load balancer, a Lambda function, an
RDS database, a VPC endpoint and so on.

Intent: name the resource behind each ENI that uses a security group, from the
DescribeNetworkInterfaces fields alone (attachment, interface type, description), so
no per-service API call or permission is needed. ENIs of the same resource (an
instance's interfaces, a load balancer's per-AZ interfaces) get the same identity.
"""
from __future__ import annotations

import re

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
