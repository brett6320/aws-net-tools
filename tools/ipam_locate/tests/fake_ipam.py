"""In-memory stand-in for the EC2 IPAM API, with a small synthetic organization.

Accounts: 111111111111 IPAM owner (network), 222222222222 app, 333333333333 reuses the
app VPC range, 444444444444 EU workload. Regions: us-east-1 (home), eu-west-1.
"""
from __future__ import annotations

import copy

from botocore.exceptions import ClientError

IPAM_ARN = "arn:aws:ec2::111111111111:ipam/ipam-0aaa"
PRIV_SCOPE = "arn:aws:ec2::111111111111:ipam-scope/ipam-scope-0priv"
PUB_SCOPE = "arn:aws:ec2::111111111111:ipam-scope/ipam-scope-0pub"
T = "2026-10-24T09:00:00+00:00"


def _pool(pid, depth, src=None, locale="None", name=None, scope=PRIV_SCOPE, fam="ipv4"):
    p = {"OwnerId": "111111111111", "IpamPoolId": pid, "IpamPoolArn": f"arn:aws:ec2::111111111111:ipam-pool/{pid}",
         "IpamScopeArn": scope, "IpamScopeType": "private" if scope == PRIV_SCOPE else "public",
         "IpamArn": IPAM_ARN, "IpamRegion": "us-east-1", "Locale": locale, "PoolDepth": depth,
         "State": "create-complete", "AddressFamily": fam}
    if src:
        p["SourceIpamPoolId"] = src
    if name:
        p["Tags"] = [{"Key": "Name", "Value": name}]
    return p


def _res(rtype, rid, cidr, owner, region, vpc=None, subnet=None, name=None, status=None):
    r = {"IpamResourceDiscoveryId": "ipam-res-disco-0def", "ResourceRegion": region, "ResourceId": rid,
         "ResourceOwnerId": owner, "ResourceCidr": cidr, "IpSource": "none" if rtype != "eip" else "amazon",
         "ResourceType": rtype, "ResourceTags": [{"Key": "Name", "Value": name}] if name else [],
         "SampleTime": T}
    if vpc:
        r["VpcId"] = vpc
    if subnet:
        r["SubnetId"] = subnet
    if status:
        r["NetworkInterfaceAttachmentStatus"] = status
    return r


STATE = {
    "ipams": [{"OwnerId": "111111111111", "IpamId": "ipam-0aaa", "IpamArn": IPAM_ARN, "IpamRegion": "us-east-1",
               "OperatingRegions": [{"RegionName": "us-east-1"}, {"RegionName": "eu-west-1"}],
               "Tier": "advanced", "DefaultResourceDiscoveryId": "ipam-res-disco-0def",
               "State": "create-complete"}],
    "scopes": [
        {"IpamScopeId": "ipam-scope-0priv", "IpamScopeArn": PRIV_SCOPE, "IpamArn": IPAM_ARN,
         "IpamScopeType": "private", "IsDefault": True},
        {"IpamScopeId": "ipam-scope-0pub", "IpamScopeArn": PUB_SCOPE, "IpamArn": IPAM_ARN,
         "IpamScopeType": "public", "IsDefault": True},
    ],
    "associations": [{"IpamResourceDiscoveryId": "ipam-res-disco-0def", "IpamId": "ipam-0aaa",
                      "IpamArn": IPAM_ARN, "State": "associate-complete", "IsDefault": True}],
    "discoveries": [{"IpamResourceDiscoveryId": "ipam-res-disco-0def", "OwnerId": "111111111111",
                     "IsDefault": True,
                     "OperatingRegions": [{"RegionName": "us-east-1"}, {"RegionName": "eu-west-1"}]}],
    "pools": [
        _pool("ipam-pool-0top", 1, name="org-10-8"),
        _pool("ipam-pool-0use1", 2, "ipam-pool-0top", "us-east-1", "use1"),
        _pool("ipam-pool-0euw1", 2, "ipam-pool-0top", "eu-west-1", "euw1"),
        _pool("ipam-pool-0prod", 3, "ipam-pool-0use1", "us-east-1", "use1-prod"),
        _pool("ipam-pool-0rsv", 2, "ipam-pool-0top", "None", "reserved"),
        _pool("ipam-pool-0v6", 1, name="v6", fam="ipv6"),
    ],
    "pool_cidrs": {
        "ipam-pool-0top": ["10.0.0.0/8"], "ipam-pool-0use1": ["10.1.0.0/16"], "ipam-pool-0euw1": ["10.2.0.0/16"],
        "ipam-pool-0prod": ["10.1.0.0/17"], "ipam-pool-0rsv": ["10.9.0.0/16"], "ipam-pool-0v6": ["2001:db8::/32"],
    },
    "allocations": {
        "ipam-pool-0top": [{"Cidr": c, "IpamPoolAllocationId": f"ipam-pool-alloc-{p}", "ResourceId": p,
                            "ResourceType": "ipam-pool", "ResourceRegion": "us-east-1",
                            "ResourceOwner": "111111111111"}
                           for c, p in (("10.1.0.0/16", "ipam-pool-0use1"), ("10.2.0.0/16", "ipam-pool-0euw1"),
                                        ("10.9.0.0/16", "ipam-pool-0rsv"))],
        "ipam-pool-0use1": [{"Cidr": "10.1.0.0/17", "IpamPoolAllocationId": "ipam-pool-alloc-prod",
                             "ResourceId": "ipam-pool-0prod", "ResourceType": "ipam-pool",
                             "ResourceRegion": "us-east-1", "ResourceOwner": "111111111111"}],
        "ipam-pool-0prod": [{"Cidr": "10.1.0.0/20", "IpamPoolAllocationId": "ipam-pool-alloc-app",
                             "ResourceId": "vpc-0app", "ResourceType": "vpc", "ResourceRegion": "us-east-1",
                             "ResourceOwner": "222222222222"}],
        "ipam-pool-0rsv": [], "ipam-pool-0euw1": [],
    },
    "resource_cidrs": {
        "us-east-1": [
            _res("vpc", "vpc-0app", "10.1.0.0/20", "222222222222", "us-east-1", name="app-prod"),
            _res("subnet", "subnet-0appa", "10.1.1.0/24", "222222222222", "us-east-1", "vpc-0app", name="app-a"),
            _res("eni", "eni-0app1", "10.1.1.25/32", "222222222222", "us-east-1", "vpc-0app", "subnet-0appa",
                 status="in-use"),
            _res("eni", "eni-0app2", "10.1.1.26/32", "222222222222", "us-east-1", "vpc-0app", "subnet-0appa",
                 status="available"),
            _res("eip", "eipalloc-0nat", "203.0.113.10/32", "222222222222", "us-east-1"),
        ],
        "eu-west-1": [
            _res("vpc", "vpc-0eu", "10.2.0.0/20", "444444444444", "eu-west-1", name="eu-app"),
            _res("subnet", "subnet-0eua", "10.2.1.0/24", "444444444444", "eu-west-1", "vpc-0eu"),
        ],
    },
    "public": {
        "us-east-1": [{"IpamResourceDiscoveryId": "ipam-res-disco-0def", "AddressRegion": "us-east-1",
                       "Address": "203.0.113.10", "AddressOwnerId": "222222222222",
                       "AddressAllocationId": "eipalloc-0nat", "AssociationStatus": "associated",
                       "AddressType": "amazon-owned-eip", "Service": "nat-gateway", "ServiceResource": "nat-0abc",
                       "VpcId": "vpc-0app", "SubnetId": "subnet-0pub", "NetworkInterfaceId": "eni-0nat",
                       "SampleTime": T}],
        "eu-west-1": [],
    },
    "history": {
        ("10.1.1.25/32", "ipam-scope-0priv"): [
            {"ResourceOwnerId": "222222222222", "ResourceRegion": "us-east-1", "ResourceType": "network-interface",
             "ResourceId": "eni-0app1", "ResourceCidr": "10.1.1.25/32", "VpcId": "vpc-0app",
             "SampledStartTime": T},
            {"ResourceOwnerId": "222222222222", "ResourceRegion": "us-east-1", "ResourceType": "instance",
             "ResourceId": "i-0app1", "ResourceName": "app-1", "ResourceCidr": "10.1.1.25/32", "VpcId": "vpc-0app",
             "SampledStartTime": T},
            {"ResourceOwnerId": "222222222222", "ResourceRegion": "us-east-1", "ResourceType": "instance",
             "ResourceId": "i-0old", "ResourceCidr": "10.1.1.25/32", "VpcId": "vpc-0app",
             "SampledStartTime": "2026-01-01T00:00:00+00:00", "SampledEndTime": "2026-02-01T00:00:00+00:00"},
        ],
    },
}


class FakeEC2:
    """Implements the read calls il_core makes. `fail` maps an op name to an error code."""

    def __init__(self, state=None, fail=None):
        self.state = copy.deepcopy(state or STATE)
        self.fail = fail or {}
        self.calls: list[tuple[str, dict]] = []

    def can_paginate(self, op):
        return False

    def _call(self, op, params):
        self.calls.append((op, params))
        if op in self.fail:
            raise ClientError({"Error": {"Code": self.fail[op], "Message": "denied"}}, op)

    def describe_ipams(self, **kw):
        self._call("describe_ipams", kw)
        ids = kw.get("IpamIds")
        return {"Ipams": [i for i in self.state["ipams"] if not ids or i["IpamId"] in ids]}

    def describe_ipam_scopes(self, **kw):
        self._call("describe_ipam_scopes", kw)
        return {"IpamScopes": self.state["scopes"]}

    def describe_ipam_resource_discovery_associations(self, **kw):
        self._call("describe_ipam_resource_discovery_associations", kw)
        return {"IpamResourceDiscoveryAssociations": self.state["associations"]}

    def describe_ipam_resource_discoveries(self, **kw):
        self._call("describe_ipam_resource_discoveries", kw)
        return {"IpamResourceDiscoveries": self.state["discoveries"]}

    def describe_ipam_pools(self, **kw):
        self._call("describe_ipam_pools", kw)
        return {"IpamPools": self.state["pools"]}

    def get_ipam_pool_cidrs(self, IpamPoolId, **kw):
        self._call("get_ipam_pool_cidrs", {"IpamPoolId": IpamPoolId})
        return {"IpamPoolCidrs": [{"Cidr": c, "State": "provisioned", "IpamPoolCidrId": f"cidr-{c}"}
                                  for c in self.state["pool_cidrs"].get(IpamPoolId, [])]}

    def get_ipam_pool_allocations(self, IpamPoolId, **kw):
        self._call("get_ipam_pool_allocations", {"IpamPoolId": IpamPoolId})
        return {"IpamPoolAllocations": self.state["allocations"].get(IpamPoolId, [])}

    def get_ipam_discovered_resource_cidrs(self, IpamResourceDiscoveryId, ResourceRegion, **kw):
        self._call("get_ipam_discovered_resource_cidrs", {"ResourceRegion": ResourceRegion})
        return {"IpamDiscoveredResourceCidrs": self.state["resource_cidrs"].get(ResourceRegion, [])}

    def get_ipam_discovered_public_addresses(self, IpamResourceDiscoveryId, AddressRegion, **kw):
        self._call("get_ipam_discovered_public_addresses", {"AddressRegion": AddressRegion})
        return {"IpamDiscoveredPublicAddresses": self.state["public"].get(AddressRegion, [])}

    def get_ipam_address_history(self, Cidr, IpamScopeId, **kw):
        self._call("get_ipam_address_history", {"Cidr": Cidr, "IpamScopeId": IpamScopeId})
        return {"HistoryRecords": self.state["history"].get((Cidr, IpamScopeId), [])}
