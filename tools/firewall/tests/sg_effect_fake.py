"""Synthetic EC2 data and an in-memory fake of the calls sg_effect makes.

Groups:
  web   (target)  in tcp 443/80 from anywhere, tcp 22 from the corp prefix list,
                  everything from itself; out everything
  base            in tcp 22 and ICMP from 10.0.0.0/8; out everything
  admin           in all TCP from 10.1.0.0/16, tcp 443 from anywhere
  db              in tcp 5432-5433 from web, tcp 5433 from base, tcp 6379 from a group it can't read
"""
from __future__ import annotations

import copy

from botocore.exceptions import ClientError

ACCOUNT = "111122223333"
VPC = "vpc-0123456789abcdef0"
WEB, BASE, ADMIN, DB = ("sg-0aaa1111bbbb22223", "sg-0bbb2222cccc33334", "sg-0ccc3333dddd44445",
                        "sg-0ddd4444eeee55556")
PEERED = "sg-0eee5555ffff66667"     # referenced, but not readable
CORP = "pl-0123456789abcdef0"


def group(gid, name, desc=""):
    return {"GroupId": gid, "GroupName": name, "Description": desc or name, "VpcId": VPC, "OwnerId": ACCOUNT,
            "Tags": [{"Key": "Name", "Value": name}]}


def rule(rid, gid, egress, proto, lo, hi, **peer):
    r = {"SecurityGroupRuleId": rid, "GroupId": gid, "GroupOwnerId": ACCOUNT, "IsEgress": egress,
         "IpProtocol": proto, "FromPort": lo, "ToPort": hi}
    if "sg" in peer:
        r["ReferencedGroupInfo"] = {"GroupId": peer.pop("sg"), "UserId": ACCOUNT}
    r.update(peer)
    return r


def eni(eid, groups, ip, desc="", instance=None, itype="interface", requester=False):
    e = {"NetworkInterfaceId": eid, "Description": desc, "InterfaceType": itype, "Status": "in-use",
         "SubnetId": "subnet-0a1b2c3d4e5f60718", "VpcId": VPC, "AvailabilityZone": "us-east-1a",
         "PrivateIpAddress": ip, "PrivateIpAddresses": [{"PrivateIpAddress": ip}],
         "Groups": [{"GroupId": g, "GroupName": g} for g in groups], "RequesterManaged": requester,
         "OwnerId": ACCOUNT}
    if instance:
        e["Attachment"] = {"InstanceId": instance}
    return e


def data():
    return {
        "groups": [group(WEB, "web-sg", "web tier"), group(BASE, "base-sg"), group(ADMIN, "admin-sg"),
                   group(DB, "db-sg")],
        "rules": [
            rule("sgr-0web0443", WEB, False, "tcp", 443, 443, CidrIpv4="0.0.0.0/0", Description="https"),
            rule("sgr-0web0080", WEB, False, "tcp", 80, 80, CidrIpv4="0.0.0.0/0"),
            rule("sgr-0web0022", WEB, False, "tcp", 22, 22, PrefixListId=CORP),
            rule("sgr-0webself", WEB, False, "-1", -1, -1, sg=WEB),
            rule("sgr-0web0out", WEB, True, "-1", -1, -1, CidrIpv4="0.0.0.0/0"),
            rule("sgr-0base022", BASE, False, "tcp", 22, 22, CidrIpv4="10.0.0.0/8"),
            rule("sgr-0baseicm", BASE, False, "icmp", -1, -1, CidrIpv4="10.0.0.0/8"),
            rule("sgr-0baseout", BASE, True, "-1", -1, -1, CidrIpv4="0.0.0.0/0"),
            rule("sgr-0admtcp0", ADMIN, False, "tcp", 0, 65535, CidrIpv4="10.1.0.0/16"),
            rule("sgr-0adm0443", ADMIN, False, "tcp", 443, 443, CidrIpv4="0.0.0.0/0"),
            rule("sgr-0db05432", DB, False, "tcp", 5432, 5433, sg=WEB),
            rule("sgr-0db05433", DB, False, "tcp", 5433, 5433, sg=BASE),
            rule("sgr-0dbpeer0", DB, False, "tcp", 6379, 6379, sg=PEERED),
        ],
        "enis": [
            eni("eni-0web1000000000001", [WEB, BASE], "10.0.1.11", "", instance="i-0web1000000000001"),
            eni("eni-0web2000000000001", [WEB, BASE], "10.0.1.12", "", instance="i-0web2000000000002"),
            eni("eni-0web2000000000002", [WEB], "10.0.2.12", "", instance="i-0web2000000000002"),
            eni("eni-0alb1000000000001", [WEB, ADMIN], "10.0.1.21", "ELB app/web-alb/0123456789abcdef",
                requester=True),
            eni("eni-0alb1000000000002", [WEB, ADMIN], "10.0.2.21", "ELB app/web-alb/0123456789abcdef",
                requester=True),
            eni("eni-0lam1000000000001", [WEB], "10.0.3.31",
                "AWS Lambda VPC ENI-api-fn-0a1b2c3d-1111-2222-3333-444455556666", itype="lambda", requester=True),
            eni("eni-0rds1000000000001", [DB], "10.0.4.41", "RDSNetworkInterface", requester=True),
        ],
        "prefix_lists": [{"PrefixListId": CORP, "PrefixListName": "corp-networks", "AddressFamily": "IPv4"}],
        "pl_entries": {CORP: [{"Cidr": "10.0.0.0/8"}, {"Cidr": "192.168.0.0/16"}]},
        "instances": {"i-0web1000000000001": "web-1", "i-0web2000000000002": "web-2"},
    }


def denied(op, code="UnauthorizedOperation"):
    return ClientError({"Error": {"Code": code, "Message": "no"}}, op)


class _Paginator:
    def __init__(self, fn):
        self.fn = fn

    def paginate(self, **params):
        items = self.fn(**params)
        key, rows = items
        for i in range(0, max(len(rows), 1), 2):        # pages of two
            yield {key: copy.deepcopy(rows[i:i + 2])}


class FakeEC2:
    def __init__(self, d=None, fail=()):
        self.d = d or data()
        self.fail = set(fail)
        self.calls: list[str] = []

    def _check(self, op):
        self.calls.append(op)
        if op in self.fail:
            raise denied(op)

    def get_paginator(self, op):
        return _Paginator(getattr(self, "_" + op))

    def describe_security_groups(self, GroupIds):
        self._check("describe_security_groups")
        found = [g for g in self.d["groups"] if g["GroupId"] in GroupIds]
        if len(found) < len(GroupIds):
            raise denied("DescribeSecurityGroups", "InvalidGroup.NotFound")
        return {"SecurityGroups": copy.deepcopy(found)}

    def _describe_security_groups(self, GroupIds=None, Filters=None):
        self._check("describe_security_groups")
        if GroupIds is not None:
            found = [g for g in self.d["groups"] if g["GroupId"] in GroupIds]
            if len(found) < len(GroupIds):
                raise denied("DescribeSecurityGroups", "InvalidGroup.NotFound")
            return "SecurityGroups", found
        f = Filters[0]
        egress = f["Name"].startswith("egress.")
        if egress and "egress_filter" in self.fail:
            raise denied("DescribeSecurityGroups")
        gids = {r["GroupId"] for r in self.d["rules"] if r["IsEgress"] == egress
                and (r.get("ReferencedGroupInfo") or {}).get("GroupId") in f["Values"]}
        return "SecurityGroups", [g for g in self.d["groups"] if g["GroupId"] in gids]

    def _describe_security_group_rules(self, Filters):
        self._check("describe_security_group_rules")
        ids = Filters[0]["Values"]
        return "SecurityGroupRules", [r for r in self.d["rules"] if r["GroupId"] in ids]

    def _describe_network_interfaces(self, Filters):
        self._check("describe_network_interfaces")
        ids = set(Filters[0]["Values"])
        return "NetworkInterfaces", [e for e in self.d["enis"] if ids & {g["GroupId"] for g in e["Groups"]}]

    def _describe_managed_prefix_lists(self, PrefixListIds):
        self._check("describe_managed_prefix_lists")
        return "PrefixLists", [p for p in self.d["prefix_lists"] if p["PrefixListId"] in PrefixListIds]

    def _get_managed_prefix_list_entries(self, PrefixListId):
        self._check("get_managed_prefix_list_entries")
        return "Entries", self.d["pl_entries"].get(PrefixListId, [])

    def _describe_instances(self, InstanceIds):
        self._check("describe_instances")
        rows = [{"Instances": [{"InstanceId": i, "Tags": [{"Key": "Name", "Value": n}]}]}
                for i, n in self.d["instances"].items() if i in InstanceIds]
        return "Reservations", rows
