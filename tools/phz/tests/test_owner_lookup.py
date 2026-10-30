"""VPC owner lookup: IPAM bulk pull first, then the PHZ account, then a batched search of other accounts."""
import argparse

import pytest
from botocore.exceptions import ClientError

from conftest import load_tool

pr = load_tool("phz_review")

PHZ, A, B = "111111111111", "222222222222", "333333333333"


class FakeEc2:
    """Answers DescribeVpcs / IPAM calls from a fixed view, and records every call."""

    def __init__(self, visible=None, ipam_rows=None, error=None, calls=None):
        self.visible = visible or {}  # vpc_id -> owner
        self.ipam_rows = ipam_rows or []
        self.error = error
        self.calls = calls if calls is not None else []

    def get_paginator(self, op):
        ec2 = self

        class P:
            def paginate(self, **kw):
                ec2.calls.append((op, kw))
                if ec2.error:
                    raise ec2.error
                if op == "describe_vpcs":
                    ids = kw["Filters"][0]["Values"]
                    yield {"Vpcs": [{"VpcId": v, "OwnerId": ec2.visible[v]} for v in ids if v in ec2.visible]}
                else:
                    yield {"IpamResourceCidrs": ec2.ipam_rows}

        return P()

    def describe_ipams(self, **kw):
        self.calls.append(("describe_ipams", kw))
        return {"Ipams": [{"IpamId": "ipam-1", "PrivateDefaultScopeId": "scope-1"}]}


def pairs(*vpcs, region="us-east-1"):
    return {(region, v) for v in vpcs}


def test_find_owners_batches_and_stops_once_everything_is_found():
    calls = []
    clients = {
        PHZ: FakeEc2({"vpc-1": PHZ}, calls=calls),
        A: FakeEc2({"vpc-2": A, "vpc-3": B}, calls=calls),  # vpc-3 is shared to A; OwnerId is still B
        B: FakeEc2({"vpc-3": B}, calls=calls),
    }
    owners = pr.find_owners(pairs("vpc-1", "vpc-2", "vpc-3"), [PHZ, A, B], lambda a, r: clients[a])
    assert owners == {"vpc-1": PHZ, "vpc-2": A, "vpc-3": B}
    assert len(calls) == 2  # B never queried
    assert calls[1][1]["Filters"][0]["Values"] == ["vpc-2", "vpc-3"]  # only the VPCs still unknown, in one call


def test_find_owners_skips_accounts_it_cannot_reach(caplog):
    denied = ClientError({"Error": {"Code": "UnauthorizedOperation", "Message": "no"}}, "DescribeVpcs")

    def client_for(account, region):
        if account == A:
            raise PermissionError("no profile maps to it")
        if account == B:
            return FakeEc2(error=denied)
        return FakeEc2({"vpc-9": "444444444444"})

    owners = pr.find_owners(pairs("vpc-9"), [A, B, "444444444444"], client_for)
    assert owners == {"vpc-9": "444444444444"}
    assert "couldn't query 2 account(s)" in caplog.text


def test_ipam_vpc_owners_is_one_bulk_pull():
    calls = []
    rows = [{"ResourceId": "vpc-1", "ResourceOwnerId": A}, {"ResourceId": "vpc-1", "ResourceOwnerId": A},
            {"ResourceId": "vpc-2", "ResourceOwnerId": B}]
    owners = pr.ipam_vpc_owners(FakeEc2(ipam_rows=rows, calls=calls))
    assert owners == {"vpc-1": A, "vpc-2": B}
    assert calls == [("describe_ipams", {}), ("get_ipam_resource_cidrs",
                     {"IpamScopeId": "scope-1", "ResourceType": "vpc", "PaginationConfig": {"PageSize": 1000}})]


def args(**kw):
    base = dict(ipam_profile=None, ipam_region=None, ipam_id=None, no_owner_search=False, owner_accounts=None)
    return argparse.Namespace(**{**base, **kw})


class FakeSessions:
    def __init__(self, clients, caller=PHZ):
        self.clients, self.caller_account = clients, caller

    def client(self, service, account=None, region=None):
        return self.clients[account or self.caller_account]


class FakeCtx:
    phz_account = PHZ
    region = "us-east-1"

    def __init__(self, clients):
        self.clients = clients

    def phz_sessions(self):
        return FakeSessions(self.clients)

    def vpc_sessions(self):
        return FakeSessions(self.clients)


def test_resolve_uses_ipam_first_and_skips_per_account_calls(monkeypatch):
    calls = []
    ipam = FakeEc2(ipam_rows=[{"ResourceId": "vpc-1", "ResourceOwnerId": A}, {"ResourceId": "vpc-2", "ResourceOwnerId": B}])
    monkeypatch.setattr(pr, "AccountSessions", lambda *a, **k: FakeSessions({PHZ: ipam}))
    ctx = FakeCtx({PHZ: FakeEc2(calls=calls), A: FakeEc2(calls=calls)})
    owners = pr.resolve_vpc_owners(args(ipam_profile="ipam", owner_accounts=A), ctx, pairs("vpc-1", "vpc-2"))
    assert owners == {"vpc-1": A, "vpc-2": B}
    assert calls == []  # IPAM answered everything


def test_resolve_falls_back_to_phz_account_then_search():
    calls = []
    ctx = FakeCtx({PHZ: FakeEc2({"vpc-1": PHZ}, calls=calls), A: FakeEc2({"vpc-2": A}, calls=calls)})
    owners = pr.resolve_vpc_owners(args(owner_accounts=f"{A},{PHZ}"), ctx, pairs("vpc-1", "vpc-2"))
    assert owners == {"vpc-1": PHZ, "vpc-2": A}
    assert [c[1]["Filters"][0]["Values"] for c in calls] == [["vpc-1", "vpc-2"], ["vpc-2"]]  # PHZ account not searched twice

    calls.clear()
    owners = pr.resolve_vpc_owners(args(owner_accounts=A, no_owner_search=True), ctx, pairs("vpc-1", "vpc-2"))
    assert owners == {"vpc-1": PHZ} and len(calls) == 1


def test_search_accounts_default_to_local_profiles(monkeypatch):
    monkeypatch.setattr(pr, "profile_accounts", lambda: {"a-ro": A, "a-priv": "999999999999", "b": B, "b-ro": B})
    assert pr.owner_search_accounts(args(), FakeCtx({})) == [A, B]
    with pytest.raises(ValueError):
        pr.owner_search_accounts(args(owner_accounts="12345"), FakeCtx({}))
