"""Owner map -> VPC, owner profile, subnets -> RAM shares -> principals (in-memory fakes), and OU expansion."""
import json

import pytest
from botocore.exceptions import ClientError

import vp_core as core
import vpc_participants as vp

OWNER, P1, P2, P3, MGMT = "111111111111", "222222222222", "333333333333", "444444444444", "999999999999"
REGION = "us-east-1"
ORG = "o-abcde12345"
OU_PROD = "ou-ab12-11111111"
OU_WEB = "ou-ab12-22222222"
OU_ARN = f"arn:aws:organizations::{MGMT}:ou/{ORG}/{OU_PROD}"
ORG_ARN = f"arn:aws:organizations::{MGMT}:organization/{ORG}"
SHARE_A = f"arn:aws:ram:{REGION}:{OWNER}:resource-share/aaaa"
SHARE_B = f"arn:aws:ram:{REGION}:{OWNER}:resource-share/bbbb"
SHARE_OLD = f"arn:aws:ram:{REGION}:{OWNER}:resource-share/dead"


def sn_arn(subnet_id, account=OWNER):
    return f"arn:aws:ec2:{REGION}:{account}:subnet/{subnet_id}"


def denied(op="X"):
    return ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, op)


# --------------------------------------------------------------------------- fakes


class Client:
    """Paginated ops from a dict: op -> fn(**kw) -> list of items; other ops as plain methods."""

    def __init__(self, pages=None, key=None, **methods):
        self.pages, self.key, self.calls = pages or {}, key or {}, []
        for name, fn in methods.items():
            setattr(self, name, fn)

    def get_paginator(self, op):
        client = self

        class P:
            def paginate(self, **kw):
                client.calls.append((op, kw))
                items = client.pages[op](**kw)
                if isinstance(items, Exception):
                    raise items
                yield {client.key[op]: items}

        return P()


class Session:
    def __init__(self, account, clients):
        self.account, self.clients = account, clients

    def client(self, name, region_name=None, config=None):
        if name == "sts":
            return Client(get_caller_identity=lambda: {"Account": self.account})
        return self.clients[name]

    def get_partition_for_region(self, region):
        return "aws"


SUBNETS = [
    {"SubnetId": "subnet-0001", "VpcId": "vpc-00000001", "OwnerId": OWNER, "CidrBlock": "10.0.0.0/24",
     "AvailabilityZone": "us-east-1a", "SubnetArn": sn_arn("subnet-0001"), "Tags": [{"Key": "Name", "Value": "a"}]},
    {"SubnetId": "subnet-0002", "VpcId": "vpc-00000001", "OwnerId": OWNER, "CidrBlock": "10.0.1.0/24"},  # no ARN
    {"SubnetId": "subnet-0003", "VpcId": "vpc-00000001", "OwnerId": OWNER, "CidrBlock": "10.0.2.0/24",
     "SubnetArn": sn_arn("subnet-0003")},
    {"SubnetId": "subnet-0009", "VpcId": "vpc-00000002", "OwnerId": OWNER, "CidrBlock": "10.9.0.0/24",
     "SubnetArn": sn_arn("subnet-0009")},
]
RESOURCES = [
    {"arn": sn_arn("subnet-0001"), "resourceShareArn": SHARE_A, "status": "AVAILABLE"},
    {"arn": sn_arn("subnet-0002"), "resourceShareArn": SHARE_A, "status": "AVAILABLE"},
    {"arn": sn_arn("subnet-0002"), "resourceShareArn": SHARE_B, "status": "AVAILABLE"},
    {"arn": sn_arn("subnet-0003"), "resourceShareArn": SHARE_OLD, "status": "UNAVAILABLE"},
    {"arn": sn_arn("subnet-9999"), "resourceShareArn": SHARE_A, "status": "AVAILABLE"},  # another VPC's
]
SHARES = [
    {"resourceShareArn": SHARE_A, "name": "prod-subnets", "status": "ACTIVE", "allowExternalPrincipals": False},
    {"resourceShareArn": SHARE_B, "name": "web-subnets", "status": "ACTIVE"},
    {"resourceShareArn": SHARE_OLD, "name": "old", "status": "DELETING"},
]
ASSOCIATIONS = [
    {"associatedEntity": P1, "resourceShareArn": SHARE_A, "status": "ASSOCIATED", "external": False},
    {"associatedEntity": P2, "resourceShareArn": SHARE_A, "status": "DISASSOCIATED"},
    {"associatedEntity": P1, "resourceShareArn": SHARE_B, "status": "ASSOCIATED"},
    {"associatedEntity": OU_ARN, "resourceShareArn": SHARE_B, "status": "ASSOCIATED"},
    {"associatedEntity": P3, "resourceShareArn": SHARE_OLD, "status": "ASSOCIATED"},
]


def owner_clients(subnets=SUBNETS, resources=RESOURCES, shares=SHARES, assocs=ASSOCIATIONS):
    def describe_subnets(Filters):
        want = Filters[0]["Values"]
        return [s for s in subnets if s["VpcId"] in want]

    def list_resources(resourceArns, **kw):
        assert kw == {"resourceOwner": "SELF", "resourceType": "ec2:Subnet"}
        assert len(resourceArns) <= core.CHUNK
        return [r for r in resources if r["arn"] in resourceArns or r["arn"].endswith("9999")]

    def get_resource_shares(resourceShareArns, resourceOwner):
        return [s for s in shares if s["resourceShareArn"] in resourceShareArns]

    def get_resource_share_associations(resourceShareArns, associationType):
        assert associationType == "PRINCIPAL"
        return [a for a in assocs if a["resourceShareArn"] in resourceShareArns]

    ec2 = Client({"describe_subnets": describe_subnets}, {"describe_subnets": "Subnets"})
    ram = Client({"list_resources": list_resources, "get_resource_shares": get_resource_shares,
                  "get_resource_share_associations": get_resource_share_associations},
                 {"list_resources": "resources", "get_resource_shares": "resourceShares",
                  "get_resource_share_associations": "resourceShareAssociations"})
    return {"ec2": ec2, "ram": ram}


def entry(account=OWNER, name="shared-vpc", account_name="network", ou_id=OU_PROD, ou_path="Root/Prod"):
    return {"account": account, "source": "ou_vpcs", "seen": "2026-11-01", "account_name": account_name,
            "ou_id": ou_id, "ou_path": ou_path, "name": name, "cidrs": ["10.0.0.0/16"]}


@pytest.fixture
def cache(tmp_path):
    path = tmp_path / "vpc-owners.json"
    path.write_text(json.dumps({
        f"{REGION}/vpc-00000001": entry(),
        f"{REGION}/vpc-00000002": entry(name="other"),
        f"{REGION}/vpc-00000aaa": entry(account=P1, account_name="app-one", name="app"),
        f"{REGION}/vpc-00000bbb": entry(account=P3, account_name="web-three", ou_id=OU_WEB, ou_path="Root/Prod/Web"),
        f"{REGION}/vpc-00000ccc": entry(account=P2, account_name="dev-two", ou_id="ou-ab12-33333333", ou_path="Root/Dev"),
        f"{REGION}/vpc-00000ddd": {"account": "555555555555", "source": "phz_review"},  # thin entry
        "ca-central-1/vpc-00000ddd": {"account": "555555555555", "source": "phz_review"},
        "junk": {"account": OWNER},
    }))
    return path


# --------------------------------------------------------------------------- input


def test_load_and_find(cache):
    catalog = core.load_vpcs(cache)
    assert len(catalog) == 7
    assert [v.account for v in core.find_vpcs(catalog, ["vpc-00000001"])] == [OWNER]
    with pytest.raises(ValueError, match="several Regions"):
        core.find_vpcs(catalog, ["vpc-00000ddd"])
    assert core.find_vpcs(catalog, ["vpc-00000ddd"], ["ca-central-1"])[0].region == "ca-central-1"
    with pytest.raises(ValueError, match="not in the VPC owner map"):
        core.find_vpcs(catalog, ["vpc-0000ffff"])
    for bad, regions in ((["subnet-1"], None), ([], None), (["vpc-00000001"], ["useast1"])):
        with pytest.raises(ValueError):
            core.find_vpcs(catalog, bad, regions)


def test_bad_input_exits_2(cache, tmp_path):
    assert vp.main(["vpc-00000001", "--cache", str(tmp_path / "none.json"), "-q"]) == 2
    assert vp.main(["vpc-0000ffff", "--cache", str(cache), "-q"]) == 2
    assert vp.main(["vpc-00000001", "--cache", str(cache), "--account-profile", "nope", "-q"]) == 2
    (tmp_path / "bad.json").write_text("{")
    assert vp.main(["vpc-00000001", "--cache", str(tmp_path / "bad.json"), "-q"]) == 2


def test_principal_type():
    assert core.principal_type(P1) == "account"
    assert core.principal_type(OU_ARN) == "ou"
    assert core.principal_type(ORG_ARN) == "organization"
    assert core.principal_type("arn:aws:iam::111111111111:role/x") == "other"


def test_resolve_profile(aws_config):
    aws_config({"net": OWNER, "net-adm": OWNER, "net-RO": OWNER, "a": P1, "b-readonly": P1, "x": P2, "y": P2})
    assert core.resolve_profile(OWNER) == "net"
    assert core.resolve_profile(P1) == "b-readonly"
    assert core.resolve_profile(P1, preferred="a") == "a"
    assert core.resolve_profile(P2, {P2: "z"}) == "z"
    with pytest.raises(LookupError, match="several"):
        core.resolve_profile(P2)
    with pytest.raises(LookupError, match="no profile"):
        core.resolve_profile(P3)


# --------------------------------------------------------------------------- lookups


def run(cache, argv, clients=None, org=None, account=OWNER, capsys=None):
    clients = clients or owner_clients()
    sessions = []

    def session_for(profile):
        if profile == "org":
            return Session(MGMT, {"organizations": org})
        sessions.append(profile)
        return Session(account, clients)

    code = vp.main(["--cache", str(cache), "--account-profile", f"{OWNER}=net", "-q", *argv], session_for=session_for)
    return code, sessions


def test_owner_and_participants(cache, capsys):
    code, sessions = run(cache, ["vpc-00000001", "vpc-00000002", "--json"])
    assert code == 0
    assert sessions == ["net"]  # one session for both VPCs of the account
    rows = json.loads(capsys.readouterr().out)
    one = [r for r in rows if r["vpc_id"] == "vpc-00000001"]
    assert [(r["role"], r["principal"]) for r in one] == [("owner", OWNER), ("participant", P1), ("participant", OU_ARN)]
    owner, p1, ou = one
    assert owner["principal_name"] == "network" and owner["subnets"] == ["subnet-0001", "subnet-0002", "subnet-0003"]
    # P1 through both shares; P2's association is gone; the deleting share's P3 is left out
    assert p1["principal_name"] == "app-one" and p1["shares"] == ["prod-subnets", "web-subnets"]
    assert p1["subnets"] == ["subnet-0001", "subnet-0002"] and p1["status"] == "ASSOCIATED"
    # OU from the catalog: Root/Prod and below, so the OU's own accounts plus Root/Prod/Web, not Root/Dev
    assert ou["principal_type"] == "ou" and ou["principal_name"] == "Root/Prod"
    assert ou["subnets"] == ["subnet-0002"]
    assert ou["members"] == [OWNER, P1, P3] and ou["members_source"] == "catalog"
    two = [r for r in rows if r["vpc_id"] == "vpc-00000002"]
    assert [(r["role"], r["subnets"]) for r in two] == [("owner", ["subnet-0009"])]


def test_all_statuses(cache, capsys):
    assert run(cache, ["vpc-00000001", "--all-statuses", "--json"])[0] == 0
    principals = {r["principal"]: r for r in json.loads(capsys.readouterr().out)}
    assert principals[P2]["status"] == "DISASSOCIATED"
    assert principals[P3]["subnets"] == ["subnet-0003"]


def test_no_shared_subnets_means_owner_only(cache, capsys):
    clients = owner_clients(resources=[])
    assert run(cache, ["vpc-00000001", "--json"], clients=clients)[0] == 0
    assert [r["role"] for r in json.loads(capsys.readouterr().out)] == ["owner"]
    assert [c[0] for c in clients["ram"].calls] == ["list_resources"]


def test_no_subnets_means_no_ram_calls(cache, capsys):
    clients = owner_clients(subnets=[])
    assert run(cache, ["vpc-00000001"], clients=clients)[0] == 0
    assert clients["ram"].calls == []
    assert "owner" in capsys.readouterr().out


def test_subnet_arns_are_chunked(cache, capsys):
    many = [{"SubnetId": f"subnet-{i:04x}", "VpcId": "vpc-00000001", "OwnerId": OWNER} for i in range(45)]
    clients = owner_clients(subnets=many, resources=[])
    assert run(cache, ["vpc-00000001"], clients=clients)[0] == 0
    assert [len(c[1]["resourceArns"]) for c in clients["ram"].calls] == [20, 20, 5]


def test_wrong_account_or_ram_error_still_prints_the_rest(cache, capsys, aws_config):
    aws_config({"app": P1})
    clients = owner_clients()
    clients["ram"].pages["list_resources"] = lambda **kw: denied("ListResources")

    def session_for(profile):
        return Session(P2 if profile == "app" else OWNER, clients)

    code = vp.main(["vpc-00000001", "vpc-00000aaa", "--cache", str(cache), "--account-profile", f"{OWNER}=net",
                    "--json", "-q"], session_for=session_for)
    assert code == vp.ERROR_EXIT
    rows = json.loads(capsys.readouterr().out)
    assert [(r["vpc_id"], r["status"]) for r in rows] == [("vpc-00000001", "error"), ("vpc-00000aaa", "error")]
    assert "AccessDenied" in rows[0]["error"] and f"authenticates as {P2}" in rows[1]["error"]


def test_no_profile_for_owner(cache, capsys):
    assert vp.main(["vpc-00000aaa", "--cache", str(cache), "-q"], session_for=lambda p: None) == vp.ERROR_EXIT
    assert "no profile" in capsys.readouterr().out


def test_external_and_iam_principals_are_flagged(cache, capsys, caplog):
    assocs = [{"associatedEntity": "777777777777", "resourceShareArn": SHARE_A, "status": "ASSOCIATED", "external": True},
              {"associatedEntity": "arn:aws:iam::777777777777:role/r", "resourceShareArn": SHARE_A, "status": "ASSOCIATED"},
              {"associatedEntity": ORG_ARN, "resourceShareArn": SHARE_A, "status": "ASSOCIATING"}]
    code, _ = run(cache, ["vpc-00000001", "--json", "-o", "csv"], clients=owner_clients(assocs=assocs))
    assert code == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("vpc_id,region,vpc_name,owner,role")
    assert any("777777777777" in line and ",yes," in line for line in out)
    assert any(",organization," in line and "catalog" in line for line in out)  # all accounts the map knows
    assert sum("subnet sharing doesn't normally allow" in m for m in caplog.messages) == 2


def test_table_output(cache, capsys):
    assert run(cache, ["vpc-00000001"])[0] == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0].split()[:4] == ["VPC_ID", "REGION", "VPC_NAME", "ROLE"]
    assert out[-1].rstrip().endswith("3")  # the OU row's member count
    vp.render([], "table")
    assert "(no results)" in capsys.readouterr().out


# --------------------------------------------------------------------------- organizations


def fake_org(fail=False, org_id=ORG):
    tree = {"r-ab12": ([], [OU_PROD]), OU_PROD: ([(OWNER, "network"), (P1, "app-one")], [OU_WEB]),
            OU_WEB: ([(P3, "web-three"), ("666666666666", "no-vpcs")], [])}

    def accounts(ParentId):
        if fail:
            return denied("ListAccountsForParent")
        return [{"Id": i, "Name": n, "State": "ACTIVE"} for i, n in tree[ParentId][0]] + \
            ([{"Id": "888888888888", "Name": "gone", "State": "SUSPENDED"}] if ParentId == OU_WEB else [])

    return Client(
        {"list_accounts_for_parent": accounts,
         "list_organizational_units_for_parent": lambda ParentId: [{"Id": o} for o in tree[ParentId][1]]},
        {"list_accounts_for_parent": "Accounts", "list_organizational_units_for_parent": "OrganizationalUnits"},
        describe_account=lambda AccountId: {"Account": {"Name": {P2: "dev-two-org"}.get(AccountId, "")}}
        if AccountId != "000000000000" else (_ for _ in ()).throw(denied()),
        describe_organizational_unit=lambda OrganizationalUnitId: {"OrganizationalUnit": {"Name": "X"}},
        list_parents=lambda ChildId: {"Parents": [{"Id": "r-ab12"}]},
        describe_organization=lambda: {"Organization": {"Id": org_id}},
        list_roots=lambda: {"Roots": [{"Id": "r-ab12"}]},
    )


def test_org_profile_expands_ous(cache, capsys):
    assocs = ASSOCIATIONS + [{"associatedEntity": ORG_ARN, "resourceShareArn": SHARE_A, "status": "ASSOCIATED"}]
    code, _ = run(cache, ["vpc-00000001", "--org-profile", "org", "--json"], clients=owner_clients(assocs=assocs),
                  org=fake_org())
    assert code == 0
    rows = {r["principal"]: r for r in json.loads(capsys.readouterr().out)}
    assert rows[OU_ARN]["members"] == [OWNER, P1, P3, "666666666666"]
    assert rows[OU_ARN]["members_source"] == "organizations"
    assert rows[ORG_ARN]["members"] == [OWNER, P1, P3, "666666666666"]


def test_org_errors_fall_back_to_the_catalog(cache, capsys):
    code, _ = run(cache, ["vpc-00000001", "--org-profile", "org", "--json"], org=fake_org(fail=True))
    assert code == 0
    rows = {r["principal"]: r for r in json.loads(capsys.readouterr().out)}
    assert rows[OU_ARN]["members_source"] == "catalog"
    d = core.Directory.from_catalog([], fake_org(org_id="o-other00000"))
    assert d.members(ORG_ARN)[1] == "catalog"


def test_directory_names_from_organizations():
    d = core.Directory.from_catalog([], fake_org())
    assert d.account_name(P2) == "dev-two-org"
    assert d.account_name("000000000000") == ""
    assert d.ou_path(OU_WEB) == "Root/X"
    assert core.principal_name(d, ORG_ARN) == f"organization {ORG}"
    assert core.principal_name(d, "arn:aws:iam::1:role/x") == ""
    # unknown OU, no Organizations: no path, no members
    bare = core.Directory.from_catalog([])
    assert bare.ou_path(OU_WEB) == "" and bare.members(OU_ARN) == ([], "unknown")
    assert vp.member_count({"principal_type": "ou", "members_source": "unknown"}) == "?"
    assert vp.member_count({"principal_type": "ou", "members": [], "members_source": "catalog"}) == "0"
    assert bare.members(P1) == ([], "")
