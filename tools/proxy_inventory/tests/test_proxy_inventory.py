import json
from pathlib import Path

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

import pi_core as core
import pi_html
import proxy_inventory as pi

ACCT = "123456789012"  # moto's account
OTHER = "210987654321"
REGION = "us-east-1"


def write_cache(path: Path, entries: dict) -> Path:
    path.write_text(json.dumps(entries))
    return path


def entry(account=ACCT, ou_id="ou-ab12-11111111", ou_path="Root/Prod", name="app", **kw):
    return {"account": account, "source": "ou_vpcs", "seen": "2026-11-01", "account_name": "prod-app",
            "ou_id": ou_id, "ou_path": ou_path, "name": name, "cidrs": ["10.0.0.0/16"], **kw}


# --------------------------------------------------------------------------- input


def test_load_and_select(tmp_path):
    cache = write_cache(tmp_path / "c.json", {
        "us-east-1/vpc-00000001": entry(),
        "us-east-1/vpc-00000002": entry(ou_id="ou-ab12-22222222", ou_path="Root/Production"),
        "ca-central-1/vpc-00000003": entry(account=OTHER, ou_id="ou-ab12-33333333", ou_path="Root/Prod/Web"),
        "us-east-1/vpc-00000004": {"account": "222222222222", "source": "phz_review"},  # no OU details
        "bad-key": entry(),
        "us-east-1/vpc-00000005": {"account": "not-an-account"},
    })
    vpcs = core.load_vpcs(cache)
    assert [v.vpc_id for v in vpcs] == ["vpc-00000004", "vpc-00000001", "vpc-00000003", "vpc-00000002"]
    # an OU path covers OUs below it, but not a sibling that shares the prefix
    assert [v.vpc_id for v in core.select_vpcs(vpcs, ous=["Root/Prod"])] == ["vpc-00000001", "vpc-00000003"]
    assert [v.vpc_id for v in core.select_vpcs(vpcs, ous=["ou-ab12-11111111"])] == ["vpc-00000001"]
    assert [v.vpc_id for v in core.select_vpcs(vpcs, regions=["ca-central-1"])] == ["vpc-00000003"]
    assert [v.vpc_id for v in core.select_vpcs(vpcs, accounts=[OTHER])] == ["vpc-00000003"]
    assert [v.vpc_id for v in core.select_vpcs(vpcs, vpc_ids=["vpc-00000004"])] == ["vpc-00000004"]
    for bad in ({"accounts": ["123"]}, {"regions": ["useast1"]}, {"vpc_ids": ["subnet-1"]}):
        with pytest.raises(ValueError):
            core.select_vpcs(vpcs, **bad)


def test_missing_cache_is_bad_input(tmp_path):
    assert pi.main(["--cache", str(tmp_path / "none.json"), "-q"]) == 2
    cache = write_cache(tmp_path / "c.json", {"us-east-1/vpc-00000001": entry()})
    assert pi.main(["--cache", str(cache), "--account", "999999999999", "-q"]) == 2
    assert pi.main(["--cache", str(cache), "--account-profile", "nope", "-q"]) == 2


def test_resolve_profile(aws_config):
    aws_config({"app": ACCT, "app-priv": ACCT, "two-a": OTHER, "two-b-ro": OTHER, "dup1": "111111111111",
                "dup2": "111111111111"})
    assert core.resolve_profile(ACCT) == "app"
    assert core.resolve_profile(OTHER) == "two-b-ro"
    assert core.resolve_profile(OTHER, preferred="two-a") == "two-a"
    assert core.resolve_profile("111111111111", {"111111111111": "x"}) == "x"
    with pytest.raises(LookupError, match="several"):
        core.resolve_profile("111111111111")
    with pytest.raises(LookupError, match="no profile"):
        core.resolve_profile("333333333333")


def test_tags():
    assert core.tag_dict([{"Key": "a", "Value": "1"}]) == {"a": "1"}
    assert core.tag_dict([{"key": "a", "value": "1"}]) == {"a": "1"}
    assert core.tag_dict({"a": None}) == {"a": ""}
    assert core.key_tag_value({"appcatid": " A1 "}, "AppCatID") == "A1"
    assert core.key_tag_value({"AppCatID": " "}, "AppCatID") == ""


# --------------------------------------------------------------------------- end to end (moto)


@pytest.fixture(autouse=True)
def moto_eni_vpc_filter(monkeypatch):
    # moto lacks DescribeInstances' network-interface.vpc-id filter; approximate it with the instance's VPC.
    from moto.ec2 import utils

    monkeypatch.setitem(utils.filter_dict_attribute_mapping, "network-interface.vpc-id", "vpc_id")


@pytest.fixture
def moto_collectors(monkeypatch):
    # moto doesn't implement AppStream, MWAA or App Runner (404); those collectors are tested with stubs below.
    monkeypatch.setattr(core, "COLLECTORS", tuple(c for c in core.COLLECTORS if c[0] not in ("AppStream", "MWAA", "App Runner")))


def _setup_aws():
    ec2 = boto3.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16", TagSpecifications=[
        {"ResourceType": "vpc", "Tags": [{"Key": "AppCatID", "Value": "VPC-1"}]}])["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
    other_vpc = ec2.create_vpc(CidrBlock="10.9.0.0/16")["Vpc"]["VpcId"]
    other_subnet = ec2.create_subnet(VpcId=other_vpc, CidrBlock="10.9.1.0/24")["Subnet"]["SubnetId"]
    ami = ec2.describe_images()["Images"][0]["ImageId"]
    tagged = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, SubnetId=subnet, TagSpecifications=[
        {"ResourceType": "instance", "Tags": [{"Key": "appcatid", "Value": "APP-100"}, {"Key": "Name", "Value": "web"},
                                              {"Key": "eks:cluster-name", "Value": "k1"}]}])["Instances"][0]["InstanceId"]
    untagged = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, SubnetId=subnet)["Instances"][0]["InstanceId"]
    stopped = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, SubnetId=subnet)["Instances"][0]["InstanceId"]
    ec2.stop_instances(InstanceIds=[stopped])
    gone = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, SubnetId=subnet)["Instances"][0]["InstanceId"]
    ec2.terminate_instances(InstanceIds=[gone])
    ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, SubnetId=other_subnet)  # VPC not selected
    # an interface no resource accounts for, and an excluded one; in their own subnet, as moto's random
    # private IPs could otherwise collide with an instance's and be attributed to it by address
    loose_subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.2.0/24")["Subnet"]["SubnetId"]
    loose = ec2.create_network_interface(SubnetId=loose_subnet, Description="Glue job ENI")["NetworkInterface"]["NetworkInterfaceId"]
    ec2.create_network_interface(SubnetId=loose_subnet, Description="ELB app/my-alb/123")

    iam = boto3.client("iam", region_name=REGION)
    role = iam.create_role(RoleName="fn", AssumeRolePolicyDocument="{}")["Role"]["Arn"]
    lam = boto3.client("lambda", region_name=REGION)
    lam.create_function(FunctionName="fn-in-vpc", Runtime="python3.12", Role=role, Handler="h.h",
                        Code={"ZipFile": b"x"}, VpcConfig={"SubnetIds": [subnet], "SecurityGroupIds": []},
                        Tags={"AppCatID": "APP-200"})
    lam.create_function(FunctionName="fn-no-vpc", Runtime="python3.12", Role=role, Handler="h.h", Code={"ZipFile": b"x"})

    ecs = boto3.client("ecs", region_name=REGION)
    sg = ec2.create_security_group(GroupName="svc", Description="svc", VpcId=vpc)["GroupId"]
    ecs.create_cluster(clusterName="c1", tags=[{"key": "AppCatID", "value": "APP-300"}])
    ecs.register_task_definition(family="td", networkMode="awsvpc",
                                 containerDefinitions=[{"name": "c", "image": "x", "memory": 128}])
    ecs.create_service(cluster="c1", serviceName="svc", taskDefinition="td", desiredCount=0, launchType="FARGATE",
                       networkConfiguration={"awsvpcConfiguration": {"subnets": [subnet], "securityGroups": [sg]}})
    return {"vpc": vpc, "other_vpc": other_vpc, "tagged": tagged, "untagged": untagged, "stopped": stopped,
            "gone": gone, "loose": loose}


@mock_aws
def test_end_to_end(tmp_path, aws_config, moto_collectors):
    ids = _setup_aws()
    aws_config({"prod-app": ACCT})
    cache = write_cache(tmp_path / "c.json", {
        f"{REGION}/{ids['vpc']}": entry(),
        f"{REGION}/vpc-0000000000000dead": entry(name="deleted"),
    })
    out = tmp_path / "r" / "inv.html"
    js = tmp_path / "inv.json"
    rc = pi.main(["--cache", str(cache), "--out", str(out), "--json-out", str(js), "--workers", "2", "-q"],
                 session_for=lambda profile: boto3.Session(region_name=REGION))
    assert rc == 0
    data = json.loads(js.read_text())
    res = {r["id"]: r for r in data["resources"]}
    assert set(res) >= {ids["tagged"], ids["untagged"], ids["stopped"], "fn-in-vpc", "c1/svc"}
    assert ids["gone"] not in res and "fn-no-vpc" not in res
    assert all(r["vpc_id"] == ids["vpc"] for r in data["resources"])
    assert res[ids["tagged"]]["appcatid"] == "APP-100" and res[ids["tagged"]]["appcatid_source"] == "resource"
    assert res[ids["tagged"]]["tags"]["Name"] == "web" and "EKS k1" in res[ids["tagged"]]["detail"]
    assert res[ids["untagged"]]["appcatid"] == core.MISSING
    assert res["fn-in-vpc"]["appcatid"] == "APP-200"
    assert res["c1/svc"]["appcatid"] == "APP-300" and res["c1/svc"]["appcatid_source"] == "inherited from ECS cluster"
    assert all(r["vpc_appcatid"] == "VPC-1" and r["ou_path"] == "Root/Prod" for r in data["resources"])

    apps = {a["appcatid"]: a for a in data["apps"]}
    assert set(apps) == {"APP-100", "APP-200", "APP-300", core.MISSING}
    assert apps[core.MISSING]["resources"] == 2

    enis = {n["eni_id"]: n for n in data["unattributed_enis"]}
    assert ids["loose"] in enis and enis[ids["loose"]]["likely"] == "Glue"
    assert not any(n["description"].startswith("ELB ") for n in enis.values())
    assert not any(n["instance_id"] in res for n in enis.values())

    status = {v["vpc_id"]: v["status"] for v in data["vpcs"]}
    assert status == {ids["vpc"]: "read", "vpc-0000000000000dead": "gone"}

    html = out.read_text()
    assert "APP-100" in html and "Download HTML (this view)" in html
    assert len(list(out.parent.glob("inv_*.html"))) == 1  # timestamped copy next to --out


@mock_aws
def test_reports_dir_and_unreadable_account(tmp_path, aws_config, moto_collectors, monkeypatch, capsys):
    ids = _setup_aws()
    aws_config({"prod-app": ACCT})
    cache = write_cache(tmp_path / "c.json", {f"{REGION}/{ids['vpc']}": entry(),
                                               f"{REGION}/vpc-00000000000000002": entry(account=OTHER)})
    monkeypatch.chdir(tmp_path)
    rc = pi.main(["--cache", str(cache), "-q"], session_for=lambda profile: boto3.Session(region_name=REGION))
    assert rc == pi.INCOMPLETE_EXIT  # OTHER has no profile
    path = Path(capsys.readouterr().out.strip())
    assert path == Path("reports") / "multi-account" / "proxy-inventory.html" and path.exists()
    assert len(list(Path("reports").glob("*-*-*/multi-account/proxy-inventory_*.html"))) == 1


# --------------------------------------------------------------------------- collectors with stub clients


class Stub:
    """A client whose operations return canned pages; records every call."""

    def __init__(self, pages: dict, paginate: bool = False):
        self.pages, self.paginate, self.calls = pages, paginate, []

    def can_paginate(self, op):
        return False

    def __getattr__(self, op):
        def call(**kw):
            self.calls.append((op, kw))
            v = self.pages[op]
            if isinstance(v, list):  # successive NextToken pages
                return v[1] if kw.get("NextToken") else v[0]
            return v(**kw) if callable(v) else v
        return call


class StubSession:
    def __init__(self, clients):
        self.clients = clients

    def client(self, name, **kw):
        return self.clients[name]


def test_apprunner_pages_by_hand():
    ar = Stub({
        "list_vpc_connectors": [{"VpcConnectors": [{"VpcConnectorArn": "arn:c1", "Subnets": ["subnet-1"],
                                                    "VpcConnectorName": "c1"}], "NextToken": "t"},
                                {"VpcConnectors": [{"VpcConnectorArn": "arn:c2", "Subnets": ["subnet-x"]}]}],
        "list_services": [{"ServiceSummaryList": [{"ServiceArn": "arn:s1"}], "NextToken": "t"},
                          {"ServiceSummaryList": [{"ServiceArn": "arn:s2"}]}],
        "describe_service": lambda ServiceArn: {"Service": {
            "ServiceArn": ServiceArn, "ServiceName": ServiceArn[4:], "Status": "RUNNING",
            "NetworkConfiguration": {"EgressConfiguration": {"VpcConnectorArn": "arn:c1" if ServiceArn == "arn:s1" else "arn:c2"}}}},
        "list_tags_for_resource": {"Tags": [{"Key": "AppCatID", "Value": "AR-1"}]},
    })
    rows = core.apprunner_services(StubSession({"apprunner": ar}), REGION, ACCT, {"vpc-1"}, {"subnet-1": "vpc-1"})
    assert [(r["id"], r["vpc_id"], r["tags"]) for r in rows] == [("s1", "vpc-1", {"AppCatID": "AR-1"})]


def test_appstream_mwaa_workspaces():
    asc = Stub({"describe_fleets": {"Fleets": [
        {"Name": "f1", "Arn": "arn:f1", "VpcConfig": {"SubnetIds": ["subnet-1"]}, "State": "RUNNING"},
        {"Name": "f2", "Arn": "arn:f2"}]}, "list_tags_for_resource": {"Tags": {"AppCatID": "AS-1"}}})
    mwaa = Stub({"list_environments": {"Environments": ["e1"]}, "get_environment": {"Environment": {
        "Arn": "arn:e1", "Status": "AVAILABLE", "NetworkConfiguration": {"SubnetIds": ["subnet-1"]}, "Tags": {"AppCatID": "MW-1"}}}})
    ws = Stub({"describe_workspaces": {"Workspaces": [
        {"WorkspaceId": "ws-1", "SubnetId": "subnet-1", "IpAddress": "10.0.1.9", "UserName": "u"},
        {"WorkspaceId": "ws-2", "SubnetId": "subnet-9"}]}, "describe_tags": {"TagList": [{"Key": "AppCatID", "Value": "WS-1"}]}})
    s = StubSession({"appstream": asc, "mwaa": mwaa, "workspaces": ws})
    subnets = {"subnet-1": "vpc-1"}
    assert [r["id"] for r in core.appstream_fleets(s, REGION, ACCT, {"vpc-1"}, subnets)] == ["f1"]
    assert [r["tags"]["AppCatID"] for r in core.mwaa_environments(s, REGION, ACCT, {"vpc-1"}, subnets)] == ["MW-1"]
    w = core.workspaces(s, REGION, ACCT, {"vpc-1"}, subnets)
    assert [(r["id"], r["private_ips"]) for r in w] == [("ws-1", ["10.0.1.9"])]
    assert ws.calls.count(("describe_tags", {"ResourceId": "ws-1"})) == 1


def test_glue_hides_passwords():
    glue = Stub({
        "get_connections": {"ConnectionList": [
            {"Name": "db", "PhysicalConnectionRequirements": {"SubnetId": "subnet-1"}},
            {"Name": "elsewhere", "PhysicalConnectionRequirements": {"SubnetId": "subnet-9"}}]},
        "get_jobs": {"Jobs": [{"Name": "j1", "Connections": {"Connections": ["db"]}},
                              {"Name": "j2", "Connections": {"Connections": ["elsewhere"]}}, {"Name": "j3"}]},
        "get_tags": {"Tags": {"AppCatID": "GL-1"}},
    })
    rows = core.glue_jobs(StubSession({"glue": glue}), REGION, ACCT, {"vpc-1"}, {"subnet-1": "vpc-1"})
    assert [(r["id"], r["tags"]) for r in rows] == [("j1", {"AppCatID": "GL-1"})]
    assert ("get_connections", {"HidePassword": True}) in glue.calls
    assert "ConnectionProperties" not in json.dumps(rows)


def test_denied_service_is_listed_not_incomplete(monkeypatch, aws_config):
    aws_config({"a": ACCT})

    def denied(*a):
        raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "no"}}, "ListFunctions")

    monkeypatch.setattr(core, "COLLECTORS", (("Lambda", "lambda", denied),))
    sts = Stub({"get_caller_identity": {"Account": ACCT}})
    ec2 = Stub({"describe_subnets": {"Subnets": []}, "describe_vpcs": {"Vpcs": []},
                "describe_network_interfaces": {"NetworkInterfaces": []}})
    scan = core.scan_account(ACCT, {REGION: ["vpc-1"]}, lambda p: StubSession({"sts": sts, "ec2": ec2}))
    assert [(i.scope, i.incomplete) for i in scan.issues] == [("Lambda", False)]
    assert (ACCT, REGION, "Lambda") not in scan.read


def test_other_service_errors_are_incomplete_and_contained(monkeypatch, aws_config):
    aws_config({"a": ACCT})

    def throttled(*a):
        raise ClientError({"Error": {"Code": "ThrottlingException", "Message": "slow down"}}, "DescribeFleets")

    def broken(*a):
        raise KeyError("Fleets")

    monkeypatch.setattr(core, "COLLECTORS", (("AppStream", "appstream", throttled), ("MWAA", "mwaa", broken),
                                             ("Glue", "glue", lambda *a: [])))
    sts = Stub({"get_caller_identity": {"Account": ACCT}})
    ec2 = Stub({"describe_subnets": {"Subnets": []}, "describe_vpcs": {"Vpcs": []},
                "describe_network_interfaces": {"NetworkInterfaces": []}})
    scan = core.scan_account(ACCT, {REGION: ["vpc-1"]}, lambda p: StubSession({"sts": sts, "ec2": ec2}))
    assert [(i.scope, i.incomplete) for i in scan.issues] == [("AppStream", True), ("MWAA", True)]
    assert scan.read == {(ACCT, REGION, "Glue")}


def test_wrong_account_profile_is_skipped(aws_config):
    aws_config({"a": ACCT})
    sts = Stub({"get_caller_identity": {"Account": OTHER}})
    scan = core.scan_account(ACCT, {REGION: ["vpc-1"]}, lambda p: StubSession({"sts": sts}))
    assert scan.issues[0].scope == "account" and "authenticates as" in scan.issues[0].reason


# --------------------------------------------------------------------------- shared VPCs and interfaces


def eni(eni_id, **kw):
    base = {"eni_id": eni_id, "vpc_id": "vpc-1", "subnet": "subnet-1", "eni_owner": ACCT, "interface_type": "interface",
            "description": "", "requester": "", "requester_managed": False, "status": "in-use", "instance_id": "",
            "instance_owner": "", "private_ips": [], "tags": {}, "account": ACCT, "region": REGION}
    return {**base, **kw}


def test_classify_enis():
    resources = [{"type": "EC2 instance", "id": "i-1", "vpc_id": "vpc-1", "private_ips": ["10.0.0.5"], "eni_ids": ["eni-task"]}]
    enis = [
        eni("eni-i", instance_id="i-1"), eni("eni-task"), eni("eni-ip", private_ips=["10.0.0.5"]),
        eni("eni-lambda", interface_type="lambda"), eni("eni-vpce", interface_type="vpc_endpoint"),
        eni("eni-nat", interface_type="natGateway"), eni("eni-rds", requester="amazon-rds"),
        eni("eni-eks", description="Amazon EKS k1"),
        eni("eni-branch", interface_type="branch"),
        eni("eni-part", eni_owner=OTHER, instance_id="i-9", instance_owner=OTHER),
        eni("eni-x", description="something new"),
    ]
    read = {(ACCT, REGION, "Lambda")}
    out = {n["eni_id"]: n["likely"] for n in core.classify_enis(enis, resources, read)}
    assert out == {"eni-branch": "ECS awsvpc trunking / EKS pod security groups",
                   "eni-part": f"attached to i-9 (participant account {OTHER})", "eni-x": ""}
    # Lambda wasn't read: its interfaces are not taken as accounted for
    assert "eni-lambda" in {n["eni_id"] for n in core.classify_enis(enis, resources)}


def test_managed_interfaces_of_reported_services_are_accounted_for():
    resources = [{"type": "Glue job", "id": "j1", "vpc_id": "vpc-1", "private_ips": [], "eni_ids": [], "account": ACCT}]
    enis = [eni("eni-glue", description="Attached to Glue using role"),
            eni("eni-glue-other-vpc", vpc_id="vpc-2", description="Attached to Glue using role"),
            eni("eni-mwaa", description="MWAA environment")]
    assert [n["eni_id"] for n in core.classify_enis(enis, resources)] == ["eni-glue-other-vpc", "eni-mwaa"]


def test_participants_are_scanned(monkeypatch):
    calls = []

    def fake(account, by_region, session_for, overrides=None, preferred=None, *, owner=True, scope="account"):
        calls.append((account, by_region, owner, scope))
        s = core.Scan()
        if owner:
            s.enis = [eni("eni-p", eni_owner=OTHER), eni("eni-own")]
        return s

    monkeypatch.setattr(core, "scan_account", fake)
    vpcs = [core.Vpc(REGION, "vpc-1", ACCT)]
    core.scan(vpcs, lambda p: None, workers=1)
    assert calls == [(ACCT, {REGION: ["vpc-1"]}, True, "account"),
                     (OTHER, {REGION: ["vpc-1"]}, False, "participant")]
    # attachment owners (often AWS service accounts) and excluded interfaces don't make participants
    calls.clear()
    monkeypatch.setattr(core, "scan_account", lambda *a, owner=True, **kw: (calls.append(a[0]), core.Scan(enis=[
        eni("eni-eks", instance_owner="999999999999"), eni("eni-vpce", eni_owner=OTHER, interface_type="vpc_endpoint")]
        if owner else []))[1])
    core.scan(vpcs, lambda p: None, workers=1)
    assert calls == [ACCT]
    calls.clear()
    core.scan(vpcs, lambda p: None, workers=1, participants=False)
    assert len(calls) == 1


def test_available_regions():
    s = boto3.Session(region_name=REGION)
    assert core.available(s, "ec2", "ca-central-1")
    assert not core.available(s, "apprunner", "ca-central-1")
    assert core.available(object(), "ec2", REGION)  # no endpoint data: let the call decide


# --------------------------------------------------------------------------- HTML


def test_html_escapes_data_and_embeds_export():
    html = pi_html.render("T </title>", tables=[{"id": "t", "title": "x", "columns": [["a", "A"]],
                                                 "rows": [{"a": "</script><script>alert(1)</script>"}]}], file="inv")
    assert "<script>alert(1)" not in html
    assert "T &lt;/title>" in html
    assert '"file": "inv"' in html and 'getElementById("view")' in html
