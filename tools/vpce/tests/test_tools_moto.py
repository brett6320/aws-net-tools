"""End-to-end tests against moto (single account 123456789012)."""
import json

import boto3
import pytest
from moto import mock_aws

from conftest import load_tool

vl = load_tool("vpce_list")

ACCT = "123456789012"


@pytest.fixture
def env():
    with mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        hub = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        spoke = ec2.create_vpc(CidrBlock="10.1.0.0/16")["Vpc"]["VpcId"]
        subnet = ec2.create_subnet(VpcId=hub, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]

        def endpoint(service, tags):
            return ec2.create_vpc_endpoint(
                VpcId=hub, ServiceName=f"com.amazonaws.us-east-1.{service}", VpcEndpointType="Interface",
                SubnetIds=[subnet], PrivateDnsEnabled=False,
                TagSpecifications=[{"ResourceType": "vpc-endpoint", "Tags": [{"Key": k, "Value": v} for k, v in tags.items()]}],
            )["VpcEndpoint"]["VpcEndpointId"]

        eps = {
            "ssm": endpoint("ssm", {"Name": "ssm", "Central": "true", "Env": "prod"}),
            "ssmmessages": endpoint("ssmmessages", {"Name": "ssmmessages", "Central": "true", "Env": "dev"}),
            "sts": endpoint("sts", {"Name": "sts"}),
        }
        r53 = boto3.client("route53", region_name="us-east-1")
        zone = r53.create_hosted_zone(
            Name="ssm.us-east-1.amazonaws.com", CallerReference="z1",
            VPC={"VPCRegion": "us-east-1", "VPCId": hub}, HostedZoneConfig={"PrivateZone": True, "Comment": "central"},
        )["HostedZone"]["Id"].rsplit("/", 1)[-1]
        r53.change_tags_for_resource(ResourceType="hostedzone", ResourceId=zone, AddTags=[{"Key": "Purpose", "Value": "vpce"}])
        yield {"hub": hub, "spoke": spoke, "eps": eps, "zone": zone, "r53": r53}


def run_json(mod, argv, capsys):
    assert mod.main(argv + ["--json", "-q"]) == 0
    return json.loads(capsys.readouterr().out)


def test_vpce_list_tag_filters(env, capsys):
    rows = run_json(vl, ["--tag", "Central=true"], capsys)
    assert {r["id"] for r in rows} == {env["eps"]["ssm"], env["eps"]["ssmmessages"]}
    rows = run_json(vl, ["--tag", "Central=true", "--exclude-tag", "Env=dev"], capsys)
    assert [r["id"] for r in rows] == [env["eps"]["ssm"]]
    rows = run_json(vl, ["--tag", "Env=pr*"], capsys)
    assert [r["id"] for r in rows] == [env["eps"]["ssm"]]


def test_vpce_list_service_and_vpc_arn(env, capsys):
    rows = run_json(vl, ["--service", "ssm"], capsys)
    assert [r["id"] for r in rows] == [env["eps"]["ssm"]]
    arn = f"arn:aws:ec2:us-east-1:{ACCT}:vpc/{env['spoke']}"
    assert run_json(vl, ["--vpc", arn], capsys) == []


def test_vpce_list_with_phz(env, capsys):
    rows = run_json(vl, ["--service", "ssm", "--with-phz"], capsys)
    assert rows[0]["phz"] and rows[0]["phz"][0].startswith(env["zone"])
