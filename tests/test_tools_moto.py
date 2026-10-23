"""End-to-end tests against moto (single account 123456789012).

moto does not implement Route 53 VPC association authorizations, so cross-account
behaviour is covered by the planner tests instead.
"""
import json

import boto3
import pytest
from moto import mock_aws

from conftest import load_tool

vl = load_tool("vpce_list")
pr = load_tool("phz_review")
pa = load_tool("phz_assoc")

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


def test_phz_review_zones_and_tags(env, capsys):
    rows = run_json(pr, ["zones", "--zone-tag", "Purpose=vpce"], capsys)
    assert [(r["zone_id"], r["vpc_count"]) for r in rows] == [(env["zone"], 1)]
    assert run_json(pr, ["zones", "--zone-tag", "Purpose=other"], capsys) == []


def test_phz_review_by_vpc_and_by_zone(env, capsys):
    rows = run_json(pr, ["by-vpc", "--vpc", env["hub"]], capsys)
    assert [(r["zone_id"], r["zone_owner"], r["cross_account"]) for r in rows] == [(env["zone"], ACCT, False)]
    rows = run_json(pr, ["by-zone", "--zone-name", "ssm.*", "--no-authorizations", "--resolve-owners"], capsys)
    assert [(r["vpc_id"], r["status"], r["vpc_owner"]) for r in rows] == [(env["hub"], "associated", ACCT)]


def test_phz_assoc_generate_then_execute(env, capsys):
    arn = f"arn:aws:ec2:us-east-1:{ACCT}:vpc/{env['spoke']}"
    assert pa.main(["associate", "--zone", env["zone"], "--vpc", arn, "-q"]) == 0
    out = capsys.readouterr().out
    assert "associate-vpc-with-hosted-zone" in out and "authorization" not in out.split("set -euo")[1]
    # generate-only must not change anything
    assert len(env["r53"].get_hosted_zone(Id=env["zone"])["VPCs"]) == 1

    assert pa.main(["associate", "--zone-tag", "Purpose=vpce", "--vpc", env["spoke"], "--execute", "-q"]) == 0
    capsys.readouterr()
    assert {v["VPCId"] for v in env["r53"].get_hosted_zone(Id=env["zone"])["VPCs"]} == {env["hub"], env["spoke"]}

    # re-running is a no-op
    assert pa.main(["associate", "--zone", env["zone"], "--vpc", env["spoke"], "-q"]) == 0
    assert "SKIP associate-vpc-with-hosted-zone" in capsys.readouterr().out

    assert pa.main(["disassociate", "--zone", env["zone"], "--vpc", env["spoke"], "--execute", "-q"]) == 0
    capsys.readouterr()
    assert {v["VPCId"] for v in env["r53"].get_hosted_zone(Id=env["zone"])["VPCs"]} == {env["hub"]}


def test_phz_assoc_unknown_vpc_fails_closed(env, capsys):
    assert pa.main(["associate", "--zone", env["zone"], "--vpc", "vpc-0bbbbbbbbbbbbbbb0", "-q"]) == 2


def test_wrong_account_fails_closed(env, capsys):
    assert pa.main(["associate", "--zone", env["zone"], "--vpc", env["spoke"], "--vpc-account", "999999999999", "-q"]) == 2


def test_phz_assoc_name_selection_sees_existing_associations(env, capsys):
    # Selecting by name must load current VPCs; otherwise the hub VPC looks "not associated".
    assert pa.main(["disassociate", "--zone-name", "ssm.*", "--vpc", env["hub"], "-q"]) == 0
    assert "last VPC" in capsys.readouterr().out
