"""phz_backup: backup against moto, restore-plan from crafted backups (no AWS)."""
import json
import shutil
import subprocess

import boto3
import pytest
from moto import mock_aws

from conftest import load_tool

pb = load_tool("phz_backup")

ACCT = "123456789012"
OTHER = "210987654321"


@pytest.fixture
def env(tmp_path, monkeypatch):
    # moto does not implement ListVPCAssociationAuthorizations
    monkeypatch.setattr(pb, "list_authorizations", lambda route53, zone_id: [])
    with mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        hub = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        spoke = ec2.create_vpc(CidrBlock="10.1.0.0/16")["Vpc"]["VpcId"]
        r53 = boto3.client("route53", region_name="us-east-1")
        zone = r53.create_hosted_zone(
            Name="corp.internal", CallerReference="z1",
            VPC={"VPCRegion": "us-east-1", "VPCId": hub}, HostedZoneConfig={"PrivateZone": True, "Comment": "core, internal"},
        )["HostedZone"]["Id"].rsplit("/", 1)[-1]
        r53.associate_vpc_with_hosted_zone(HostedZoneId=zone, VPC={"VPCRegion": "us-east-1", "VPCId": spoke})
        r53.change_tags_for_resource(ResourceType="hostedzone", ResourceId=zone, AddTags=[{"Key": "Owner", "Value": "net"}])
        r53.change_resource_record_sets(HostedZoneId=zone, ChangeBatch={"Changes": [
            {"Action": "CREATE", "ResourceRecordSet": {"Name": "db.corp.internal.", "Type": "A", "TTL": 60,
                                                        "ResourceRecords": [{"Value": "10.0.0.5"}]}},
            {"Action": "CREATE", "ResourceRecordSet": {"Name": "corp.internal.", "Type": "TXT", "TTL": 300,
                                                        "ResourceRecords": [{"Value": '"v=it\'s $HOME"'}]}},
        ]})
        r53.create_hosted_zone(Name="public.example", CallerReference="p1")
        yield {"hub": hub, "spoke": spoke, "zone": zone, "r53": r53, "root": tmp_path / "backups", "reports": tmp_path / "reports"}


def backup(env, capsys, *extra):
    argv = ["backup", "--backup-dir", str(env["root"]), "--reports-dir", str(env["reports"]), "--no-owner-cache", "--json", "-q"]
    assert pb.main(argv + list(extra)) == 0
    return json.loads(capsys.readouterr().out)


def test_backup_records_tags_and_associations(env, capsys):
    out = backup(env, capsys)
    assert [z["zone_id"] for z in out["zones"]] == [env["zone"]]  # public zone skipped
    data = json.loads((pb.Path(out["backup"]) / out["zones"][0]["file"]).read_text())
    assert data["zone"] == {"id": env["zone"], "name": "corp.internal", "comment": "core, internal", "private": True}
    assert data["tags"] == {"Owner": "net"}
    assert {(v["vpc_id"], v["owner"]) for v in data["vpcs"]} == {(env["hub"], ACCT), (env["spoke"], ACCT)}
    assert {(r["Name"], r["Type"]) for r in data["records"]} >= {("db.corp.internal.", "A"), ("corp.internal.", "SOA")}
    assert json.loads((pb.Path(out["backup"]) / pb.MANIFEST).read_text())["account"] == ACCT


def test_backup_public_zone_rejected(env, capsys):
    pub = [z for z in env["r53"].list_hosted_zones()["HostedZones"] if z["Name"] == "public.example."][0]["Id"]
    assert pb.main(["backup", "--backup-dir", str(env["root"]), "--reports-dir", str(env["reports"]),
                    "--no-owner-cache", "--zone", pub, "-q"]) == 2


def test_restore_plan_from_latest(env, capsys):
    backup(env, capsys)
    assert pb.main(["restore-plan", "latest", "--backup-dir", str(env["root"]), "-q"]) == 0
    script = capsys.readouterr().out
    body = script.split("set -euo pipefail", 1)[1]
    assert "aws route53 create-hosted-zone --name corp.internal." in body
    assert f"--vpc VPCRegion=us-east-1,VPCId={env['hub']}" in body
    assert '"Comment": "core, internal"' in body
    assert "change-tags-for-resource" in body and '"Key": "Owner"' in body
    assert '"Name": "db.corp.internal."' in body
    assert '"Type": "SOA"' not in body
    # the spoke is associated afterwards, same account: no authorization dance
    assert f"associate-vpc-with-hosted-zone --hosted-zone-id \"$ZONE_{env['zone']}\" --vpc VPCRegion=us-east-1,VPCId={env['spoke']}" in body
    assert "create-vpc-association-authorization" not in body
    assert body.index("change-resource-record-sets") < body.index("associate-vpc-with-hosted-zone")
    # generating a plan changed nothing
    assert len(env["r53"].list_hosted_zones()["HostedZones"]) == 2
    if shutil.which("bash"):
        assert subprocess.run(["bash", "-n"], input=script, text=True).returncode == 0


def zone_file(tmp_path, **over):
    data = {
        "format": 1, "taken_at": "2026-11-23T00:00:00+00:00", "account": ACCT,
        "zone": {"id": "ZOLD", "name": "corp.internal", "comment": "", "private": True},
        "tags": {}, "authorizations": [],
        "vpcs": [{"region": "us-east-1", "vpc_id": "vpc-0aaaaaaaaaaaaaaa0", "owner": ACCT}],
        "records": [
            {"Name": "corp.internal.", "Type": "SOA", "TTL": 900, "ResourceRecords": [{"Value": "x"}]},
            {"Name": "corp.internal.", "Type": "NS", "TTL": 172800, "ResourceRecords": [{"Value": "ns"}]},
        ],
    }
    data.update(over)
    f = tmp_path / "ZOLD_corp.internal.json"
    f.write_text(json.dumps(data))
    return f


def plan(f, capsys, *extra):
    assert pb.main(["restore-plan", str(f), "-q", *extra]) == 0
    return capsys.readouterr().out


def test_cross_account_and_unknown_owner(tmp_path, capsys):
    f = zone_file(tmp_path, vpcs=[
        {"region": "us-east-1", "vpc_id": "vpc-0aaaaaaaaaaaaaaa0", "owner": ACCT},
        {"region": "us-west-2", "vpc_id": "vpc-0bbbbbbbbbbbbbbb0", "owner": OTHER},
        {"region": "us-west-2", "vpc_id": "vpc-0ccccccccccccccc0", "owner": None},
    ], authorizations=[{"region": "us-east-2", "vpc_id": "vpc-0ddddddddddddddd0"}])
    s = plan(f, capsys)
    assert f'PROFILE_{OTHER}="${{PROFILE_{OTHER}-}}"' in s
    assert ': "${PROFILE_VPC_0CCCCCCCCCCCCCCC0:?' in s
    lines = [line for line in s.splitlines() if "vpc-0bbbbbbbbbbbbbbb0" in line and line.startswith("aws")]
    assert [line.split()[2] for line in lines] == [
        "create-vpc-association-authorization", "associate-vpc-with-hosted-zone", "delete-vpc-association-authorization"]
    assert f'--profile "$PROFILE_{OTHER}"' in lines[1] and '"$PHZ_PROFILE"' in lines[0]
    assert "VPCRegion=us-east-2,VPCId=vpc-0ddddddddddddddd0" in s  # pending authorization recreated
    assert subprocess.run(["bash", "-n"], input=s, text=True).returncode == 0


def test_no_same_account_vpc_requires_creation_vpc(tmp_path, capsys):
    f = zone_file(tmp_path, vpcs=[{"region": "us-west-2", "vpc_id": "vpc-0bbbbbbbbbbbbbbb0", "owner": OTHER}])
    s = plan(f, capsys)
    assert ': "${CREATE_VPC_ID_ZOLD:?' in s and '--vpc "VPCRegion=$CREATE_VPC_REGION_ZOLD,VPCId=$CREATE_VPC_ID_ZOLD"' in s
    assert "associate-vpc-with-hosted-zone" in s and "# aws route53 disassociate-vpc-from-hosted-zone" in s


def test_into_existing_zone(tmp_path, capsys):
    f = zone_file(tmp_path, vpcs=[
        {"region": "us-east-1", "vpc_id": "vpc-0aaaaaaaaaaaaaaa0", "owner": ACCT},
        {"region": "us-east-1", "vpc_id": "vpc-0eeeeeeeeeeeeeee0", "owner": ACCT},
    ])
    s = plan(f, capsys, "--into", "/hostedzone/ZNEW")
    assert "create-hosted-zone" not in s and "ZONE_ZOLD=ZNEW" in s
    assoc = [line for line in s.splitlines() if line.startswith("aws route53 associate-vpc-with-hosted-zone")]
    assert len(assoc) == 2 and all("|| echo" in line for line in assoc)


def test_into_needs_one_zone(tmp_path, capsys):
    zone_file(tmp_path)
    other = json.loads((tmp_path / "ZOLD_corp.internal.json").read_text())
    other["zone"] = {**other["zone"], "id": "ZTWO", "name": "two.internal"}
    (tmp_path / "ZTWO_two.internal.json").write_text(json.dumps(other))
    assert pb.main(["restore-plan", str(tmp_path), "--into", "ZNEW", "-q"]) == 2
    assert pb.main(["restore-plan", str(tmp_path), "--zone", "two.internal", "--into", "ZNEW", "-q"]) == 0
    assert "two.internal" in capsys.readouterr().out


def test_alias_ordering_and_rewrite(tmp_path, capsys):
    recs = [
        {"Name": "b.corp.internal.", "Type": "A", "AliasTarget": {"HostedZoneId": "ZOLD", "DNSName": "a.corp.internal.", "EvaluateTargetHealth": False}},
        {"Name": "a.corp.internal.", "Type": "A", "AliasTarget": {"HostedZoneId": "ZOLD", "DNSName": "web.corp.internal.", "EvaluateTargetHealth": False}},
        {"Name": "lb.corp.internal.", "Type": "A", "AliasTarget": {"HostedZoneId": "Z35SXDOTRQ7X7K", "DNSName": "x.elb.amazonaws.com.", "EvaluateTargetHealth": False}},
        {"Name": "web.corp.internal.", "Type": "A", "TTL": 60, "ResourceRecords": [{"Value": "10.0.0.1"}]},
        {"Name": "tp.corp.internal.", "Type": "A", "TrafficPolicyInstanceId": "tpi-1"},
    ]
    ordered = pb.order_records(recs[:4], "ZOLD")
    assert [r["Name"].split(".")[0] for r in ordered] == ["web", "lb", "a", "b"]
    s = plan(zone_file(tmp_path, records=recs), capsys)
    assert '"HostedZoneId": "@@ZONE_ID@@"' in s and 'sed "s/@@ZONE_ID@@/$ZONE_ZOLD/g"' in s
    assert '"HostedZoneId": "Z35SXDOTRQ7X7K"' in s
    assert "# SKIP tp.corp.internal. A" in s
    # web+lb, then a, then b: each alias level in its own batch
    assert [[r["Name"].split(".")[0] for r in lvl] for lvl in pb.record_levels(recs[:4], "ZOLD")] == [["web", "lb"], ["a"], ["b"]]
    assert "# batch 3/3: 1 record set(s)" in s


def test_batches_split_by_count_and_size():
    small = [{"Name": f"h{i}.x.", "Type": "A", "TTL": 1, "ResourceRecords": [{"Value": "10.0.0.1"}]} for i in range(250)]
    assert [len(b) for b in pb.chunk_changes(small)] == [100, 100, 50]
    big = [{"Name": f"t{i}.x.", "Type": "TXT", "TTL": 1, "ResourceRecords": [{"Value": '"' + "a" * 9000 + '"'}]} for i in range(5)]
    assert all(len(b) <= 2 for b in pb.chunk_changes(big))


def test_restore_plan_out_file(tmp_path, capsys):
    out = tmp_path / "restore.sh"
    assert pb.main(["restore-plan", str(zone_file(tmp_path)), "-o", str(out), "-q"]) == 0
    assert out.read_text().startswith("#!/usr/bin/env bash") and out.stat().st_mode & 0o777 == 0o700


def test_latest_ambiguous_across_accounts(tmp_path, capsys):
    for acct in (ACCT, OTHER):
        (tmp_path / acct / "20261123T000000Z").mkdir(parents=True)
    assert pb.main(["restore-plan", "latest", "--backup-dir", str(tmp_path), "-q"]) == 2
    assert pb.main(["restore-plan", "previous", "--backup-dir", str(tmp_path), "--account", ACCT, "-q"]) == 2


def test_backup_writes_html_report_by_default(env, capsys):
    out = backup(env, capsys)
    report = pb.Path(out["report"])
    assert report == env["reports"] / ACCT / "phz-backup.html"
    page = report.read_text()
    assert "corp.internal" in page and env["zone"] in page and "db.corp.internal." in page
    assert "Owner=net" in page and env["spoke"] in page
    assert "aws route53 create-hosted-zone" in page  # the zone's restore script is embedded
    assert "&quot;v=it&#x27;s $HOME&quot;" in page  # TXT value escaped
    history = list((env["reports"]).glob(f"*/{ACCT}/phz-backup_*.html"))
    assert len(history) == 1


def test_backup_no_html(env, capsys):
    assert backup(env, capsys, "--no-html")["report"] is None
    assert not env["reports"].exists()


def test_report_subcommand(env, capsys):
    backup(env, capsys, "--no-html")
    target = env["reports"] / "r.html"
    assert pb.main(["report", "latest", "--backup-dir", str(env["root"]), "--out", str(target), "-q"]) == 0
    assert capsys.readouterr().out.strip() == str(target)
    assert "PHZ backup" in target.read_text()


def test_report_escapes_and_flags(tmp_path, capsys):
    f = zone_file(tmp_path, tags={"x": "<script>alert(1)</script>"}, vpcs=[
        {"region": "us-east-1", "vpc_id": "vpc-0aaaaaaaaaaaaaaa0", "owner": ACCT},
        {"region": "us-west-2", "vpc_id": "vpc-0bbbbbbbbbbbbbbb0", "owner": OTHER},
        {"region": "us-west-2", "vpc_id": "vpc-0ccccccccccccccc0", "owner": None},
    ], records=[{"Name": "\\052.corp.internal.", "Type": "CNAME", "TTL": 60, "SetIdentifier": "a", "Weight": 10,
                 "ResourceRecords": [{"Value": "x.corp.internal"}]}])
    out = tmp_path / "r.html"
    assert pb.main(["report", str(f), "--out", str(out), "-q"]) == 0
    page = out.read_text()
    assert "<script>alert(1)" not in page and "&lt;script&gt;alert(1)" in page
    assert "cross-account" in page and "unknown owner" in page and "PROFILE_VPC_" in page
    assert "*.corp.internal." in page and "weight 10" in page
