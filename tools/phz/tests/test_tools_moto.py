"""End-to-end tests against moto (single account 123456789012).

moto does not implement Route 53 VPC association authorizations, so cross-account
behaviour is covered by the planner tests instead.
"""
import json
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

from conftest import load_tool

pr = load_tool("phz_review")
pa = load_tool("phz_assoc")

ACCT = "123456789012"


@pytest.fixture
def env():
    with mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        hub = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        spoke = ec2.create_vpc(CidrBlock="10.1.0.0/16")["Vpc"]["VpcId"]
        r53 = boto3.client("route53", region_name="us-east-1")
        zone = r53.create_hosted_zone(
            Name="ssm.us-east-1.amazonaws.com", CallerReference="z1",
            VPC={"VPCRegion": "us-east-1", "VPCId": hub}, HostedZoneConfig={"PrivateZone": True, "Comment": "central"},
        )["HostedZone"]["Id"].rsplit("/", 1)[-1]
        r53.change_tags_for_resource(ResourceType="hostedzone", ResourceId=zone, AddTags=[{"Key": "Purpose", "Value": "vpce"}])
        yield {"hub": hub, "spoke": spoke, "zone": zone, "r53": r53}


def run_json(mod, argv, capsys):
    assert mod.main(argv + ["--json", "-q"]) == 0
    return json.loads(capsys.readouterr().out)


def test_phz_review_zones_and_tags(env, capsys):
    rows = run_json(pr, ["zones", "--zone-tag", "Purpose=vpce"], capsys)
    assert [(r["zone_id"], r["vpc_count"]) for r in rows] == [(env["zone"], 1)]
    assert run_json(pr, ["zones", "--zone-tag", "Purpose=other"], capsys) == []


def test_phz_review_by_vpc_and_by_zone(env, capsys):
    rows = run_json(pr, ["by-vpc", "--vpc", env["hub"]], capsys)
    assert [(r["zone_id"], r["zone_owner"], r["cross_account"]) for r in rows] == [(env["zone"], ACCT, False)]
    rows = run_json(pr, ["by-zone", "--zone-name", "ssm.*", "--no-authorizations", "--resolve-owners"], capsys)
    assert [(r["vpc_id"], r["status"], r["vpc_owner"]) for r in rows] == [(env["hub"], "associated", ACCT)]


def test_phz_assoc_generate_only(env, capsys):
    arn = f"arn:aws:ec2:us-east-1:{ACCT}:vpc/{env['spoke']}"
    assert pa.main(["associate", "--zone", env["zone"], "--vpc", arn, "-q"]) == 0
    out = capsys.readouterr().out
    assert "associate-vpc-with-hosted-zone" in out and "authorization" not in out.split("set -euo")[1]
    # generating must not change anything
    assert len(env["r53"].get_hosted_zone(Id=env["zone"])["VPCs"]) == 1

    env["r53"].associate_vpc_with_hosted_zone(HostedZoneId=env["zone"], VPC={"VPCRegion": "us-east-1", "VPCId": env["spoke"]})
    assert pa.main(["associate", "--zone-tag", "Purpose=vpce", "--vpc", env["spoke"], "-q"]) == 0
    assert "SKIP associate-vpc-with-hosted-zone" in capsys.readouterr().out

    assert pa.main(["disassociate", "--zone", env["zone"], "--vpc", env["spoke"], "-q"]) == 0
    out = capsys.readouterr().out
    assert "\naws route53 disassociate-vpc-from-hosted-zone" in out
    assert len(env["r53"].get_hosted_zone(Id=env["zone"])["VPCs"]) == 2


def test_phz_assoc_has_no_execute_flag(env, capsys):
    with pytest.raises(SystemExit):
        pa.main(["associate", "--zone", env["zone"], "--vpc", env["spoke"], "--execute"])


def test_phz_assoc_unknown_vpc_fails_closed(env, capsys):
    assert pa.main(["associate", "--zone", env["zone"], "--vpc", "vpc-0bbbbbbbbbbbbbbb0", "-q"]) == 2


def test_wrong_account_fails_closed(env, capsys):
    assert pa.main(["associate", "--zone", env["zone"], "--vpc", env["spoke"], "--vpc-account", "999999999999", "-q"]) == 2


def test_phz_assoc_name_selection_sees_existing_associations(env, capsys):
    # Selecting by name must load current VPCs; otherwise the hub VPC looks "not associated".
    assert pa.main(["disassociate", "--zone-name", "ssm.*", "--vpc", env["hub"], "-q"]) == 0
    assert "last VPC" in capsys.readouterr().out


@pytest.fixture
def no_auths(monkeypatch):
    # moto does not implement ListVPCAssociationAuthorizations
    monkeypatch.setattr(pr, "list_authorizations", lambda route53, zone_id: [])


def test_outputs_include_accounts(env, no_auths, capsys):
    rows = run_json(pr, ["zones"], capsys)
    assert rows[0]["account"] == ACCT and rows[0]["vpc_owners"] == {env["hub"]: ACCT}
    rows = run_json(pr, ["by-zone", "--zone-name", "ssm.*"], capsys)
    assert [(r["zone_owner"], r["vpc_owner"], r["cross_account"]) for r in rows] == [(ACCT, ACCT, False)]
    assert pr.main(["by-zone", "--zone-name", "ssm.*", "-o", "csv", "-q"]) == 0
    assert capsys.readouterr().out.splitlines()[0] == "zone_id,zone_name,zone_owner,vpc_id,vpc_region,vpc_owner,cross_account,status"
    rows = run_json(pr, ["by-zone", "--zone-name", "ssm.*", "--no-resolve-owners"], capsys)
    assert rows[0]["vpc_owner"] == "unknown" and rows[0]["cross_account"] is None


def _report_data(path):
    text = path.read_text()
    raw = text.split('<script type="application/json" id="phz-data">', 1)[1].split("</script>", 1)[0]
    return json.loads(raw.replace("<\\/", "</"))


@pytest.mark.parametrize("argv", [["zones"], ["by-zone", "--zone-tag", "Purpose=vpce"]])
def test_html_report_from_phz_account(env, no_auths, capsys, tmp_path, argv):
    assert pr.main(argv + ["-o", "html", "--reports-dir", str(tmp_path), "-q"]) == 0
    path = Path(capsys.readouterr().out.strip())
    assert path.parent.name == ACCT and path.is_relative_to(tmp_path)
    d = _report_data(path)
    assert d["vpc_counts_complete"] and d["authorizations_listed"]
    assert [(z["zone_id"], z["owner"], z["vpc_count"], z["tags"]) for z in d["zones"]] == [(env["zone"], ACCT, 1, {"Purpose": "vpce"})]
    assert [(a["vpc_id"], a["vpc_owner"], a["zone_owner"], a["status"]) for a in d["associations"]] == [(env["hub"], ACCT, ACCT, "associated")]


def test_html_report_by_vpc(env, capsys, tmp_path):
    out = tmp_path / "r.html"
    assert pr.main(["by-vpc", "--vpc", env["hub"], "-o", "html", "--out", str(out), "-q"]) == 0
    d = _report_data(out)
    assert not d["vpc_counts_complete"] and not d["authorizations_listed"] and d["notes"]
    assert d["zones"][0]["owner"] == ACCT and d["associations"][0]["vpc_owner"] == ACCT


@pytest.fixture
def auths(monkeypatch, env):
    # One stale authorization (hub, already associated) and one with no association (spoke).
    monkeypatch.setattr(pr, "list_authorizations", lambda route53, zone_id: [("us-east-1", env["hub"]), ("us-east-1", env["spoke"])])


def test_by_zone_hides_stale_authorizations_by_default(env, auths, capsys):
    rows = run_json(pr, ["by-zone", "--zone-name", "ssm.*"], capsys)
    assert [(r["vpc_id"], r["status"]) for r in rows] == [(env["hub"], "associated"), (env["spoke"], "authorized-pending")]
    rows = run_json(pr, ["by-zone", "--zone-name", "ssm.*", "--show-stale-authorizations"], capsys)
    assert sorted(r["status"] for r in rows) == ["associated", "authorized", "authorized-pending"]


def test_zones_splits_pending_and_stale_authorizations(env, auths, capsys):
    rows = run_json(pr, ["zones", "--authorizations"], capsys)
    assert rows[0]["pending_authorizations"] == [f"us-east-1/{env['spoke']}"] and "stale_authorizations" not in rows[0]
    assert pr.main(["zones", "--authorizations", "--show-stale-authorizations", "-o", "csv", "-q"]) == 0
    header, line = capsys.readouterr().out.splitlines()[:2]
    assert header.endswith("pending_authorizations,stale_authorizations") and line.endswith(f"us-east-1/{env['hub']}")


def test_table_highlights_only_on_a_terminal(monkeypatch):
    import io

    from lib.aws_common import render

    class Tty(io.StringIO):
        def isatty(self):
            return True

    rows = [{"status": "associated"}, {"status": "authorized-pending"}]
    hl = lambda r: r["status"] == "authorized-pending"  # noqa: E731
    out = Tty()
    monkeypatch.delenv("NO_COLOR", raising=False)
    render(rows, ["status"], "table", out, highlight=hl)
    lines = out.getvalue().splitlines()
    assert "\033[33m" not in lines[2] and lines[3].startswith("\033[33m")
    plain = io.StringIO()
    render(rows, ["status"], "table", plain, highlight=hl)
    assert "\033[" not in plain.getvalue()
    monkeypatch.setenv("NO_COLOR", "1")
    out = Tty()
    render(rows, ["status"], "table", out, highlight=hl)
    assert "\033[" not in out.getvalue()
