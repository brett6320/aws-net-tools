import pytest

from conftest import load_tool
from lib.aws_common import VpcRef

pa = load_tool("phz_assoc")

HUB, SPOKE = "222222222222", "111111111111"
Z = "Z0123456789ABC"
V1 = VpcRef("vpc-0123456789abcdef0", "us-east-1", SPOKE)
V2 = VpcRef("vpc-0fedcba9876543210", "us-west-2", SPOKE)
LOCAL = VpcRef("vpc-0aaaaaaaaaaaaaaa0", "us-east-1", HUB)


def acts(steps, include_skipped=False):
    return [(s.action, s.side, s.account, s.vpc_id) for s in steps if include_skipped or not s.skipped]


def test_same_account_associate_single_step():
    steps = pa.build_plan("associate", [pa.ZoneState(Z)], [LOCAL], HUB)
    assert acts(steps) == [(pa.ASSOCIATE, "vpc", HUB, LOCAL.vpc_id)]


def test_cross_account_associate_order():
    steps = pa.build_plan("associate", [pa.ZoneState(Z)], [V1, V2], HUB)
    assert acts(steps) == [
        (pa.CREATE_AUTH, "phz", HUB, V1.vpc_id),
        (pa.CREATE_AUTH, "phz", HUB, V2.vpc_id),
        (pa.ASSOCIATE, "vpc", SPOKE, V1.vpc_id),
        (pa.ASSOCIATE, "vpc", SPOKE, V2.vpc_id),
        (pa.DELETE_AUTH, "phz", HUB, V1.vpc_id),
        (pa.DELETE_AUTH, "phz", HUB, V2.vpc_id),
    ]


def test_keep_authorization():
    steps = pa.build_plan("associate", [pa.ZoneState(Z)], [V1], HUB, keep_authorization=True)
    assert [a for a, *_ in acts(steps)] == [pa.CREATE_AUTH, pa.ASSOCIATE]


def test_already_associated_skipped():
    z = pa.ZoneState(Z, associated={("us-east-1", V1.vpc_id)}, authorized=set())
    steps = pa.build_plan("associate", [z], [V1], HUB)
    assert acts(steps) == []
    assert steps[0].skipped == "already associated"


def test_already_associated_cleans_stale_auth():
    key = ("us-east-1", V1.vpc_id)
    z = pa.ZoneState(Z, associated={key}, authorized={key})
    assert acts(pa.build_plan("associate", [z], [V1], HUB)) == [(pa.DELETE_AUTH, "phz", HUB, V1.vpc_id)]


def test_existing_authorization_not_recreated():
    z = pa.ZoneState(Z, associated={("us-east-1", LOCAL.vpc_id)}, authorized={("us-east-1", V1.vpc_id)})
    steps = pa.build_plan("associate", [z], [V1], HUB)
    assert [a for a, *_ in acts(steps)] == [pa.ASSOCIATE, pa.DELETE_AUTH]
    assert any(s.action == pa.CREATE_AUTH and s.skipped for s in steps)


def test_disassociate_last_vpc_blocked():
    z = pa.ZoneState(Z, associated={("us-east-1", V1.vpc_id)}, authorized=set())
    steps = pa.build_plan("disassociate", [z], [V1], HUB)
    assert acts(steps) == [] and "last VPC" in steps[0].skipped


def test_disassociate_all_but_one():
    z = pa.ZoneState(Z, associated={("us-east-1", V1.vpc_id), ("us-west-2", V2.vpc_id)}, authorized=set())
    steps = pa.build_plan("disassociate", [z], [V1, V2], HUB)
    assert acts(steps) == [(pa.DISASSOCIATE, "vpc", SPOKE, V1.vpc_id)]
    assert "last VPC" in steps[1].skipped


def test_disassociate_not_associated():
    z = pa.ZoneState(Z, associated={("us-east-1", LOCAL.vpc_id)}, authorized=set())
    steps = pa.build_plan("disassociate", [z], [V1], HUB)
    assert steps[0].skipped == "not associated"


def test_disassociate_as_phz_and_offline_cleanup():
    steps = pa.build_plan("disassociate", [pa.ZoneState(Z)], [V1], HUB, disassociate_as="phz", cleanup_authorization=True)
    assert acts(steps) == [(pa.DISASSOCIATE, "phz", HUB, V1.vpc_id), (pa.DELETE_AUTH, "phz", HUB, V1.vpc_id)]
    assert steps[1].tolerate_failure
    assert "|| echo" in pa.cli_for(steps[1], None)


def test_cli_rendering():
    s = pa.build_plan("associate", [pa.ZoneState(Z)], [V1], HUB, comment="spoke A")[1]
    assert pa.cli_for(s, "spoke") == (
        "aws route53 associate-vpc-with-hosted-zone --hosted-zone-id Z0123456789ABC "
        "--vpc VPCRegion=us-east-1,VPCId=vpc-0123456789abcdef0 --comment 'spoke A' --profile spoke"
    )


def test_missing_account_rejected():
    with pytest.raises(ValueError):
        pa.build_plan("associate", [pa.ZoneState(Z)], [VpcRef(V1.vpc_id, "us-east-1")], HUB)


def test_offline_cli_requires_accounts(capsys):
    rc = pa.main(["associate", "--offline", "--zone", Z, "--vpc", V1.vpc_id, "-q"])
    assert rc == 2


def test_offline_cli_cross_account(capsys):
    rc = pa.main(
        ["associate", "--offline", "--phz-account", HUB, "--vpc-account", SPOKE, "--zone", Z,
         "--vpc", f"arn:aws:ec2:us-west-2:{SPOKE}:vpc/{V2.vpc_id}", "--phz-profile", "hub", "-q"]
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert out.index(pa.CREATE_AUTH) < out.index(pa.ASSOCIATE) < out.index(pa.DELETE_AUTH)
    assert "VPCRegion=us-west-2" in out and "--profile hub" in out
    assert "run as VPC owner account 111111111111" in out


def test_offline_rejects_execute():
    assert pa.main(["associate", "--offline", "--account", HUB, "--zone", Z, "--vpc", V1.vpc_id, "--execute", "-q"]) == 2
