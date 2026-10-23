import pytest

from lib.aws_common import TagFilter, normalize_zone_id, parse_tag_filters, parse_vpc_ref, parse_vpc_refs, tags_match

VPC = "vpc-0123456789abcdef0"


def test_parse_vpc_id_uses_defaults():
    ref = parse_vpc_ref(VPC, "eu-west-1", "111111111111")
    assert (ref.vpc_id, ref.region, ref.account) == (VPC, "eu-west-1", "111111111111")


def test_parse_short_vpc_id():
    assert parse_vpc_ref("vpc-0a1b2c3d").vpc_id == "vpc-0a1b2c3d"


def test_parse_vpc_arn_overrides_region():
    ref = parse_vpc_ref(f"arn:aws:ec2:us-west-2:222222222222:vpc/{VPC}", "us-east-1", None)
    assert (ref.region, ref.account) == ("us-west-2", "222222222222")


def test_parse_govcloud_arn():
    ref = parse_vpc_ref(f"arn:aws-us-gov:ec2:us-gov-west-1:222222222222:vpc/{VPC}")
    assert ref.region == "us-gov-west-1"


def test_arn_account_conflict_rejected():
    with pytest.raises(ValueError, match="in account 222222222222"):
        parse_vpc_ref(f"arn:aws:ec2:us-west-2:222222222222:vpc/{VPC}", None, "111111111111")


@pytest.mark.parametrize("bad", ["vpc-xyz", "subnet-0123456789abcdef0", "arn:aws:ec2:us-east-1:12:vpc/vpc-01234567", ""])
def test_invalid_vpc(bad):
    with pytest.raises(ValueError):
        parse_vpc_ref(bad)


def test_parse_vpc_refs_csv_dedup():
    refs = parse_vpc_refs([f"{VPC},{VPC}", "vpc-0a1b2c3d"], "us-east-1", None)
    assert [r.vpc_id for r in refs] == [VPC, "vpc-0a1b2c3d"]


@pytest.mark.parametrize(
    "raw", ["Z0123456789ABC", "/hostedzone/Z0123456789ABC", "arn:aws:route53:::hostedzone/Z0123456789ABC"]
)
def test_normalize_zone_id(raw):
    assert normalize_zone_id(raw) == "Z0123456789ABC"


def test_normalize_zone_id_invalid():
    with pytest.raises(ValueError):
        normalize_zone_id("not-a-zone")


def test_tag_filters():
    inc = parse_tag_filters(["Env=prod,stage", "Owner", "App=net*"])
    assert inc == [TagFilter("Env", ("prod", "stage")), TagFilter("Owner"), TagFilter("App", ("net*",))]
    assert inc[0].to_ec2_filter() == {"Name": "tag:Env", "Values": ["prod", "stage"]}
    assert inc[1].to_ec2_filter() == {"Name": "tag-key", "Values": ["Owner"]}
    tags = {"Env": "stage", "Owner": "x", "App": "network"}
    assert tags_match(tags, inc)
    assert not tags_match(tags, inc, parse_tag_filters(["Env=stage"]))
    assert not tags_match({"Env": "dev", "Owner": "x", "App": "network"}, inc)


@pytest.mark.parametrize("bad", ["=x", "Key=", ""])
def test_tag_filter_invalid(bad):
    with pytest.raises(ValueError):
        parse_tag_filters([bad])
