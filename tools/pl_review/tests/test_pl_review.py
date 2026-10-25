import os, tempfile, pathlib
cfg = pathlib.Path(tempfile.mkdtemp())/"config"
cfg.write_text("""
[profile hcli-net-ro]
region = us-east-1
role_arn = arn:aws:iam::123456789012:role/ReadOnly
source_profile = hcli-app-ro
[profile hcli-app-ro]
region = us-east-1
[profile zz-sso-test]
sso_account_id = 999888777666
sso_role_name = ReadOnly
sso_start_url = https://example.awsapps.com/start
sso_region = us-east-1
[profile hcli-app-priv]
region = us-east-1
[profile hcli-x-cpar]
region = us-east-1
[profile bmeier-prd-ro]
region = us-east-1
""")
os.environ["AWS_CONFIG_FILE"] = str(cfg)
cred = cfg.parent/"credentials"
cred.write_text("".join(f"[{n}]\naws_access_key_id = testing\naws_secret_access_key = testing\n" for n in ["hcli-net-ro","hcli-app-ro","hcli-app-priv","hcli-x-cpar","bmeier-prd-ro"]))
os.environ["AWS_SHARED_CREDENTIALS_FILE"] = str(cred)
os.environ["PL_REVIEW_NO_TRUSTSTORE"] = "1"
os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
from moto import mock_aws
import boto3
import pl_review

with mock_aws():
    assert pl_review.discover_profiles() == ["hcli-app-ro", "hcli-net-ro"], pl_review.discover_profiles()
    assert pl_review.aws_managed_weight("com.amazonaws.us-east-1.s3") == 1
    assert pl_review.aws_managed_weight("com.amazonaws.ap-southeast-2.dynamodb") == 1
    assert pl_review.aws_managed_weight("com.amazonaws.us-gov-west-1.ipv6.vpc-lattice") == 10
    assert pl_review.aws_managed_weight("com.amazonaws.global.cloudfront.origin-facing") == 55
    assert pl_review.aws_managed_weight("com.amazonaws.us-east-1.unknown") is None
    assert pl_review.aws_managed_weight(None) is None
    assert pl_review.SessionCache.configured_account_id("hcli-net-ro") == "123456789012"  # via role_arn
    assert pl_review.SessionCache.configured_account_id("zz-sso-test") == "999888777666"  # via sso_account_id
    assert pl_review.SessionCache.configured_account_id("hcli-app-ro") is None
    sc = pl_review.SessionCache("us-east-1")
    assert sc.account_id("hcli-app-ro", allow_network=False) is None  # no session/STS
    assert sc._sessions == {}
    assert sc.account_id("hcli-net-ro", allow_network=False) == "123456789012"
    assert sc._sessions == {}, "config lookup must not create a boto3 session in cache"
    ec2 = boto3.client("ec2", region_name="us-east-1")
    pl = ec2.create_managed_prefix_list(PrefixListName="shared", MaxEntries=40, AddressFamily="IPv4",
        Entries=[{"Cidr": "10.0.0.0/24"}, {"Cidr": "10.0.1.0/24"}])["PrefixList"]["PrefixListId"]
    other = ec2.create_managed_prefix_list(PrefixListName="other", MaxEntries=30, AddressFamily="IPv4")["PrefixList"]["PrefixListId"]
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg1 = ec2.create_security_group(GroupName="sg-tight", Description="d", VpcId=vpc)["GroupId"]
    sg2 = ec2.create_security_group(GroupName="sg-loose", Description="d", VpcId=vpc)["GroupId"]
    ec2.create_tags(Resources=[sg1], Tags=[{"Key": "FMManaged", "Value": "true"}, {"Key": "FMPolicyId", "Value": "abc-123"}])
    assert pl_review.detect_fm({"GroupName": "FMManagedSecurityGroupdeadbeef", "Tags": []}) == (True, "deadbeef")
    assert pl_review.detect_fm({"GroupName": "web", "Tags": [{"Key": "FMManaged", "Value": "true"}, {"Key": "FMPolicyId", "Value": "p1"}]}) == (True, "p1")
    assert pl_review.detect_fm({"GroupName": "web", "Tags": []}) == (False, None)
    ec2.authorize_security_group_ingress(GroupId=sg1, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "PrefixListIds": [{"PrefixListId": pl}, {"PrefixListId": other}]},
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": f"10.1.{i}.0/24"} for i in range(5)]},
    ])
    ec2.authorize_security_group_ingress(GroupId=sg2, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "PrefixListIds": [{"PrefixListId": pl}]}])
    acct = boto3.client("sts").get_caller_identity()["Account"]
    # moto lacks get_managed_prefix_list_associations; stub it
    pl_review.PrefixListResolver.associations = lambda self, p, i: [
        {"ResourceId": sg1, "ResourceOwner": acct}, {"ResourceId": sg2, "ResourceOwner": acct},
        {"ResourceId": "sg-0deadbeef", "ResourceOwner": "999999999999"}]
    # AWS-managed PL: no MaxEntries -> weight by entry count
    real_describe = pl_review.PrefixListResolver.describe
    def fake_describe(self, profile, pl_id, use_cache=True):
        d = real_describe(self, profile, pl_id, use_cache)
        if d and d.get("PrefixListId") == other:
            d = {**d, "MaxEntries": None}
        return d
    pl_review.PrefixListResolver.describe = fake_describe
    ec2.modify_managed_prefix_list(PrefixListId=other, CurrentVersion=1, AddEntries=[{"Cidr": "192.168.0.0/24"}, {"Cidr": "192.168.1.0/24"}, {"Cidr": "192.168.2.0/24"}])
    s3pl = ec2.create_managed_prefix_list(PrefixListName="com.amazonaws.us-east-1.s3", MaxEntries=50, AddressFamily="IPv4",
        Entries=[{"Cidr": f"52.216.{i}.0/24"} for i in range(8)])["PrefixList"]["PrefixListId"]
    def fake_describe2(self, profile, pl_id, use_cache=True):
        d = fake_describe(self, profile, pl_id, use_cache)
        if d and d.get("PrefixListId") == s3pl:
            d = {**d, "OwnerId": "AWS", "MaxEntries": None}
        return d
    pl_review.PrefixListResolver.describe = fake_describe2
    ec2.authorize_security_group_egress(GroupId=sg2, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "PrefixListIds": [{"PrefixListId": s3pl}]}])
    cpath = pathlib.Path(tempfile.mkdtemp())/"c.json"
    r = pl_review.review_prefix_list(pl=pl, proposed_length=95, limit=100, cache_path=cpath)
    import json as _j
    ck = _j.loads(cpath.read_text())
    print("CACHE KEYS:", sorted(ck))
    assert f"account:hcli-app-ro" in ck and f"pl:us-east-1:{other}" in ck and f"sg:us-east-1:{sg1}" in ck
    r2 = pl_review.review_prefix_list(pl=pl, proposed_length=95, limit=100, cache_path=cpath)
    assert r2.at_risk_count == r.at_risk_count
    # no path -> in-memory only, nothing written to cwd
    before = set(pathlib.Path.cwd().rglob("*cache*.json"))
    r3 = pl_review.review_prefix_list(pl=pl, proposed_length=95, limit=100)
    assert r3.at_risk_count == 1 and set(pathlib.Path.cwd().rglob("*cache*.json")) == before
    pl_review.print_summary(r)
    paths = pl_review.write_report(r, pathlib.Path(tempfile.mkdtemp()))
    assert [x.suffix for x in paths] == [".json", ".md", ".csv"], paths
    import csv as _csv
    rows = list(_csv.DictReader(paths[2].open()))
    assert len(rows) == 5 and rows[0]["status"] == "EXCEEDS" and rows[-1]["status"] == "ERROR", rows
    md = paths[1].read_text()
    assert "| ingress |" in md and "**EXCEEDS**" in md
    print(md)
    sg1r = next(s for s in r.security_groups if s.group_id == sg1)
    # 5 cidr + other(3 entries, no MaxEntries) + pl(40) = 48 now; 5+3+95 = 103 proposed -> exceeds
    assert sg1r.ingress.current_weight == 48, sg1r.ingress
    assert sg1r.ingress.proposed_weight == 103 and sg1r.ingress.exceeds_proposed
    sg2r = next(s for s in r.security_groups if s.group_id == sg2)
    assert sg2r.ingress.proposed_weight == 95 and not sg2r.at_risk
    assert sg2r.egress.current_weight == 2, sg2r.egress  # default egress rule + S3 PL (weight 1, not 8 entries)
    assert r.accounts_without_profile == ["999999999999"]
    assert sg1r.fm_managed and sg1r.fm_policy_id == "abc-123" and not sg2r.fm_managed
    assert r.fm_policies["abc-123"]["replicas"] == 1 and r.fm_policies["abc-123"]["at_risk"] == 1, r.fm_policies
    assert "## Firewall Manager policies" in pl_review.render_markdown(r)
    assert r.at_risk_count == 1 and r.current_entry_count == 2
    # None-safety in renderers
    import copy
    rn = copy.deepcopy(r)
    rn.prefix_list_name = None
    rn.security_groups[0].group_name = None
    rn.security_groups[0].vpc_id = None
    rn.security_groups[-1].error = None  # error row w/o message -> treated as normal row
    for fn in (pl_review.render_markdown, pl_review.render_csv, pl_review.render_json):
        out = fn(rn); assert "None" not in out.replace("null", ""), fn.__name__
    pl_review.print_summary(rn)
    # Unauthorized in an account -> error rows, run continues, report still renders
    from botocore.exceptions import ClientError as _CE
    def denied(*a, **k):
        raise _CE({"Error": {"Code": "UnauthorizedOperation", "Message": "You are not authorized to perform this operation."}}, "DescribeSecurityGroupRules")
    real_fetch_rules = pl_review.fetch_rules
    pl_review.fetch_rules = denied
    ru = pl_review.review_prefix_list(pl=pl, proposed_length=95, limit=100)
    pl_review.fetch_rules = real_fetch_rules
    assert ru.error_count == 3 and ru.at_risk_count == 0, (ru.error_count, ru.at_risk_count)
    assert all("UnauthorizedOperation" in (x.error or "") for x in ru.security_groups if x.profile), [x.error for x in ru.security_groups]
    pl_review.render_markdown(ru); pl_review.render_csv(ru)
    print("ALL ASSERTS PASS")
