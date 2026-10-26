import copy
import ipaddress
import json
from pathlib import Path

import pytest
from botocore.exceptions import ClientError

import sg_effect_fake as F
from conftest import load_tool
from lib import sg_algebra as acc
from lib.eni_owners import eni_owner

sge = load_tool("sg_effect")

ALB, LAMBDA, WEB1, WEB2 = "web-alb", "api-fn", "i-0web1000000000001", "i-0web2000000000002"


@pytest.fixture
def fake(monkeypatch):
    holder = {"ec2": F.FakeEC2()}
    monkeypatch.setattr(sge, "get_client", lambda svc, session: holder["ec2"])
    return holder


@pytest.fixture
def bundle(fake):
    return sge.collect(object(), "us-east-1", F.WEB)


def res(result, rid, groups=None):
    hits = [r for r in result["resources"] if r["id"] == rid and (groups is None or r["groups"] == groups)]
    assert len(hits) == 1, [r["id"] for r in result["resources"]]
    return hits[0]


def lost(block, direction="inbound"):
    return {i["rule"]: i["lost"] for i in block[direction]}


def R(proto, lo=None, hi=None, peer="0.0.0.0/0", kind="cidr", egress=False, rid="r", group="g", nets=()):
    return acc.Rule(rid, group, egress, proto, lo, hi, kind, peer, peer_nets=nets)


# ---------- rule algebra ----------

def test_peers_minus_and_overlap():
    a = acc.Peers.of([ipaddress.ip_network("10.0.0.0/8")], ["sg:x"])
    b = acc.Peers.of([ipaddress.ip_network("10.1.0.0/16"), ipaddress.ip_network("2001:db8::/32")], ["sg:x"])
    left = a.minus(b)
    assert not left.atoms and ipaddress.ip_network("10.1.0.0/16") not in left.nets
    assert sum(n.num_addresses for n in left.nets) == 2 ** 24 - 2 ** 16
    assert a.overlaps(b) and not acc.Peers.of(atoms=["sg:y"]).overlaps(b)
    assert not acc.Peers.of([ipaddress.ip_network("10.0.0.0/8")]).minus(acc.Peers.of([ipaddress.ip_network("0.0.0.0/0")]))


def test_residual_ports_and_protocols():
    assert acc.residual(R("tcp", 443, 443), [R("tcp", 0, 65535)]) == []
    left = acc.residual(R("tcp", 80, 90), [R("tcp", 85, 85)])
    assert [(r.lo, r.hi) for r in left] == [(80, 84), (86, 90)]
    assert acc.residual(R("tcp", 22, 22), [R("-1")]) == []
    all_left = acc.residual(R("-1"), [R("tcp", 0, 65535)])
    assert {r.key for r in all_left} == {"udp", "icmp", "icmpv6", "ip"}
    assert acc.residual(R("tcp", 22, 22, egress=True), [R("-1")]) != []          # other direction
    assert acc.residual(R("icmp", 8, 0), [R("icmp", -1, -1)]) == []
    assert acc.residual(R("icmp", -1, -1), [R("icmp", 8, 0)])[0].key == "icmp"
    assert acc.residual(R("47"), [R("-1")]) == [] and acc.residual(R("47"), [R("50")]) != []
    sg = R("tcp", 5432, 5432, "sg-1", "sg")
    assert acc.residual(sg, [R("tcp", 5432, 5432, "sg-1", "sg")]) == []
    assert acc.residual(sg, [R("tcp", 5432, 5432)]) != []                       # a CIDR doesn't cover a group
    pl = R("tcp", 22, 22, "pl-1", "pl", nets=(ipaddress.ip_network("10.0.0.0/8"),))
    assert acc.residual(pl, [R("tcp", 22, 22, "10.0.0.0/8")]) == []
    assert acc.residual(R("tcp", 22, 22, "pl-2", "pl"), [R("tcp", 22, 22)]) != []  # unexpanded list: opaque
    assert acc.covers(R("tcp", 0, 65535), R("tcp", 1, 2)) and not acc.covers(R("tcp", 1, 2), R("tcp", 0, 65535))


def test_text_helpers():
    assert acc.ports_text("-1", None, None) == "all traffic"
    assert acc.ports_text("tcp", 0, 65535) == "tcp all ports"
    assert acc.ports_text("udp", 53, 53) == "udp 53" and acc.ports_text("tcp", 1, 2) == "tcp 1-2"
    assert acc.ports_text("icmp", -1, -1) == "icmp all types" and acc.ports_text("icmpv6", 128, 0) == "icmpv6 type 128"
    assert acc.ports_text("47", None, None) == "protocol 47 (GRE)" and acc.ports_text("200", 0, 0) == "protocol 200"
    assert acc.normalize_protocol(6) == "tcp" and acc.normalize_protocol(None) == "-1"
    r = acc.residual(R("-1"), [R("tcp", 0, 65535), R("icmp", -1, -1, "10.0.0.0/8")])
    lines = acc.describe(r, False)
    assert "udp all ports from 0.0.0.0/0" in lines and "all other protocols from 0.0.0.0/0" in lines
    assert any(x.startswith("icmp all types from 0.0.0.0/5") for x in lines)
    assert acc.describe(acc.residual(R("-1"), []), True) == ["all traffic to 0.0.0.0/0"]
    assert acc.describe([acc.Rect("icmp", 3, 4, acc.Peers.of(atoms=["sg:a"]))], False, {"a": "x"}) == \
        ["icmp types 3-4 from a (x)"]
    assert acc.describe([acc.Rect("ip", 5, 9, acc.Peers.of(atoms=["pl:p"]))], False) == ["protocols 5-9 from p"]
    assert acc.describe([acc.Rect("tcp", 1, 1, acc.Peers.of(atoms=["sg:a"]))], False) == ["tcp 1 from a"]
    many = acc.Peers.of([ipaddress.ip_network(f"10.{i}.0.0/16") for i in range(0, 20, 2)])
    assert acc.peers_text(many).endswith("and 4 more")
    assert acc.describe([], False) == []


# ---------- collection ----------

def test_eni_owner_classification():
    cases = [
        ({"Attachment": {"InstanceId": "i-1"}}, ("EC2 instance", "i-1")),
        ({"Description": "ELB net/nlb-1/abc", "RequesterManaged": True}, ("Network Load Balancer", "nlb-1")),
        ({"Description": "ELB gwy/gw-1/abc"}, ("Gateway Load Balancer", "gw-1")),
        ({"Description": "ELB classic-1"}, ("Classic Load Balancer", "classic-1")),
        ({"Description": "AWS Lambda VPC ENI-fn"}, ("Lambda function", "fn")),
        ({"Description": "VPC Endpoint Interface vpce-0abc"}, ("VPC endpoint", "vpce-0abc")),
        ({"Description": "EFS mount target for fs-0abc (fsmt-1)"}, ("EFS file system", "fs-0abc")),
        ({"Description": "arn:aws:ecs:us-east-1:111122223333:attachment/abc-123"}, ("ECS task", "abc-123")),
        ({"Description": "Amazon EKS prod"}, ("EKS cluster", "prod")),
        ({"Description": "RDSNetworkInterface"}, ("RDS", "eni-x")),
        ({"Description": "something", "InterfaceType": "api_gateway_managed"}, ("API Gateway", "eni-x")),
        ({"Description": "custom", "RequesterManaged": True, "Attachment": {"InstanceId": "i-2"}},
         ("EC2 instance", "i-2")),
        ({}, ("Network interface", "eni-x")),
    ]
    for extra, want in cases:
        assert eni_owner({"NetworkInterfaceId": "eni-x", **extra}) == want


def test_collect(bundle, fake):
    assert bundle["target"] == F.WEB and bundle["account"] == F.ACCOUNT
    assert len(bundle["enis"]) == 6 and bundle["referencing"] == [F.DB]
    assert [e["id"] for e in bundle["referencing_enis"]] == ["eni-0rds1000000000001"]
    assert bundle["prefix_lists"][F.CORP]["entries"] == ["10.0.0.0/8", "192.168.0.0/16"]
    assert bundle["instance_names"] == {WEB1: "web-1", WEB2: "web-2"}
    assert set(bundle["groups"]) == {F.WEB, F.BASE, F.ADMIN, F.DB}
    assert bundle["warnings"] == [f"{F.PEERED}: DescribeSecurityGroups failed: InvalidGroup.NotFound"]
    sgref = next(r for r in bundle["rules"] if r["id"] == "sgr-0webself")
    assert sgref["peer_kind"] == "sg" and sgref["peer"] == F.WEB


def test_collect_errors(fake):
    with pytest.raises(sge.ValidationError, match="Not a security group"):
        sge.collect(object(), "us-east-1", "web-sg")
    with pytest.raises(sge.ValidationError, match="No region"):
        sge.collect(object(), None, F.WEB)
    with pytest.raises(sge.ValidationError, match="not found"):
        sge.collect(object(), "us-east-1", "sg-0fff0000ffff00001")
    d = F.data()
    d["groups"] = [g for g in d["groups"] if g["GroupId"] != F.WEB]
    fake["ec2"] = F.FakeEC2(d)
    with pytest.raises(sge.ValidationError, match="not found"):
        sge.collect(object(), "us-east-1", F.WEB)


def test_collect_partial_failures(fake):
    fake["ec2"] = F.FakeEC2(fail={"get_managed_prefix_list_entries", "describe_instances", "egress_filter",
                                  "describe_managed_prefix_lists"})
    b = sge.collect(object(), "us-east-1", F.WEB)
    w = " ".join(b["warnings"])
    assert f"{F.CORP}: UnauthorizedOperation: prefix list entries unreadable" in w and "DescribeInstances failed" in w
    assert "egress.ip-permission.group-id" in w
    assert b["prefix_lists"][F.CORP] == {"id": F.CORP, "name": None, "entries": None}
    fake["ec2"] = F.FakeEC2(fail={"describe_security_group_rules"})
    b = sge.collect(object(), "us-east-1", F.WEB)
    assert b["rules"] == [] and "DescribeSecurityGroupRules failed" in b["warnings"][0]


def test_collect_unexpected_error_propagates(fake, monkeypatch):
    def boom(GroupIds):
        raise ClientError({"Error": {"Code": "RequestLimitExceeded", "Message": "slow"}}, "Describe")
    monkeypatch.setattr(fake["ec2"], "describe_security_groups", boom)
    with pytest.raises(ClientError):
        sge.collect(object(), "us-east-1", F.WEB)


# ---------- analysis ----------

def test_resources_grouping(bundle):
    rs = sge.resources(bundle)
    assert [(r["kind"], r["id"]) for r in rs] == [("Application Load Balancer", ALB), ("EC2 instance", WEB1),
                                                 ("EC2 instance", WEB2), ("EC2 instance", WEB2),
                                                 ("Lambda function", LAMBDA)]
    alb = rs[0]
    assert len(alb["enis"]) == 2 and alb["groups"] == [F.WEB, F.ADMIN] and not alb["split"]
    assert rs[2]["split"] and rs[1]["name"] == "web-1"


def test_effective_access(bundle):
    r = sge.analyze(bundle)
    web1 = res(r, WEB1)
    inbound = {(e["traffic"], e["peer"]): e for e in web1["effective"]["inbound"]}
    assert inbound[("tcp 443", "0.0.0.0/0")]["only_target"] and inbound[("tcp 443", "0.0.0.0/0")]["open_to_world"]
    ssh = inbound[("tcp 22", "10.0.0.0/8")]
    assert not ssh["from_target"] and ssh["covered_by"][0]["rule"] == "sgr-0web0022"
    out = web1["effective"]["outbound"]
    assert len(out) == 1 and {g["group"] for g in out[0]["grants"]} == {F.WEB, F.BASE}
    assert out[0]["from_target"] and not out[0]["only_target"]
    assert inbound[("tcp 443", "0.0.0.0/0")]["descriptions"] == ["https"]


def test_remove_sg_scenario(bundle):
    r = sge.analyze(bundle)
    web1 = res(r, WEB1)["remove_sg"]
    l_in = lost(web1)
    assert l_in["sgr-0web0443"] == ["tcp 443 from 0.0.0.0/0"]
    assert l_in["sgr-0web0022"] == ["tcp 22 from pl-0123456789abcdef0 (corp-networks) except 10.0.0.0/8"]
    assert lost(web1, "outbound")["sgr-0web0out"] == []                       # base allows it too
    kept = next(i for i in web1["outbound"] if i["rule"] == "sgr-0web0out")
    assert kept["kept_by"][0]["group"] == F.BASE
    assert [p["text"] for p in web1["as_peer"]] == \
        [f"{F.DB} (db-sg) would stop allowing inbound tcp 5432 from this resource"]   # 5433 still via base
    alb = res(r, ALB)["remove_sg"]
    assert lost(alb)["sgr-0web0443"] == []                                     # admin allows 443 from anywhere
    assert lost(alb)["sgr-0web0080"] == ["tcp 80 from 0.0.0.0/0 except 10.1.0.0/16"]
    assert alb["as_peer"][0]["text"].endswith("inbound tcp 5432-5433 from this resource")
    lam = res(r, LAMBDA)["remove_sg"]
    assert all(i["lost"] for i in lam["inbound"] + lam["outbound"])


def test_remove_rules_scenario(bundle):
    r = sge.analyze(bundle, ["sgr-0web0443", "in:tcp:22:pl-0123456789abcdef0", "sgr-0web0443"])
    assert [x["id"] for x in r["removing"]] == ["sgr-0web0443", "sgr-0web0022"]
    assert lost(res(r, ALB)["remove_rules"])["sgr-0web0443"] == []
    assert lost(res(r, WEB1)["remove_rules"])["sgr-0web0022"] == \
        ["tcp 22 from pl-0123456789abcdef0 (corp-networks) except 10.0.0.0/8"]
    assert lost(res(r, LAMBDA)["remove_rules"])["sgr-0web0443"] == ["tcp 443 from 0.0.0.0/0"]
    assert sge.loses_access(r)
    r = sge.analyze(bundle, ["out:all:all:0.0.0.0/0"])
    assert sge.loses_access(r)                                                   # Lambda has no other group
    r = sge.analyze(bundle, ["sgr-0web0443"], only=[ALB])
    assert [x["id"] for x in r["resources"]] == [ALB] and not sge.loses_access(r)


def test_remove_rules_kept_by_several_rules(bundle):
    b = copy.deepcopy(bundle)
    b["rules"] += [
        {"id": "sgr-0adm0080", "group": F.ADMIN, "egress": False, "protocol": "tcp", "from": 80, "to": 80,
         "peer_kind": "cidr", "peer": "0.0.0.0/1"},
        {"id": "sgr-0adm0081", "group": F.ADMIN, "egress": False, "protocol": "tcp", "from": 80, "to": 80,
         "peer_kind": "cidr", "peer": "128.0.0.0/1"}]
    r = sge.analyze(b, ["sgr-0web0080"], only=[ALB])
    item = res(r, ALB)["remove_rules"]["inbound"][0]
    assert item["lost"] == [] and item["kept_by"][0]["text"] == "several rules together"


def test_rule_summary_and_referencing(bundle):
    r = sge.analyze(bundle)
    s = {x["rule"]: x for x in r["rule_summary"]}
    assert len(s["sgr-0web0443"]["unique_on"]) == 4 and s["sgr-0web0443"]["redundant_on"] == [
        "Application Load Balancer web-alb"]
    assert len(s["sgr-0web0out"]["redundant_on"]) == 2
    assert f"EC2 instance {WEB2} (web-2) via eni-0web2000000000002" in s["sgr-0web0out"]["unique_on"]
    ref = r["referencing"][0]
    assert ref["group"] == F.DB and ref["rules"] == [f"inbound tcp 5432-5433 from {F.WEB} (web-sg)"]
    assert ref["resources"] == [{"kind": "RDS", "id": "eni-0rds1000000000001", "name": None}]


def test_rule_specs():
    assert sge.parse_rule_spec("in:tcp:443:0.0.0.0/0") == {"egress": False, "protocol": "tcp", "lo": 443, "hi": 443,
                                                          "peer": "0.0.0.0/0"}
    assert sge.parse_rule_spec("egress:6:8000-8080:10.1.2.3/8")["peer"] == "10.0.0.0/8"
    assert sge.parse_rule_spec("out:all:*:sg-0123")["protocol"] == "-1"
    with pytest.raises(sge.ValidationError, match="DIRECTION:PROTOCOL"):
        sge.parse_rule_spec("tcp/443")
    rules = [R("tcp", 0, 65535, rid="a"), R("icmp", -1, -1, rid="b")]
    assert sge._matches(rules[0], sge.parse_rule_spec("in:tcp:all:0.0.0.0/0"))
    assert sge._matches(rules[1], sge.parse_rule_spec("in:icmp:all:0.0.0.0/0"))
    assert not sge._matches(rules[0], sge.parse_rule_spec("out:tcp:all:0.0.0.0/0"))
    with pytest.raises(sge.ValidationError, match="No rule of the target group"):
        sge.select_rules(rules, ["sgr-0missing"])


def test_no_resources(bundle):
    b = copy.deepcopy(bundle)
    b["enis"], b["referencing"] = [], []
    r = sge.analyze(b)
    assert r["resources"] == []
    text = sge.render_text(r, full=True)
    assert f"No resources use {F.WEB}." in text and "Target rules across" not in text
    assert '"rows": []' in sge.render_html(r).replace("\\u003c", "<")


# ---------- output ----------

def test_text_output(bundle):
    text = sge.render_text(sge.analyze(bundle, ["sgr-0web0443"]), full=True)
    assert text.startswith(f"Security group {F.WEB} (web-sg), {F.VPC}, account {F.ACCOUNT}, us-east-1")
    assert "Scenario" not in text and "If the selected rules are removed" not in text   # HTML only
    assert "== EC2 instance i-0web1000000000001 (web-1)" in text and "(ENIs with different groups" in text
    assert "   * tcp 443 from 0.0.0.0/0" in text
    assert "(covered by inbound tcp 22 from pl-0123456789abcdef0 (corp-networks))" in text
    assert "     loses inbound tcp 443 from 0.0.0.0/0   [sgr-0web0443]" in text
    assert "     partly loses inbound tcp 80 from 0.0.0.0/0 except 10.1.0.0/16   [sgr-0web0080]" in text
    assert "keeps outbound all traffic to 0.0.0.0/0   (still allowed by outbound all traffic to 0.0.0.0/0" in text
    assert "sgr-0web0out  outbound all traffic to 0.0.0.0/0: only rule allowing it on 3, redundant on 2" in text
    assert f"Groups whose rules reference {F.WEB}:" in text and "% sg-0eee5555ffff66667" in text


def test_concise_output(bundle):
    text = sge.render_text(sge.analyze(bundle, ["sgr-0web0443"]))
    assert text.startswith(f"{F.WEB} (web-sg) · {F.VPC} · account {F.ACCOUNT} · us-east-1 · 5 rules · "
                           "used by 5 resources")
    assert "Inbound (" not in text and "keeps" not in text and "sgr-0web0443" not in text
    # resources losing the same access share one block
    assert f"  EC2 instance {WEB2} (web-2) via eni-0web2000000000002\n  Lambda function api-fn\n" in text
    assert f"  EC2 instance {WEB1} (web-1)   [also: {F.BASE} (base-sg)]" in text
    assert "    ~ inbound tcp 22 from pl-0123456789abcdef0 (corp-networks) except 10.0.0.0/8" in text
    assert "    - sg-0ddd4444eeee55556 (db-sg) would stop allowing inbound tcp 5432 from this resource" in text
    assert f"No rule of {F.WEB} is redundant on every resource." in text
    assert text.count("    - inbound tcp 443 from 0.0.0.0/0") == 2      # two blocks, not four resources


def test_concise_no_change_and_redundant(bundle):
    b = copy.deepcopy(bundle)
    b["enis"] = [e for e in b["enis"] if e["resource"] == ALB]
    b["rules"] = [r for r in b["rules"] if r["id"] in ("sgr-0web0443", "sgr-0adm0443")]
    text = sge.render_text(sge.analyze(b))
    assert "  No change: Application Load Balancer web-alb" in text
    assert "Redundant on every resource (deleting them changes no access):\n  sgr-0web0443" in text
    b["enis"] = []
    assert sge.render_text(sge.analyze(b)).rstrip().endswith("not used by any resource")
    b["rules"] = []
    b["enis"] = [e for e in bundle["enis"] if e["resource"] == ALB]
    text = sge.render_text(sge.analyze(b))                                  # a group with no rules
    assert "Redundant on every resource" not in text and "No rule of" not in text


def test_text_redundant_everywhere_and_no_change(bundle):
    b = copy.deepcopy(bundle)
    b["enis"] = [e for e in b["enis"] if e["resource"] == ALB]
    b["rules"] = [r for r in b["rules"] if r["id"] in ("sgr-0web0443", "sgr-0adm0443")]
    text = sge.render_text(sge.analyze(b), full=True)
    assert "redundant on all 1: removing it changes no access" in text
    assert "Outbound: nothing allowed" in text
    b["rules"] = [r for r in b["rules"] if r["group"] != F.WEB]
    assert "     no change" in sge.render_text(sge.analyze(b), full=True)


def html_data(out: str) -> dict:
    return json.loads(out.split('<script id="data" type="application/json">', 1)[1].split("</script>", 1)[0])


def test_html_report(bundle):
    b = copy.deepcopy(bundle)
    b["groups"][F.ADMIN]["name"] = "<admin>"
    r = sge.analyze(b, ["sgr-0web0443"])
    out = sge.render_html(r)
    assert "<admin>" not in out and "\\u003cadmin>" in out
    d = html_data(out)
    assert [t["id"] for t in d["tables"]] == ["remove_group", "remove_rules", "rules", "access", "referencing",
                                              "warnings"]
    assert [5, "resources"] in d["cards"] and [4, "lose access if the selected rules are removed"] in d["cards"]
    assert d["meta"][-1] == "Scenario: remove sgr-0web0443 inbound tcp 443 from 0.0.0.0/0"
    group = d["tables"][0]["rows"]
    alb = [x for x in group if x["resource"] == "Application Load Balancer web-alb"]
    assert {"change": "keeps", "access": "tcp 443 from 0.0.0.0/0", "rule": "sgr-0web0443"}.items() <= alb[0].items()
    assert alb[0]["note"].startswith("still allowed by inbound tcp 443 from 0.0.0.0/0 (sg-0ccc3333dddd44445")
    assert any(x["change"] == "partly loses" and x["access"].endswith("except 10.1.0.0/16") for x in alb)
    assert any(x["change"] == "as a peer" and x["direction"] == "inbound" for x in alb)
    access = d["tables"][3]["rows"]
    assert {x["target"] for x in access} == {"target only", "target + other", "other groups"}
    assert any("anywhere" in x["note"] for x in access) and any("covered by" in x["note"] for x in access)
    ok = html_data(sge.render_html(sge.analyze(b, ["sgr-0web0443"], only=[ALB])))
    assert [0, "lose access if the selected rules are removed"] in ok["cards"]
    assert [x["change"] for x in ok["tables"][1]["rows"]] == ["no change", "keeps"]
    plain = html_data(sge.render_html(sge.analyze(b)))
    assert [t["id"] for t in plain["tables"]][:2] == ["remove_group", "rules"]
    folded = {t["id"]: t.get("collapsed") for t in d["tables"]}
    assert folded["remove_group"] is True and folded["rules"] is True and not folded["remove_rules"]
    folded = {t["id"]: t.get("collapsed") for t in plain["tables"]}
    assert folded["remove_group"] is False and folded["rules"] is True


def test_change_rows_csv(bundle):
    rows = sge.change_rows(sge.analyze(bundle))
    assert set(rows[0]) == set(sge.CSV_COLUMNS)
    assert {x["change"] for x in rows} >= {"loses", "partly loses", "as a peer", "keeps"}


# ---------- CLI ----------

@pytest.fixture
def cli(fake, monkeypatch):
    monkeypatch.setattr(sge, "resolve_account_profiles",
                        lambda args, arns, bare: ({F.ACCOUNT: (None, "default credentials")}, F.ACCOUNT))


def test_cli(cli, capsys):
    assert sge.main([F.WEB, "--json-out", "r.json", "--html-out", "r.html", "-q"]) == 0
    out = capsys.readouterr().out
    assert "If sg-0aaa1111bbbb22223 (web-sg) is removed:" in out and "Inbound (" not in out
    assert "Saved:" in out and "r.html" in out
    saved = json.loads(Path("r.json").read_text())
    assert saved["bundle"]["target"] == F.WEB and saved["target"]["id"] == F.WEB
    reports = sorted(Path("reports/sg_effect").rglob("*"))
    assert [x.suffix for x in reports if x.is_file()] == [".csv"]          # json and html went to the flags
    assert sge.main(["--from-json", "r.json", "--full", "--no-save"]) == 0
    assert "Resources using" in capsys.readouterr().out
    assert sge.main(["--from-json", "r.json", "--remove-rule", "sgr-0web0443", "--no-save"]) == 2
    assert sge.main(["--from-json", "r.json", "--remove-rule", "sgr-0web0443", "--no-save",
                     "--html-out", "s.html"]) == 1
    out = capsys.readouterr().out
    assert "If the selected rules are removed" not in out
    assert "Rule removal scenario (sgr-0web0443): see the HTML report" in out
    assert "If the selected rules are removed" in Path("s.html").read_text()
    assert sge.main(["--from-json", "r.json", "--remove-rule", "sgr-0web0443", "--resource", ALB,
                     "--json", "--no-save", "--html-out", "x.html"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert [x["id"] for x in data["resources"]] == [ALB] and Path("x.html").is_file()
    assert "removing" not in data and "remove_rules" not in data["resources"][0]
    assert sge.main(["--from-json", "r.json", "--resource", "i-0nothing", "--no-save"]) == 0
    assert sge.main(["sg-0fff0000ffff00001", "--from-json", "r.json"]) == 2
    arn = f"arn:aws:ec2:us-east-1:{F.ACCOUNT}:security-group/{F.WEB}"
    assert sge.main([arn, "--from-json", "r.json", "--no-save"]) == 0
    assert sge.main(["--from-json", "r.json", "--remove-rule", "bad", "--no-save"]) == 2
    Path("other.json").write_text(json.dumps({"tool": "sg_quota_audit"}))
    assert sge.main(["--from-json", "other.json"]) == 2
    assert sge.main(["--no-save"]) == 2
    assert sge.main(["web-sg", "--no-save"]) == 2
    assert sge.main(["sg-0fff0000ffff00001", "--region", "us-east-1", "-v", "--no-save"]) == 2
    assert sge.main([arn, "--no-save"]) == 0


def test_cli_aws_errors(cli, monkeypatch):
    def throttled(*a, **k):
        raise ClientError({"Error": {"Code": "Throttling", "Message": "slow"}}, "X")
    monkeypatch.setattr(sge, "collect", throttled)
    assert sge.main([F.WEB, "--no-save"]) == 2
