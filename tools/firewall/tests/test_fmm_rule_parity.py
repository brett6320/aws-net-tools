import ipaddress
import json

import pytest
from botocore.exceptions import ClientError

from conftest import load_tool

frp = load_tool("fmm_rule_parity")
N = ipaddress.ip_network


def rule(src=None, dst=None, proto="tcp", dports=None, sports=None, container="sg-1", policy="p1", kind="sg-ingress",
         direction="ingress", action="allow", src_pls=(), dst_pls=(), raw=None):
    return frp.Rule(region="us-east-1", policy_id=policy, policy_name=f"name-{policy}", policy_type="SECURITY_GROUPS_COMMON",
                    container=container, container_name=container, kind=kind, direction=direction, action=action,
                    proto=proto, src_nets=None if src is None else [N(x) for x in src],
                    dst_nets=None if dst is None else [N(x) for x in dst], src_ports=sports, dst_ports=dports,
                    raw=raw or f"{container} {src} {dst} {dports}", src_pls=list(src_pls), dst_pls=list(dst_pls))


def target(label, ip, proto="tcp", port="443", **kw):
    return frp.Target.parse(label, ip, proto, port, **kw)


# --------------------------------------------------------------------------- #
# Helpers and parsing
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("s,r", [("8080", (8080, 8080)), ("8000-8100", (8000, 8100)), (" 8000:8100 ", (8000, 8100)),
                                 ("any", (0, 65535)), ("*", (0, 65535)), ("", (0, 65535))])
def test_parse_port_range(s, r):
    assert frp.parse_port_range(s) == r


def test_parse_port_range_invalid():
    with pytest.raises(ValueError):
        frp.parse_port_range("http")


def test_ports_and_nets():
    assert frp.fmt_ports((0, 65535)) == "any" and frp.fmt_ports((22, 22)) == "22" and frp.fmt_ports((1, 2)) == "1-2"
    assert frp.ports_contain(None, (1, 2))
    assert frp.ports_contain([(1, 10), (20, 30)], (21, 25)) and not frp.ports_contain([(1, 10)], (9, 11))
    assert frp.nets_contain(None, N("10.0.0.0/8"))
    assert frp.nets_contain([N("::/0"), N("10.0.0.0/8")], N("10.1.0.0/16"))
    assert not frp.nets_contain([N("::/0")], N("10.1.0.0/16"))
    assert frp.safe_net(" 10.0.0.1 ") == N("10.0.0.1/32") and frp.safe_net("$HOME_NET") is None
    assert frp.proto_compatible("any", "udp") and frp.proto_compatible("tcp", "any")
    assert not frp.proto_compatible("tcp", "udp")


@pytest.mark.parametrize("tokens,out", [
    (["10.0.0.1", "tcp", "8080"], ("10.0.0.1", "tcp", "8080")),
    (["10.0.0.1 tcp 8080"], ("10.0.0.1", "tcp", "8080")),
    (["10.0.0.1,tcp,8080"], ("10.0.0.1", "tcp", "8080")),
    (["10.0.0.1", "tcp", "port", "8080"], ("10.0.0.1", "tcp", "8080")),
    (["10.0.0.1 over udp"], ("10.0.0.1", "udp", "any")),
    (["10.0.0.1"], ("10.0.0.1", "any", "any")),
])
def test_split_target_tokens(tokens, out):
    assert frp.split_target_tokens(tokens) == out


def test_split_target_tokens_too_many():
    with pytest.raises(ValueError, match="expected 'IP PROTO PORT'"):
        frp.split_target_tokens(["10.0.0.1 tcp 80 extra"])


def test_target_parse_cidr():
    t = target("A", "10.0.0.5/24", "6", "8000-8100")
    assert (t.nets, t.proto, t.ports, t.source, t.match, t.pl_id) == \
        ([N("10.0.0.0/24")], "tcp", (8000, 8100), "10.0.0.0/24", "cidrs-all", None)
    assert str(t) == "10.0.0.0/24 tcp 8000-8100"
    assert target("A", "10.0.0.1", "-1", "any").ports is None


def test_target_parse_prefix_list_modes():
    t = target("A", "PL-0ABC")
    assert (t.pl_id, t.match, t.nets) == ("pl-0abc", "ref", [])
    assert str(t) == "pl-0abc (prefix list, match=ref) tcp 443"
    arn = target("A", "arn:aws:ec2:us-east-1:111122223333:prefix-list/pl-0abc")
    assert arn.pl_id == "pl-0abc"
    t = target("A", "pl-0abc", resolve_pl=lambda pid: [N("10.0.0.0/8"), N("10.1.0.0/16")], pl_match="cidrs-any")
    assert t.match == "cidrs-any" and len(t.nets) == 2
    assert str(t) == "pl-0abc (prefix list, match=cidrs-any, 2 cidrs) tcp 443"
    with pytest.raises(ValueError, match="needs an AWS session"):
        target("A", "pl-0abc", pl_match="cidrs-all")
    with pytest.raises(ValueError, match="could not read"):
        target("A", "pl-0abc", resolve_pl=lambda pid: None, pl_match="cidrs-all")
    with pytest.raises(ValueError, match="no entries"):
        target("A", "pl-0abc", resolve_pl=lambda pid: [], pl_match="cidrs-all")


def test_parse_targets_labels():
    ts = frp.parse_targets("B", [["10.0.0.1 tcp 443"], ["10.0.0.2", "tcp"]], "all", None, "ref")
    assert [t.label for t in ts.targets] == ["B1", "B2"] and ts.mode == "all"
    assert str(ts) == "B1=10.0.0.1/32 tcp 443; B2=10.0.0.2/32 tcp any (match all)"
    assert [t.label for t in frp.parse_targets("A", [["10.0.0.1"]], "any", None, "ref").targets] == ["A"]


# --------------------------------------------------------------------------- #
# Rule.matches
# --------------------------------------------------------------------------- #
def test_matches_roles_and_ports():
    t = target("A", "10.0.0.1", "tcp", "443")
    assert rule(src=["10.0.0.0/24"], dports=[(443, 443)]).matches(t) == ["src"]
    assert rule(src=["10.0.0.0/24"], dst=["10.0.0.0/8"], dports=[(0, 1000)]).matches(t) == ["src", "dst"]
    assert rule(src=["10.0.0.0/24"], dports=[(80, 80)]).matches(t) == []          # port not granted
    assert rule(src=["10.0.0.0/24"], proto="udp").matches(t) == []                # protocol differs
    assert rule(src=["10.0.0.0/24"], proto="any").matches(t) == ["src"]           # port-agnostic rule
    assert rule(src=["10.9.0.0/24"]).matches(t) == []


def test_matches_unconstrained_rule():
    assert rule().matches(target("A", "10.0.0.1")) == ["any"]
    assert rule().matches(target("A", "pl-1")) == []           # an any/any rule never references a prefix list


def test_matches_prefix_list_modes():
    ref = target("A", "pl-1")
    assert rule(src=[], src_pls=["pl-1"]).matches(ref) == ["src"]
    assert rule(src=["10.0.0.0/8"]).matches(ref) == []
    nets = lambda pid: [N("10.0.0.0/16"), N("192.168.0.0/24")]  # noqa: E731
    all_ = target("A", "pl-1", resolve_pl=nets, pl_match="cidrs-all")
    any_ = target("A", "pl-1", resolve_pl=nets, pl_match="cidrs-any")
    r = rule(src=["10.0.0.0/8"])
    assert r.matches(all_) == [] and r.matches(any_) == ["src"]
    assert rule(src=["10.0.0.0/8", "192.168.0.0/16"]).matches(all_) == ["src"]


# --------------------------------------------------------------------------- #
# analyze / reports
# --------------------------------------------------------------------------- #
A = frp.TargetSet("A", [frp.Target.parse("A", "10.0.0.1", "tcp", "443")])
B = frp.TargetSet("B", [frp.Target.parse("B", "10.0.0.2", "tcp", "443")])


def test_analyze_container_scope():
    both = rule(src=["10.0.0.0/24"], dports=[(443, 443)], container="sg-1")
    a_only = rule(src=["10.0.0.1/32"], dports=[(443, 443)], container="sg-2")
    b_elsewhere = rule(src=["10.0.0.2/32"], dports=[(443, 443)], container="sg-3")
    unrelated = rule(src=["172.16.0.0/12"], container="sg-4")
    rules = [both, a_only, b_elsewhere, unrelated]
    findings, stats = frp.analyze(rules, A, B, "container")
    assert [f.rule.container for f in findings] == ["sg-2"]
    f = findings[0]
    assert (f.roles_a, f.a_hits, f.missing_b) == (["src"], {"A": ["src"]}, {"src": ["B"]})
    assert "no sg-ingress ingress allow tcp rule in same container for src: missing B (B mode=any)" in f.reason
    assert stats == {"rules_total": 4, "a_matches": 2, "b_matches": 2, "a_without_b": 1, "b_mode": "any",
                     "a_targets": 1, "b_targets": 1}
    # policy scope: the B rule in sg-3 (same policy, same shape) satisfies it
    assert frp.analyze(rules, A, B, "policy")[0] == []
    # but not when the shape differs (egress rule)
    eg = rule(dst=["10.0.0.2/32"], dports=[(443, 443)], container="sg-3", kind="sg-egress", direction="egress")
    assert len(frp.analyze([a_only, eg], A, B, "policy")[0]) == 1


def test_analyze_b_mode_all():
    b2 = frp.TargetSet("B", [frp.Target.parse("B1", "10.0.0.2", "tcp", "443"),
                             frp.Target.parse("B2", "10.0.0.3", "tcp", "443")], mode="all")
    rules = [rule(src=["10.0.0.1/32", "10.0.0.2/32"], dports=[(443, 443)])]
    [f] = frp.analyze(rules, A, b2, "container")[0]
    assert f.missing_b == {"src": ["B2"]}
    b2.mode = "any"
    assert frp.analyze(rules, A, b2, "container")[0] == []


def test_container_report_and_rows():
    gap_rule = rule(src=["10.0.0.1/32"], dports=[(443, 443)], container="sg-gap", raw="gap rule")
    ok = rule(src=["10.0.0.0/24"], dports=[(443, 443)], container="sg-ok")
    na = rule(src=["172.16.0.0/12"], container="sg-na")
    rules = [na, ok, gap_rule]
    findings, stats = frp.analyze(rules, A, B, "container")
    report = frp.build_container_report(rules, findings, A, B)
    assert [(r["status"], r["container"]) for r in report] == \
        [("NON_COMPLIANT", "sg-gap"), ("COMPLIANT", "sg-ok"), ("NOT_APPLICABLE", "sg-na")]
    assert report[0]["gap_rules"] == ["gap rule"] and report[0]["container_type"] == "SG"
    assert report[1]["a_targets_seen"] == ["A"] and report[1]["b_targets_seen"] == ["B"]
    rows = frp.build_rows(rules, findings, A, B, include_all=False)
    assert [r["container"] for r in rows] == ["sg-gap"] and rows[0]["gap"] is True
    rows = frp.build_rows(rules, findings, A, B, include_all=True)
    assert [(r["container"], r["gap"], r["a_targets"], r["b_targets"]) for r in rows] == \
        [("sg-ok", False, "A:src", "B:src"), ("sg-gap", True, "A:src", "")]
    assert rows[0]["dst_nets"] == "any" and rows[0]["dst_ports"] == "443"
    payload = frp.build_json(rules, findings, stats, A, B, "container", True, ["us-east-1"])
    json.dumps(payload)
    assert len(payload["matching_rules"]) == 2 and payload["targets_a"] == [{"label": "A", "target": "10.0.0.1/32 tcp 443"}]


def test_slug_and_paths():
    import datetime as dt
    assert frp._slug(A) == "10.0.0.1_32_tcp_443"
    many = frp.TargetSet("B", [frp.Target.parse(f"B{i}", f"10.0.0.{i}", "tcp", "443") for i in range(10)])
    s = frp._slug(many)
    assert len(s) == 57 and s == frp._slug(many)
    paths = frp.default_report_paths("out", A, B, dt.datetime(2026, 1, 2, 3, 4, 5))
    assert str(paths["json"]) == "out/fmm_rule_parity/2026-01-02/030405_parity_10.0.0.1_32_tcp_443_vs_10.0.0.2_32_tcp_443.json"
    assert str(paths["report"]).endswith(".compliance.csv") and str(paths["csv"]).endswith(".gaps.csv")


# --------------------------------------------------------------------------- #
# Extractor (fake clients)
# --------------------------------------------------------------------------- #
class Pager:
    def __init__(self, fn):
        self.paginate = fn


class FakeEc2:
    def __init__(self, sgs, pls):
        self.sgs, self.pls = sgs, pls
        self.sg_calls = 0

    def describe_security_groups(self, GroupIds):
        self.sg_calls += 1
        if GroupIds[0] not in self.sgs:
            raise ClientError({"Error": {"Code": "InvalidGroup.NotFound", "Message": "x"}}, "DescribeSecurityGroups")
        return {"SecurityGroups": [self.sgs[GroupIds[0]]]}

    def get_paginator(self, op):
        def entries(PrefixListId):
            if PrefixListId not in self.pls:
                raise ClientError({"Error": {"Code": "AccessDenied", "Message": "x"}}, op)
            return [{"Entries": [{"Cidr": c} for c in self.pls[PrefixListId]]}]
        return Pager(entries)


class FakeNfw:
    def __init__(self, groups):
        self.groups = groups

    def describe_rule_group(self, RuleGroupArn):
        return self.groups[RuleGroupArn]


class FakeSession:
    def __init__(self, **clients):
        self.clients = {"fms": object(), **clients}

    def client(self, service, config=None):
        return self.clients[service]


def policy(ptype, msd, pid="p1"):
    return {"PolicyId": pid, "PolicyName": f"name-{pid}",
            "SecurityServicePolicyData": {"Type": ptype, "ManagedServiceData": json.dumps(msd)}}


def test_extract_security_group_policy():
    sg = {"GroupId": "sg-1", "GroupName": "web", "IpPermissions": [
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "10.0.0.0/8"}, {"CidrIp": "junk"}],
         "Ipv6Ranges": [{"CidrIpv6": "2001:db8::/32"}], "PrefixListIds": [{"PrefixListId": "pl-ok"}]},
        {"IpProtocol": "-1", "PrefixListIds": [{"PrefixListId": "pl-denied"}], "UserIdGroupPairs": [{"GroupId": "sg-2"}]},
        {"IpProtocol": "udp", "FromPort": 53, "ToPort": 53},     # no peers: skipped
    ], "IpPermissionsEgress": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}
    ec2 = FakeEc2({"sg-1": sg}, {"pl-ok": ["192.168.0.0/24", "not-a-cidr"]})
    ex = frp.Extractor(FakeSession(ec2=ec2), "us-east-1")
    msd = {"securityGroups": [{"id": "sg-1"}, {"id": "sg-1"}, {"id": "sg-missing"}]}
    rules = list(ex.rules_for_policy(policy("SECURITY_GROUPS_COMMON", msd)))
    assert ec2.sg_calls == 2                                       # sg-1 cached
    first = [r for r in rules][:5]
    assert [r.raw for r in first] == [
        "sg-1 ingress tcp 443 10.0.0.0/8", "sg-1 ingress tcp 443 2001:db8::/32", "sg-1 ingress tcp 443 pl-ok(1 cidrs)",
        "sg-1 ingress any any pl-denied,sg-2", "sg-1 egress any any 0.0.0.0/0"]
    assert first[0].unresolved == [] and first[0].dst_ports == [(443, 443)] and first[0].src_nets == [N("10.0.0.0/8")]
    assert first[2].src_pls == ["pl-ok"]
    assert (first[3].src_nets, first[3].src_pls, first[3].unresolved) == ([], ["pl-denied"], ["pl-denied", "sg-2"])
    assert first[4].dst_nets == [N("0.0.0.0/0")] and first[4].src_nets is None and first[4].kind == "sg-egress"
    assert len(rules) == 10                                        # second reference repeats sg-1


def test_extract_nacl_policy():
    msd = {"networkAclEntrySet": {
        "firstEntries": [{"egress": False, "protocol": "6", "portRange": {"from": 22, "to": 22},
                          "cidrBlock": "10.0.0.0/8", "ruleAction": "deny"}],
        "lastEntries": [{"egress": True, "protocol": "-1", "ipv6CidrBlock": "::/0", "ruleAction": "allow"},
                        {"egress": False, "protocol": "17", "cidrBlock": "bogus", "ruleAction": "allow"}]}}
    ex = frp.Extractor(FakeSession(), "us-east-1")
    rules = list(ex.rules_for_policy(policy("NETWORK_ACL_COMMON", msd)))
    assert [r.raw for r in rules] == ["entry[0] ingress deny tcp 22 10.0.0.0/8", "entry[0] egress allow any any ::/0",
                                      "entry[1] ingress allow udp any bogus"]
    assert rules[0].container == "networkAclEntrySet.firstEntries" and rules[0].action == "deny"
    assert rules[1].dst_nets == [N("::/0")] and rules[1].src_nets is None
    assert rules[2].unresolved == ["bogus"] and rules[2].src_nets == []


def test_extract_unsupported_and_bad_json():
    ex = frp.Extractor(FakeSession(), "us-east-1")
    assert list(ex.rules_for_policy(policy("WAFV2", {}))) == []
    bad = policy("NETWORK_ACL_COMMON", {})
    bad["SecurityServicePolicyData"]["ManagedServiceData"] = "{not json"
    assert list(ex.rules_for_policy(bad)) == []


def test_extract_network_firewall_policy():
    ref_arn = "arn:aws:ec2:us-east-1:111122223333:prefix-list/pl-corp"
    stateful = {
        "RuleGroupResponse": {"Type": "STATEFUL", "RuleGroupName": "sf"},
        "RuleGroup": {
            "RuleVariables": {"IPSets": {"HOME": {"Definition": ["10.0.0.0/8"]}},
                              "PortSets": {"WEB": {"Definition": ["80", "443"]}}},
            "ReferenceSets": {"IPSetReferences": {"CORP": {"ReferenceArn": ref_arn}}},
            "RulesSource": {
                "StatefulRules": [{"Action": "PASS", "Header": {
                    "Protocol": "TCP", "Source": "$HOME", "SourcePort": "ANY", "Direction": "FORWARD",
                    "Destination": "$CORP", "DestinationPort": "$WEB"}}],
                "RulesString": "# comment\n\n"
                               "pass tcp [10.1.0.0/16, !10.1.2.0/24] any -> any [8000:8100,$WEB,$NOPE] (sid:1;)\n"
                               "drop udp $UNKNOWN any <> 192.168.0.0/16 53 (sid:2;)\n"
                               "this is not suricata\n",
            }}}
    stateless = {
        "RuleGroupResponse": {"Type": "STATELESS", "RuleGroupName": "sl"},
        "RuleGroup": {"RulesSource": {"StatelessRulesAndCustomActions": {"StatelessRules": [
            {"Priority": 1, "RuleDefinition": {"Actions": ["aws:drop"], "MatchAttributes": {
                "Sources": [{"AddressDefinition": "10.0.0.0/8"}], "DestinationPorts": [{"FromPort": 22, "ToPort": 22}],
                "Protocols": [6, 17]}}}]}}}}
    nfw = FakeNfw({"arn:sf": stateful, "arn:sl": stateless})
    ec2 = FakeEc2({}, {"pl-corp": ["172.16.0.0/12"]})
    ex = frp.Extractor(FakeSession(ec2=ec2, **{"network-firewall": nfw}), "us-east-1")
    msd = {"networkFirewallStatelessRuleGroupReferences": [{"resourceARN": "arn:sl"}],
           "networkFirewallStatefulRuleGroupReferences": [{"resourceARN": "arn:sf"}]}
    rules = list(ex.rules_for_policy(policy("NETWORK_FIREWALL", msd)))
    assert [(r.kind, r.proto, r.container_name) for r in rules] == [
        ("nfw-stateless", "tcp", "sl"), ("nfw-stateless", "udp", "sl"),
        ("nfw-stateful", "tcp", "sf"), ("nfw-stateful", "tcp", "sf"), ("nfw-stateful", "udp", "sf")]
    sl = rules[0]
    assert (sl.src_nets, sl.dst_nets, sl.dst_ports, sl.action) == ([N("10.0.0.0/8")], None, [(22, 22)], "aws:drop")
    hdr = rules[2]
    assert (hdr.src_nets, hdr.dst_nets, hdr.dst_pls, hdr.dst_ports, hdr.src_ports, hdr.action, hdr.direction) == \
        ([N("10.0.0.0/8")], [N("172.16.0.0/12")], ["pl-corp"], [(80, 80), (443, 443)], None, "pass", "forward")
    sur = rules[3]
    assert sur.src_nets == [N("10.1.0.0/16")] and sur.dst_nets is None
    assert sur.dst_ports == [(8000, 8100), (80, 80), (443, 443)]
    assert sur.unresolved == ["!10.1.2.0/24", "$NOPE"]
    assert sur.raw.startswith("suricata L3: pass tcp")
    drop = rules[4]
    assert (drop.action, drop.direction, drop.src_nets, drop.unresolved, drop.dst_ports) == \
        ("drop", "any", [], ["$UNKNOWN"], [(53, 53)])
    # the PL reference target matches the stateful header rule by id
    assert hdr.matches(frp.Target.parse("A", "pl-corp", "tcp", "443")) == ["dst"]


def test_collect_rules_with_fake_fms(monkeypatch):
    class FakeFms:
        def get_paginator(self, op):
            return Pager(lambda: [{"PolicyList": [
                {"PolicyId": "p1", "PolicyName": "nacl", "SecurityServiceType": "NETWORK_ACL_COMMON"},
                {"PolicyId": "p2", "PolicyName": "waf", "SecurityServiceType": "WAFV2"},
                {"PolicyId": "p3", "PolicyName": "broken", "SecurityServiceType": "NETWORK_ACL_COMMON"}]}])

        def get_policy(self, PolicyId):
            if PolicyId == "p3":
                raise ClientError({"Error": {"Code": "ResourceNotFound", "Message": "x"}}, "GetPolicy")
            return {"Policy": policy("NETWORK_ACL_COMMON", {"networkAclEntrySet": {"firstEntries": [
                {"egress": False, "protocol": "-1", "cidrBlock": "10.0.0.0/8", "ruleAction": "allow"}]}}, PolicyId)}

    monkeypatch.setattr(frp, "get_session", lambda profile, region: FakeSession(fms=FakeFms()))
    rules = frp.collect_rules(None, ["us-east-1", "eu-west-1"], None)
    assert [(r.region, r.policy_id) for r in rules] == [("us-east-1", "p1"), ("eu-west-1", "p1")]
    assert frp.collect_rules(None, ["us-east-1"], "other") == []


def test_main_fake_fms(monkeypatch, capsys, tmp_path):
    from conftest import run_main

    class FakeFms:
        def get_paginator(self, op):
            return Pager(lambda: [{"PolicyList": [
                {"PolicyId": "p1", "PolicyName": "sg-pol", "SecurityServiceType": "SECURITY_GROUPS_COMMON"}]}])

        def get_policy(self, PolicyId):
            return {"Policy": policy("SECURITY_GROUPS_COMMON", {"securityGroups": [{"id": "sg-a"}, {"id": "sg-b"}]})}

    perm = lambda *cidrs: {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,  # noqa: E731
                           "IpRanges": [{"CidrIp": c} for c in cidrs]}
    ec2 = FakeEc2({"sg-a": {"GroupId": "sg-a", "GroupName": "a", "IpPermissions": [perm("10.0.0.1/32")]},
                   "sg-b": {"GroupId": "sg-b", "GroupName": "b", "IpPermissions": [perm("10.0.0.1/32", "10.0.0.2/32")]}},
                  {"pl-b": ["10.0.0.2/32"]})
    monkeypatch.setattr(frp, "get_session", lambda profile, region: FakeSession(fms=FakeFms(), ec2=ec2))
    rc = run_main(frp, monkeypatch, ["-a", "10.0.0.1", "tcp", "443", "-b", "pl-b tcp 443", "--pl-match", "cidrs-all",
                                     "--region", "us-east-1", "--out-dir", str(tmp_path / "rep"), "--json", "-q"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert [f["rule"]["container"] for f in out["findings"]] == ["sg-a"]
    assert [(c["container"], c["status"]) for c in out["containers"]] == [("sg-a", "NON_COMPLIANT"), ("sg-b", "COMPLIANT")]
    written = sorted(p.name.split("parity_")[1] for p in (tmp_path / "rep" / "fmm_rule_parity").glob("*/*"))
    assert written == [f"10.0.0.1_32_tcp_443_vs_pl-b_tcp_443.{ext}" for ext in ("compliance.csv", "gaps.csv", "html", "json")]

    assert run_main(frp, monkeypatch, ["-a", "10.0.0.2", "tcp", "443", "-b", "10.0.0.1", "tcp", "443",
                                       "--no-save", "--show-all", "--all-containers"]) == 0
    assert "sg-b" in capsys.readouterr().out
    with pytest.raises(SystemExit):        # prefix list CIDRs could not be read
        run_main(frp, monkeypatch, ["-a", "pl-missing", "tcp", "443", "-b", "10.0.0.1", "--pl-match", "cidrs-any",
                                    "--no-save"])
