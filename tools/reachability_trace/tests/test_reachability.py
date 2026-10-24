import json
import logging
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import ra_accounts as accounts  # noqa: E402
import ra_core as core  # noqa: E402
import reachability  # noqa: E402
from ra_export import render_html  # noqa: E402
from ra_icons import classify  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


def load(name):
    return json.loads((FIXTURES / name).read_text())


# ---------- validation / request building ----------

@pytest.mark.parametrize("ref,kind", [
    ("i-0123456789abcdef0", "instance"),
    ("igw-0123", "internet-gateway"),
    ("eni-0123", "network-interface"),
    ("tgw-0123", "transit-gateway"),
    ("tgw-attach-0123", "transit-gateway-attachment"),
    ("vgw-0123", "vpn-gateway"),
    ("vpce-svc-0123", "vpc-endpoint-service"),
    ("vpce-0123", "vpc-endpoint"),
    ("pcx-0123", "vpc-peering-connection"),
    ("arn:aws:ec2:us-east-1:111122223333:instance/i-0123", "instance"),
    ("arn:aws:ec2:us-east-1:111122223333:transit-gateway-attachment/tgw-attach-0123", "transit-gateway-attachment"),
    ("arn:aws:ec2:us-east-1:111122223333:vpc-endpoint-service/vpce-svc-0123", "vpc-endpoint-service"),
])
def test_classify_endpoint_supported(ref, kind):
    assert core.classify_endpoint(ref) == kind


@pytest.mark.parametrize("ref", ["sg-0123", "subnet-0123", "nat-0123", "arn:aws:ec2:us-east-1:1:security-group/sg-1"])
def test_classify_endpoint_rejects_unsupported(ref):
    with pytest.raises(core.ValidationError):
        core.classify_endpoint(ref)


def test_ports_and_source_ip_go_into_filter_at_source():
    spec = core.PathSpec(source="i-aaa", destination="i-bbb", protocol="tcp", source_ip="10.0.1.5",
                         source_ports=core.parse_port_range("1024-65535"),
                         destination_ports=core.parse_port_range("443"), name="web")
    req = core.build_create_path_request(spec)
    assert req["FilterAtSource"] == {
        "SourceAddress": "10.0.1.5",
        "SourcePortRange": {"FromPort": 1024, "ToPort": 65535},
        "DestinationPortRange": {"FromPort": 443, "ToPort": 443},
    }
    # API forbids these alongside FilterAtSource
    assert "SourceIp" not in req and "DestinationPort" not in req
    assert "FilterAtDestination" not in req
    assert req["TagSpecifications"][0]["Tags"] == [{"Key": "Name", "Value": "web"}]


def test_ip_only_destination():
    req = core.build_create_path_request(core.PathSpec(source="i-aaa", destination_ip="8.8.8.8", protocol="udp",
                                                       destination_ports=core.PortRange(53, 53)))
    assert req["DestinationIp"] == "8.8.8.8" and "Destination" not in req
    assert req["FilterAtSource"] == {"DestinationPortRange": {"FromPort": 53, "ToPort": 53}}


def test_no_filter_when_no_ports_or_ip():
    req = core.build_create_path_request(core.PathSpec(source="i-aaa", destination="i-bbb", protocol="tcp"))
    assert "FilterAtSource" not in req


@pytest.mark.parametrize("bad", [
    dict(source="i-a", protocol="tcp"),                                  # no destination
    dict(source="i-a", destination="i-b", protocol="icmp"),
    dict(source="i-a", destination_ip="2001:db8::1", protocol="tcp"),    # IPv6
    dict(source="i-a", destination="i-b", protocol="tcp", source_ip="nope"),
])
def test_invalid_specs(bad):
    with pytest.raises(core.ValidationError):
        core.build_create_path_request(core.PathSpec(**bad))


@pytest.mark.parametrize("val,exp", [("443", (443, 443)), ("1024-65535", (1024, 65535)), ("0", (0, 0))])
def test_parse_port_range(val, exp):
    pr = core.parse_port_range(val)
    assert (pr.from_port, pr.to_port) == exp


@pytest.mark.parametrize("val", ["70000", "10-5", "abc", "1-2-3", "-1"])
def test_parse_port_range_invalid(val):
    with pytest.raises(core.ValidationError):
        core.parse_port_range(val)


def test_start_analysis_request():
    arn = "arn:aws:ec2:us-east-1:111122223333:transit-gateway/tgw-1"
    req = core.build_start_analysis_request("nip-1", filter_in=[arn], additional_accounts=["444455556666"],
                                            name="x")
    assert req["FilterInArns"] == [arn] and req["AdditionalAccounts"] == ["444455556666"]
    with pytest.raises(core.ValidationError):
        core.build_start_analysis_request("nip-1", filter_in=["tgw-1"])
    with pytest.raises(core.ValidationError):
        core.build_start_analysis_request("nip-1", filter_in=[arn], filter_out=[arn])


def test_create_dry_run_makes_no_api_calls(monkeypatch, caplog):
    def boom(*a, **k):
        raise AssertionError("API session must not be created in dry-run")
    caplog.set_level(logging.INFO)
    monkeypatch.setattr(core, "get_session", boom)
    rc = reachability.main(["create", "-s", "i-aaa", "-d", "i-bbb", "--dest-port", "443", "--profile", "p"])
    assert rc == 0
    assert "[DRY-RUN] Would call CreateNetworkInsightsPath" in caplog.text


# ---------- icons ----------

@pytest.mark.parametrize("ident,arn,kind,sub", [
    ("tgw-attach-1", None, "transit-gateway-attachment", None),
    ("tgw-rtb-1", None, "transit-gateway-route-table", None),
    ("acl-1", None, "network-acl", None),
    (None, "arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/net/x/1", "load-balancer", "NLB"),
    (None, "arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/app/x/1", "load-balancer", "ALB"),
    (None, "arn:aws:elasticloadbalancing:us-east-1:1:targetgroup/x/1", "target-group", None),
    (None, "arn:aws:network-firewall:us-east-1:1:firewall/fw", "network-firewall", None),
    ("weird", None, "unknown", None),
])
def test_icon_classify(ident, arn, kind, sub):
    assert classify(ident, arn) == (kind, sub)


# ---------- HTML export ----------

def test_export_reachable_is_self_contained():
    html = render_html([load("reachable.json")])
    assert "Reachable" in html and "Not reachable" not in html
    # no external resources
    assert not re.search(r'(src|href)="(https?:)?//', html)
    assert "<link" not in html and "<script src" not in html  # only the inline theme toggle script
    # every forward/return component rendered with an icon and anchor
    for seq in range(1, 10):
        assert f'id="nia-0fedcba9876543210-fwd-{seq}"' in html
    for seq in range(1, 6):
        assert f'id="nia-0fedcba9876543210-ret-{seq}"' in html
    assert html.count("<svg") > 20
    # rule details from the source-side filter carried through
    assert "5432" in html and "1024-65535" in html and "Rule number" in html


def test_export_not_reachable_shows_explanations():
    html = render_html([load("not_reachable.json")])
    assert "Not reachable" in html
    assert "SUBNET_ACL_RESTRICTION" in html and "NO_ROUTE_TO_DESTINATION" in html
    assert "must be admitted by the network ACL" in html
    assert "Alternate path hints" in html and "444455556666" in html
    # no hops returned: source -> blocking components -> break -> unreached destination
    assert "Forward path" in html and "0 components returned before the block" in html
    assert html.count('class="node blocked"') == 2  # the ACL and the route table
    assert 'class="link broken"' in html and 'class="node unreached"' in html


def test_export_escapes_values():
    b = load("reachable.json")
    b["path"]["Tags"] = [{"Key": "Name", "Value": "<script>alert(1)</script>"}]
    html = render_html([b])
    assert "<script>alert(1)" not in html and "&lt;script&gt;" in html


def test_export_excludes_profile(tmp_path, monkeypatch):
    out = tmp_path / "x.html"
    rc = reachability.main(["export", "--from-json", str(FIXTURES / "igw_nlb.json"), "-o", str(out),
                            "--profile", "super-secret-profile"])
    assert rc == 0
    html = out.read_text()
    assert "super-secret-profile" not in html
    assert "Network Load Balancer" in html and "REMAP_EPHEMERAL_PORT" in html


def test_export_multiple_has_toc(tmp_path):
    out = tmp_path / "multi.html"
    rc = reachability.main(["export", "--from-json", str(FIXTURES / "reachable.json"),
                            "--from-json", str(FIXTURES / "not_reachable.json"), "-o", str(out)])
    assert rc == 0
    assert 'class="toc"' in out.read_text()


# ---------- default reports folder ----------

def test_report_path_by_date_and_account():
    p = core.report_path(load("reachable.json"), "reports")
    assert p == Path("reports/2026-10-23/111122223333/app-to-db-5432_nia-0fedcba9876543210.html")


def test_report_path_prefers_analysis_name_and_handles_missing_data():
    b = load("not_reachable.json")
    assert core.report_path(b, "r").name == "tgw-check_nia-0bad000000000bad1.html"
    b = {"path": {}, "analysis": {"NetworkInsightsAnalysisId": "nia-1", "Tags": [{"Key": "Name", "Value": "a/b c"}]}}
    p = core.report_path(b, "r")
    assert p.parent.name == "unknown-account" and p.name == "a-b-c_nia-1.html"


def test_export_defaults_to_reports_folder(tmp_path):
    rc = reachability.main(["export", "--from-json", str(FIXTURES / "reachable.json"),
                            "--from-json", str(FIXTURES / "igw_nlb.json"), "--reports-dir", str(tmp_path)])
    assert rc == 0
    files = sorted(str(f.relative_to(tmp_path)) for f in tmp_path.rglob("*.html"))
    assert files == ["2026-10-23/111122223333/app-to-db-5432_nia-0fedcba9876543210.html",
                     "2026-10-23/111122223333/nia-0ccc000000000ccc3.html"]


def test_export_output_flag_writes_single_file(tmp_path):
    out = tmp_path / "one.html"
    rc = reachability.main(["export", "--from-json", str(FIXTURES / "reachable.json"), "-o", str(out),
                            "--reports-dir", str(tmp_path / "reports")])
    assert rc == 0 and out.exists() and not (tmp_path / "reports").exists()


def _finish_args(tmp_path, **kw):
    args = reachability.build_parser().parse_args(["analyze", "nip-1", "--reports-dir", str(tmp_path)])
    for k, v in kw.items():
        setattr(args, k, v)
    return args


def test_finish_waits_and_writes_report_by_default(tmp_path, monkeypatch):
    b = load("reachable.json")
    monkeypatch.setattr(core, "wait_for_analysis", lambda ec2, aid, timeout: b["analysis"])
    rc = reachability._finish(None, _finish_args(tmp_path), b["path"], {"NetworkInsightsAnalysisId": "x"})
    assert rc == 0
    assert (tmp_path / "2026-10-23/111122223333/app-to-db-5432_nia-0fedcba9876543210.html").exists()


def test_finish_no_report_returns_without_waiting(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("must not wait")
    monkeypatch.setattr(core, "wait_for_analysis", boom)
    rc = reachability._finish(None, _finish_args(tmp_path, no_report=True), {}, {"NetworkInsightsAnalysisId": "x"})
    assert rc == 0 and not list(tmp_path.rglob("*.html"))


def test_dry_run_mentions_report_location(caplog):
    caplog.set_level(logging.INFO)
    assert reachability.main(["create", "-s", "i-aaa", "-d", "i-bbb", "--reports-dir", "out"]) == 0
    assert "out/<date>/<account>/<analysis>.html" in caplog.text


# ---------- theme ----------

def test_dark_is_default_theme():
    html = render_html([load("reachable.json")])
    assert '<html lang="en" data-theme="dark">' in html
    assert ":root{--bg:#0f1419" in html  # dark tokens on bare :root


@pytest.mark.parametrize("theme", ["light", "auto"])
def test_theme_option(tmp_path, theme):
    out = tmp_path / "t.html"
    assert reachability.main(["export", "--from-json", str(FIXTURES / "reachable.json"), "-o", str(out),
                              "--theme", theme]) == 0
    assert f'data-theme="{theme}"' in out.read_text()


def test_invalid_theme_rejected():
    with pytest.raises(ValueError):
        render_html([load("reachable.json")], theme="neon")


# ---------- cross-account ----------

def test_arn_account():
    assert accounts.arn_account("arn:aws:ec2:us-east-1:444455556666:instance/i-1") == "444455556666"
    assert accounts.arn_account("i-1") is None
    assert accounts.arn_account("arn:aws:s3:::bucket") is None


def test_account_summary_cross_account():
    b = load("cross_account.json")
    acc = accounts.account_summary(b["path"], b["analysis"])
    assert acc["cross_account"]
    assert (acc["owner"], acc["source"], acc["destination"]) == ("111122223333", "111122223333", "444455556666")
    assert list(acc["accounts"]) == ["111122223333", "444455556666", "222233334444"]
    net = acc["accounts"]["222233334444"]
    assert net["roles"] == ["Additional (requested)"] and (net["forward"], net["return"]) == (3, 3)
    assert acc["accounts"]["111122223333"]["roles"] == ["Analysis owner", "Source"]


def test_account_summary_single_account():
    b = load("reachable.json")
    assert not accounts.account_summary(b["path"], b["analysis"])["cross_account"]
    # requested/suggested-only accounts don't make a path cross-account
    b = load("not_reachable.json")
    acc = accounts.account_summary(b["path"], b["analysis"])
    assert not acc["cross_account"]
    assert "Suggested by AWS" in acc["accounts"]["444455556666"]["roles"]


def test_related_accounts_excludes_owner():
    p = load("cross_account.json")["path"]
    extra = ["arn:aws:ec2:us-east-1:222233334444:transit-gateway/tgw-1",
             "arn:aws:ec2:us-east-1:111122223333:transit-gateway/tgw-2"]
    assert accounts.related_accounts(p, extra) == ["444455556666", "222233334444"]


def test_export_cross_account_rendering():
    html = render_html([load("cross_account.json")])
    assert "Cross-account" in html and "<h3>Accounts" in html
    # boundaries: app->network and network->data on forward; data->network and network->app on return
    assert html.count('class="link xacct"') == 4
    assert html.count('class="nacct"') == 12 + 8
    assert "Path owner account" in html


def test_export_single_account_has_no_boundaries():
    html = render_html([load("reachable.json")])
    assert "xacct" not in html.split("</style>")[1] and "⇄ Cross-account" not in html


def test_export_suggested_accounts_note():
    html = render_html([load("not_reachable.json")])
    assert "--additional-account 444455556666" in html


class _FakeArgs:
    no_auto_accounts = False
    filter_in = ["arn:aws:ec2:us-east-1:222233334444:transit-gateway/tgw-1"]
    filter_out = None


def test_auto_accounts_added_to_request(caplog):
    caplog.set_level(logging.INFO)
    p = load("cross_account.json")["path"]
    req = {"NetworkInsightsPathId": "nip-1", "AdditionalAccounts": ["444455556666"]}
    reachability._auto_accounts(_FakeArgs(), p, req)
    assert req["AdditionalAccounts"] == ["444455556666", "222233334444"]
    args = _FakeArgs()
    args.no_auto_accounts = True
    req = {"NetworkInsightsPathId": "nip-1"}
    reachability._auto_accounts(args, p, req)
    assert "AdditionalAccounts" not in req


def test_suggested_accounts_warning(caplog):
    reachability._warn_suggested_accounts({"SuggestedAccounts": ["444455556666", "555"],
                                           "AdditionalAccounts": ["555"]})
    assert "--additional-account 444455556666" in caplog.text and "--additional-account 555" not in caplog.text


def test_summary_shows_accounts(capsys):
    reachability.print_summary(load("cross_account.json"))
    out = capsys.readouterr().out
    assert "[CROSS-ACCOUNT]" in out and "<222233334444>" in out


# ---------- breakpoints ----------

def _flow(html, title):
    card = html.split(f"<h3>{title}")[1]
    return card.split('<div class="flow">')[1].split("</div>")[0]


def test_breakpoint_partial_path_shows_all_hops_and_break():
    b = load("blocked_midpath.json")
    html = render_html([b])
    flow = _flow(html, "Forward path")
    # every returned hop is drawn, in order, as a link to its details card
    for seq in range(1, 7):
        assert f'href="#nia-0b10c4ed00000000a-fwd-{seq}"' in flow
    # then the blocking SG (not among the hops), the break marker, and the unreached destination
    tail = flow.split('href="#nia-0b10c4ed00000000a-fwd-6"')[1]
    first_break = tail.index('class="link broken"')
    second_break = tail.index('class="link broken"', first_break + 1)
    assert first_break < tail.index("sg-0db000000000000b2") < second_break < tail.index("node unreached")
    assert "ENI_SG_RULES_MISMATCH" in tail and "Destination — not reached" in tail
    assert flow.count('class="link broken"') == 2
    # banner names the last hop and the blocker
    assert "Path blocked on the forward path after hop 6" in html and 'class="breakbanner"' in html
    assert "Blocked at" in html
    # component detail cards still rendered for every hop
    for seq in range(1, 7):
        assert f'id="nia-0b10c4ed00000000a-fwd-{seq}"' in html


def test_breakpoint_on_a_returned_hop_marks_that_node():
    b = load("blocked_midpath.json")
    acl = b["analysis"]["ForwardPathComponents"][-1]["Component"]
    b["analysis"]["Explanations"] = [{"Component": acl, "Acl": acl, "ExplanationCode": "SUBNET_ACL_RESTRICTION"}]
    html = render_html([b])
    flow = _flow(html, "Forward path")
    assert flow.count('class="node blocked"') == 1 and "acl-0b0000000000000b2" in flow.split('class="node blocked"')[1]
    assert "BLOCKING" in html and "at hop 6" in html
    # blocker is in the path, so the break goes straight to the unreached destination
    assert flow.count('class="link broken"') == 1


def test_context_fields_are_not_marked_blocking():
    b = load("blocked_midpath.json")
    # explanation lists the source ENI/subnet as context only; the SG is the blocker
    html = render_html([b])
    flow = _flow(html, "Forward path")
    eni = flow.split('href="#nia-0b10c4ed00000000a-fwd-2"')[0].rsplit("<a ", 1)[1]
    assert "blocked" not in eni


def test_break_on_return_path():
    b = load("reachable.json")
    a = b["analysis"]
    a["NetworkPathFound"] = False
    a["ReturnPathComponents"] = a["ReturnPathComponents"][:2]
    acl = {"Id": "acl-0a0000000000000a1", "Arn": "arn:aws:ec2:us-east-1:111122223333:network-acl/acl-0a0000000000000a1"}
    a["Explanations"] = [{"Component": acl, "ExplanationCode": "SUBNET_ACL_RESTRICTION", "Direction": "ingress"}]
    html = render_html([b])
    assert "Path blocked on the return path after hop 2" in html
    assert "Source — reply not reached" in _flow(html, "Return path")
    assert 'link broken' not in _flow(html, "Forward path")


def test_reachable_path_has_no_break():
    html = render_html([load("reachable.json")])
    body = html.split("</style>")[1]
    assert "link broken" not in body and "breakbanner" not in body and "node unreached" not in body


def test_summary_marks_breakpoint(capsys):
    reachability.print_summary(load("blocked_midpath.json"))
    out = capsys.readouterr().out
    assert "BLOCKED at sg-0db000000000000b2 (ENI_SG_RULES_MISMATCH)" in out
    assert "path stops after hop 6" in out


# ---------- review fixes ----------

def test_unparseable_timestamp_is_escaped():
    b = load("reachable.json")
    b["path"]["CreatedDate"] = "<img src=x onerror=alert(1)>"
    html = render_html([b])
    assert "<img src=x" not in html and "&lt;img src=x" in html


def test_blocker_without_code_still_marked():
    b = load("blocked_midpath.json")
    acl = b["analysis"]["ForwardPathComponents"][-1]["Component"]
    b["analysis"]["Explanations"] = [{"Component": acl}]
    html = render_html([b])
    assert "⛔ BLOCKING" in html and 'class="node blocked"' in html


def test_summary_tolerates_missing_status(capsys):
    b = load("reachable.json")
    del b["analysis"]["Status"]
    reachability.print_summary(b)
    assert "Status: unknown" in capsys.readouterr().out


@pytest.mark.parametrize("tag", ["novalue", "=x"])
def test_bad_tag_rejected(tag, caplog):
    assert reachability.main(["create", "-s", "i-a", "-d", "i-b", "--tag", tag]) == 1
    assert "use KEY=VALUE" in caplog.text


# ---------- export by path ID ----------

def _fake_api(monkeypatch, bundle, analyses):
    """Point export at canned path/analysis data instead of the EC2 API."""
    by_id = {a["NetworkInsightsAnalysisId"]: a for a in analyses}
    monkeypatch.setattr(reachability, "_ec2", lambda args: object())
    monkeypatch.setattr(core, "iter_analyses", lambda ec2, pid=None: iter(analyses))
    monkeypatch.setattr(core, "get_path", lambda ec2, pid: bundle["path"])
    monkeypatch.setattr(core, "get_analysis", lambda ec2, aid: by_id[aid])


def _three_analyses(bundle):
    base = bundle["analysis"]
    return [dict(base, NetworkInsightsAnalysisId=f"nia-{n}", StartDate=f"2026-10-{d}T10:00:00+00:00")
            for n, d in (("old", "20"), ("new", "23"), ("mid", "21"))]


def test_export_path_id_non_interactive_uses_latest(tmp_path, monkeypatch, caplog):
    bundle = load("reachable.json")
    _fake_api(monkeypatch, bundle, _three_analyses(bundle))
    monkeypatch.setattr(reachability, "_interactive", lambda: False)
    caplog.set_level(logging.INFO)
    out = tmp_path / "r.html"
    pid = bundle["path"]["NetworkInsightsPathId"]
    assert reachability.main(["export", pid, "-o", str(out), "--region", "us-east-1"]) == 0
    html = out.read_text()
    assert "nia-new" in html and "nia-old" not in html
    assert "using the most recent, nia-new" in caplog.text


def test_export_path_id_prompt_lists_newest_first(tmp_path, monkeypatch, capsys):
    bundle = load("reachable.json")
    _fake_api(monkeypatch, bundle, _three_analyses(bundle))
    monkeypatch.setattr(reachability, "_interactive", lambda: True)
    answers = iter(["9", "x", "3"])
    monkeypatch.setattr("builtins.input", lambda: next(answers))
    out = tmp_path / "r.html"
    pid = bundle["path"]["NetworkInsightsPathId"]
    assert reachability.main(["export", pid, "-o", str(out), "--region", "us-east-1"]) == 0
    err = capsys.readouterr().err
    assert err.index("1) nia-new") < err.index("2) nia-mid") < err.index("3) nia-old")
    assert "nia-new" in err.split("\n")[1] and "(default)" in err.split("\n")[1]
    assert err.count("Enter a number from 1 to 3") == 2
    assert "nia-old" in out.read_text()


def test_export_path_id_enter_picks_default(tmp_path, monkeypatch):
    bundle = load("reachable.json")
    _fake_api(monkeypatch, bundle, _three_analyses(bundle))
    monkeypatch.setattr(reachability, "_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda: "")
    out = tmp_path / "r.html"
    assert reachability.main(["export", bundle["path"]["NetworkInsightsPathId"], "-o", str(out),
                              "--region", "us-east-1"]) == 0
    assert "nia-new" in out.read_text()


def test_export_path_id_latest_flag_skips_prompt(tmp_path, monkeypatch):
    bundle = load("reachable.json")
    _fake_api(monkeypatch, bundle, _three_analyses(bundle))
    monkeypatch.setattr(reachability, "_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda: pytest.fail("prompted despite --latest"))
    out = tmp_path / "r.html"
    assert reachability.main(["export", bundle["path"]["NetworkInsightsPathId"], "--latest", "-o", str(out),
                              "--region", "us-east-1"]) == 0
    assert "nia-new" in out.read_text()


def test_export_path_id_single_analysis_no_prompt(tmp_path, monkeypatch):
    bundle = load("reachable.json")
    _fake_api(monkeypatch, bundle, [bundle["analysis"]])
    monkeypatch.setattr(reachability, "_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda: pytest.fail("prompted for a single analysis"))
    out = tmp_path / "r.html"
    assert reachability.main(["export", bundle["path"]["NetworkInsightsPathId"], "-o", str(out),
                              "--region", "us-east-1"]) == 0
    assert bundle["analysis"]["NetworkInsightsAnalysisId"] in out.read_text()


def test_export_path_id_without_analyses_writes_path_only(tmp_path, monkeypatch):
    bundle = load("reachable.json")
    _fake_api(monkeypatch, bundle, [])
    pid = bundle["path"]["NetworkInsightsPathId"]
    assert reachability.main(["export", pid, "--reports-dir", str(tmp_path), "--region", "us-east-1"]) == 0
    files = list(tmp_path.rglob("*.html"))
    assert len(files) == 1
    # Filed under the path's creation date and owner account, named by path ID.
    rel = files[0].relative_to(tmp_path).parts
    assert rel[0] == "2026-10-23" and rel[1] == "111122223333" and rel[2].endswith(f"{pid}.html")
    html = files[0].read_text()
    assert "No analysis" in html and f"analyze --apply {pid}" in html
    assert "Forward path" not in html


def test_export_rejects_unknown_id(monkeypatch):
    monkeypatch.setattr(reachability, "_ec2", lambda args: object())
    assert reachability.main(["export", "i-0123456789abcdef0", "--region", "us-east-1"]) == 1


def test_render_path_only_bundle():
    p = load("reachable.json")["path"]
    html = render_html([{"path": p, "analysis": {}}, load("reachable.json")])
    assert html.count('class="analysis"') == 2
    assert f'href="#{p["NetworkInsightsPathId"]}"' in html  # TOC falls back to the path ID
