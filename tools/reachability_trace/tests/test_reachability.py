import json
import logging
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

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
    assert "<link" not in html and "<script" not in html
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
    assert "Intended path" in html and "node blocked" in html


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
