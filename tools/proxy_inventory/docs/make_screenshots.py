#!/usr/bin/env python3
"""Regenerate the README screenshots from a made-up inventory.

Builds synthetic scan results (invented accounts, VPCs and resources), runs them through
the tool's own build_rows() and render_report(), measures the crop height in headless
Chrome (--dump-dom with an injected script), then captures the viewport at that height
in the dark or light color scheme. macOS/Chrome docs helper, not part of the tool.

    python docs/make_screenshots.py [--chrome PATH] [NAME ...]
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOL = HERE.parent
sys.path.insert(0, str(TOOL))

import pi_core as core  # noqa: E402
import proxy_inventory as pi  # noqa: E402

IMAGES = HERE / "images"
WIDTH = 1600
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
SCHEME = {"dark": 0, "light": 1}

# name, scheme, URL fragment (table state), table headings to hide, max height
SHOTS = [
    ("report", "dark", "", [], 1000),
    ("report-light", "light", "", [], 1000),
    ("resources", "dark", "res.vpc_id=vpc-0b7e41c2d9a3f5602", ["AppCatIDs by VPC"], 900),
    ("unattributed", "dark", "eni.open=1", ["AppCatIDs by VPC", "Resources", "VPCs read"], 700),
]

PAY, NET, ANA = "111111111111", "222222222222", "333333333333"
NAMES = {PAY: "payments-prod", NET: "network-shared-prod", ANA: "analytics-prod"}
E1, C1 = "us-east-1", "ca-central-1"
V_PAY, V_SHARED, V_ANA, V_GONE = "vpc-0a3c9e1f42b7d8101", "vpc-0b7e41c2d9a3f5602", "vpc-0c19d4a7e6f2b0303", "vpc-0d55e0b3c8a1f7404"


def vpcs() -> list[core.Vpc]:
    return [
        core.Vpc(E1, V_PAY, PAY, NAMES[PAY], "ou-ab12-11111111", "Root/Prod/Payments", "payments-prod-vpc", ("10.20.0.0/16",)),
        core.Vpc(E1, V_SHARED, NET, NAMES[NET], "ou-ab12-22222222", "Root/Prod/Network", "shared-apps-vpc", ("10.40.0.0/16",)),
        core.Vpc(C1, V_ANA, ANA, NAMES[ANA], "ou-ab12-33333333", "Root/Prod/Analytics", "analytics-ca-vpc", ("10.60.0.0/16",)),
        core.Vpc(E1, V_GONE, PAY, NAMES[PAY], "ou-ab12-11111111", "Root/Prod/Payments", "payments-old-vpc", ("10.21.0.0/16",)),
    ]


def res(account: str, region: str, rtype: str, rid: str, vpc: str, app: str | None, **kw) -> dict:
    tags = {"Name": kw.pop("name_tag", rid), "Environment": "prod", **kw.pop("tags", {})}
    if app:
        tags["AppCatID"] = app
    return {**core.resource(rtype, rid, vpc, tags=tags, **kw), "account": account, "region": region}


def eni(eni_id: str, account: str, region: str, vpc: str, description: str, *, owner: str = "", itype: str = "interface",
        ip: str = "") -> dict:
    return {"eni_id": eni_id, "vpc_id": vpc, "subnet": "subnet-0f00d", "eni_owner": owner or account, "interface_type": itype,
            "description": description, "requester": "", "requester_managed": False, "status": "in-use", "instance_id": "",
            "instance_owner": "", "private_ips": [ip] if ip else [], "tags": {}, "account": account, "region": region}


def scan() -> core.Scan:
    ec2 = "EC2 instance"
    s = core.Scan()
    s.resources = [
        res(PAY, E1, ec2, "i-0a11c3e5f7b9d1001", V_PAY, "APP-1042", name="pay-api-1", state="running",
            ips=["10.20.1.15"], subnets=["subnet-0a1001"], detail=["m6i.large", "EKS payments"], name_tag="pay-api-1",
            tags={"eks:cluster-name": "payments", "CostCenter": "4410"}),
        res(PAY, E1, ec2, "i-0a11c3e5f7b9d1002", V_PAY, "APP-1042", name="pay-api-2", state="running",
            ips=["10.20.2.31"], subnets=["subnet-0a1002"], detail=["m6i.large", "EKS payments"], name_tag="pay-api-2",
            tags={"eks:cluster-name": "payments", "CostCenter": "4410"}),
        res(PAY, E1, "Lambda function", "settlement-export", V_PAY, "APP-1077", subnets=["subnet-0a1001", "subnet-0a1002"],
            detail=["python3.12"], tags={"Owner": "settlements-team"}),
        res(PAY, E1, "ECS service", "pay-cluster/fraud-score", V_PAY, None, name="fraud-score", state="ACTIVE",
            subnets=["subnet-0a1002"], detail=["FARGATE", "desired 3"],
            inherited=("ECS cluster", {"AppCatID": "APP-1090"})),
        res(PAY, E1, ec2, "i-0a11c3e5f7b9d1003", V_PAY, None, name="jump-box", state="stopped",
            ips=["10.20.1.200"], subnets=["subnet-0a1001"], detail=["t3.micro"], name_tag="jump-box"),
        res(NET, E1, ec2, "i-0b22d4f6a8c0e2001", V_SHARED, "APP-2210", name="crm-web-1", state="running",
            ips=["10.40.1.12"], subnets=["subnet-0b2001"], detail=["c6i.xlarge"], name_tag="crm-web-1"),
        res(NET, E1, "AppStream fleet", "analyst-desktops", V_SHARED, "APP-2301", state="RUNNING",
            subnets=["subnet-0b2001", "subnet-0b2002"], detail=["stream.standard.medium", "ON_DEMAND"]),
        res(ANA, E1, "Lambda function", "crm-sync", V_SHARED, "APP-2210", subnets=["subnet-0b2002"],
            detail=["nodejs20.x"], tags={"Owner": "crm-team"}),
        res(ANA, E1, "ECS task", "etl-cluster/4f1c9e2a", V_SHARED, "APP-3005", state="RUNNING",
            ips=["10.40.2.77"], subnets=["subnet-0b2002"], detail=["FARGATE", "standalone task"]),
        res(ANA, C1, ec2, "i-0c33e5a7b9d1f3001", V_ANA, "APP-3005", name="spark-worker-1", state="running",
            ips=["10.60.1.21"], subnets=["subnet-0c3001"], detail=["r6i.2xlarge", "EMR j-2AXXXXXXGAPLF"]),
        res(ANA, C1, ec2, "i-0c33e5a7b9d1f3002", V_ANA, "APP-3005", name="spark-worker-2", state="running",
            ips=["10.60.1.22"], subnets=["subnet-0c3001"], detail=["r6i.2xlarge", "EMR j-2AXXXXXXGAPLF"]),
        res(ANA, C1, "Lambda function", "report-mailer", V_ANA, None, subnets=["subnet-0c3001"], detail=["python3.12"]),
    ]
    s.enis = [
        eni("eni-0a9f1e2d3c4b5a601", PAY, E1, V_PAY, "aws-K8S-i-0a11c3e5f7b9d1001", ip="10.20.1.88"),
        eni("eni-0b8e2f3a4d5c6b702", NET, E1, V_SHARED, "Attached to Glue using role: arn:aws:iam::333333333333:role/etl",
            owner=ANA, ip="10.40.2.140"),
        eni("eni-0b8e2f3a4d5c6b703", NET, E1, V_SHARED, "CodeBuild project crm-build", owner="444444444444", ip="10.40.2.141"),
        eni("eni-0c7d3a4b5e6f7c804", ANA, C1, V_ANA, "", ip="10.60.2.9"),
        eni("eni-0c7d3a4b5e6f7c805", ANA, C1, V_ANA, "VPC Endpoint Interface vpce-0abc", itype="vpc_endpoint"),
    ]
    s.vpcs = [{"account": v.account, "region": v.region, "vpc_id": v.vpc_id, "gone": v.vpc_id == V_GONE,
               "tags": {} if v.vpc_id == V_GONE else {"Name": v.name, "AppCatID": "APP-0001"}} for v in vpcs()]
    s.read = {(a, r, v, "Lambda") for a, r, v in ((PAY, E1, V_PAY), (ANA, E1, V_SHARED), (ANA, C1, V_ANA))}
    s.issues = [core.Issue("444444444444", E1, "participant", "no profile in ~/.aws/config maps to account 444444444444"),
                core.Issue(ANA, C1, "AppStream", "AccessDeniedException: explicit deny in a service control policy",
                           incomplete=False)]
    return s


def render() -> str:
    rows = pi.build_rows(scan(), vpcs(), core.DEFAULT_KEY_TAG)
    meta = ["Generated 2026-11-03 14:05:12 UTC from the VPC owner map vpc-owners.json (OU Root/Prod)",
            "Application tag: AppCatID (any case). ECS services and tasks without it inherit their cluster's "
            "(shown in the \"from\" column).",
            "Not read (opt-in with --include): WorkSpaces, Glue, MWAA, App Runner. Their network interfaces show as unattributed."]
    return pi.render_report(rows, title="Proxy-capable resources by AppCatID", key_tag=core.DEFAULT_KEY_TAG, meta=meta)


def chrome(args: list[str], binary: str, scheme: str) -> str:
    return subprocess.run([binary, "--headless=new", "--disable-gpu", "--hide-scrollbars",
                           "--force-device-scale-factor=1", f"--blink-settings=preferredColorScheme={SCHEME[scheme]}",
                           "--virtual-time-budget=2000", *args],
                          capture_output=True, text=True, check=True).stdout


def inject(html: str, snippet: str) -> str:
    """Insert before the page's closing </body> only; report scripts can contain "</body>" in strings."""
    head, sep, tail = html.rpartition("</body>")
    return f"{head}{snippet}{sep}{tail}"


def shoot(name: str, scheme: str, fragment: str, hide: list[str], max_height: int, html: str, tmp: Path,
          binary: str) -> None:
    setup = ("<script>addEventListener('load',()=>{document.querySelectorAll('#app h2').forEach(h=>{"
             f"if({json.dumps(hide)}.includes(h.textContent))h.closest('section').style.display='none'}})}})</script>")
    page = tmp / f"{name}.html"
    page.write_text(inject(html, setup), encoding="utf-8")
    measure = tmp / f"{name}-measure.html"
    measure.write_text(inject(html, setup + (
        "<script>addEventListener('load',()=>setTimeout(()=>document.body.setAttribute('data-crop',"
        "Math.ceil(document.documentElement.scrollHeight)),0))</script>")), encoding="utf-8")
    hash_ = f"#{fragment}" if fragment else ""
    dom = chrome([f"--window-size={WIDTH},1000", "--dump-dom", measure.as_uri() + hash_], binary, scheme)
    height = min(int(re.search(r'data-crop="(\d+)"', dom).group(1)), max_height)
    out = IMAGES / f"{name}.png"
    chrome([f"--window-size={WIDTH},{height}", f"--screenshot={out}", page.as_uri() + hash_], binary, scheme)
    print(f"{out.relative_to(TOOL)}  ({WIDTH}x{height}, {scheme})")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--chrome", default=CHROME, help="Chrome/Chromium binary")
    parser.add_argument("names", nargs="*", help="Only regenerate these shots (default: all)")
    args = parser.parse_args()
    unknown = set(args.names) - {s[0] for s in SHOTS}
    if unknown:
        parser.error(f"unknown shot(s): {', '.join(sorted(unknown))}")
    IMAGES.mkdir(exist_ok=True)
    html = render()
    with tempfile.TemporaryDirectory() as d:
        for shot in SHOTS:
            if not args.names or shot[0] in args.names:
                shoot(*shot, html, Path(d), args.chrome)
    return 0


if __name__ == "__main__":
    sys.exit(main())
