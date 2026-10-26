#!/usr/bin/env python3
"""Regenerate the README screenshots of the diff report from the synthetic test data.

Builds two snapshots from the fake Direct Connect API in tests/ (the second with a few
configuration changes), renders the diff and restore plan with db_export, measures the
crop height in headless Chrome (--dump-dom with an injected script), then captures the
viewport at that height. macOS/Chrome docs helper, not part of the tool.

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
sys.path[:0] = [str(TOOL), str(TOOL / "tests")]

import db_core as core  # noqa: E402
import db_diff  # noqa: E402
import db_restore  # noqa: E402
import test_dx_backup as data  # noqa: E402
from db_export import render_html  # noqa: E402

IMAGES = HERE / "images"
WIDTH = 1300
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

# name, theme, card heading whose bottom ends the capture
SHOTS = [
    ("diff", "dark", "Restore plan"),
    ("diff-light", "light", "Restore plan"),
]


def snapshots() -> tuple[dict, dict]:
    """The example in the README: yesterday's backup and today's, with a few changes."""
    holder = {"dx": data.FakeDX(data.api_data())}
    core.get_client = lambda svc, session, region=None: holder["dx"]

    def snap(api, generated):
        holder["dx"] = data.FakeDX(api)
        s = core.collect(object(), ["us-east-1"], account=data.ACCOUNT)
        s["manifest"]["generated"] = generated
        s["manifest"]["path"] = f"backups/{data.ACCOUNT}/{generated[:10].replace('-', '')}T060000Z"
        return s

    old = snap(data.api_data(), "2026-10-25T06:00:00+00:00")
    d = data.api_data()
    v = d["vifs"][0]
    v["mtu"] = 1500
    v["bgpPeers"].pop(1)
    v["tags"] = data.tags(Name="nyc-primary", env="dev")
    d["associations"][0]["allowedPrefixesToDirectConnectGateway"] = [{"cidr": "172.31.0.0/16"},
                                                                    {"cidr": "172.28.0.0/16"}]
    d["lags"][0]["minimumLinks"] = 2
    d["routes"][data.VIF_PRIV] = d["routes"][data.VIF_PRIV][1:]
    d["vifs"].pop(2)
    return old, snap(d, "2026-10-26T06:00:00+00:00")


def chrome(args: list[str], binary: str) -> str:
    return subprocess.run([binary, "--headless=new", "--disable-gpu", "--hide-scrollbars",
                           "--force-device-scale-factor=1", *args], capture_output=True, text=True, check=True).stdout


def inject(html: str, script: str) -> str:
    """Insert a script before the page's own closing </body>."""
    head, sep, tail = html.rpartition("</body>")
    return f"{head}<script>{script}</script>{sep}{tail}"


def shoot(name: str, theme: str, heading: str, tmp: Path, binary: str) -> None:
    old, new = snapshots()
    html = render_html(db_diff.diff(old, new), old, new, plan_text=db_restore.plan(old, new).text, theme=theme)
    page = tmp / f"{name}.html"
    page.write_text(html, encoding="utf-8")
    measure = tmp / f"{name}-measure.html"
    measure.write_text(inject(html, (
        "var h=[...document.querySelectorAll('h3')].find(e=>e.textContent.startsWith("
        f"{json.dumps(heading)})).closest('.card');"
        "document.body.setAttribute('data-crop',Math.round(h.getBoundingClientRect().bottom+scrollY+16))")),
        encoding="utf-8")
    dom = chrome([f"--window-size={WIDTH},1000", "--dump-dom", measure.as_uri()], binary)
    height = int(re.search(r'data-crop="(\d+)"', dom).group(1))
    out = IMAGES / f"{name}.png"
    chrome([f"--window-size={WIDTH},{height}", f"--screenshot={out}", page.as_uri()], binary)
    print(f"{out.relative_to(TOOL)}  ({WIDTH}x{height}, {theme})")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--chrome", default=CHROME, help="Chrome/Chromium binary")
    parser.add_argument("names", nargs="*", help="Only regenerate these shots (default: all)")
    args = parser.parse_args()
    unknown = set(args.names) - {s[0] for s in SHOTS}
    if unknown:
        parser.error(f"unknown shot(s): {', '.join(sorted(unknown))}")
    IMAGES.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as d:
        for shot in SHOTS:
            if not args.names or shot[0] in args.names:
                shoot(*shot, Path(d), args.chrome)
    return 0


if __name__ == "__main__":
    sys.exit(main())
