#!/usr/bin/env python3
"""Regenerate the README screenshots from the synthetic test data.

Collects a bundle from the fake EC2 API in tests/, analyzes it with one rule-removal
scenario, renders the report with se_export, measures the crop height in headless
Chrome (--dump-dom with an injected script), then captures the viewport at that height.
macOS/Chrome docs helper, not part of the tool.

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

import fake_ec2  # noqa: E402
import se_analyze  # noqa: E402
import se_core  # noqa: E402
from se_export import render_html  # noqa: E402

IMAGES = HERE / "images"
WIDTH = 1300
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
SCENARIO = ["sgr-0web0443"]

# name, theme, heading of the card whose bottom ends the capture
SHOTS = [
    ("report", "dark", "EC2 instance i-0web1000000000001"),
    ("report-light", "light", "Application Load Balancer"),
]


def bundle() -> dict:
    fake = fake_ec2.FakeEC2()
    se_core.get_client = lambda svc, session, region=None: fake
    b = se_core.collect(object(), "us-east-1", fake_ec2.WEB)
    b["generated"] = "2026-10-26T15:00:00+00:00"
    return b


def chrome(args: list[str], binary: str) -> str:
    return subprocess.run([binary, "--headless=new", "--disable-gpu", "--hide-scrollbars",
                           "--force-device-scale-factor=1", *args], capture_output=True, text=True, check=True).stdout


def inject(html: str, script: str) -> str:
    """Insert a script before the page's own closing </body>."""
    head, sep, tail = html.rpartition("</body>")
    return f"{head}<script>{script}</script>{sep}{tail}"


def shoot(name: str, theme: str, heading: str, tmp: Path, binary: str) -> None:
    b = bundle()
    html = render_html(se_analyze.analyze(b, SCENARIO), b, theme=theme)
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
