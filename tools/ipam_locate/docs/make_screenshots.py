#!/usr/bin/env python3
"""Regenerate the README screenshots from the synthetic fixtures in tests/fixtures/.

Renders each fixture with il_export, measures the crop height in headless Chrome
(--dump-dom with an injected script), then captures the viewport at that height.
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
sys.path.insert(0, str(TOOL))

from il_export import render_html  # noqa: E402

FIXTURES = TOOL / "tests" / "fixtures"
IMAGES = HERE / "images"
WIDTH = 1300
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

# name, fixture, theme, card heading whose bottom ends the capture
SHOTS = [
    ("located-instance", "private_instance", "dark", "Hierarchy"),
    ("located-instance-light", "private_instance", "light", "Hierarchy"),
    ("pool-only", "pool_only", "dark", "Hierarchy"),
    ("public-nat", "public_nat", "dark", "Hierarchy"),
    ("cidr-query", "cidr_subnet", "dark", "Discovered resources inside"),
]


def chrome(args: list[str], binary: str) -> str:
    return subprocess.run([binary, "--headless=new", "--disable-gpu", "--hide-scrollbars",
                           "--force-device-scale-factor=1", *args], capture_output=True, text=True, check=True).stdout


def shoot(name: str, fixture: str, theme: str, heading: str, tmp: Path, binary: str) -> None:
    html = render_html([json.loads((FIXTURES / f"{fixture}.json").read_text())], "IPAM Locate", theme)
    page = tmp / f"{name}.html"
    page.write_text(html, encoding="utf-8")
    measure = tmp / f"{name}-measure.html"
    measure.write_text(html.replace("</body>", (
        "<script>var h=[...document.querySelectorAll('h3')].find(e=>e.textContent.startsWith("
        f"{json.dumps(heading)})).closest('.card');"
        "document.body.setAttribute('data-crop',Math.round(h.getBoundingClientRect().bottom+scrollY+16))"
        "</script></body>")), encoding="utf-8")
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
