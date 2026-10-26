#!/usr/bin/env python3
"""Regenerate the README screenshots from the synthetic bundle in tests/fixtures/.

Runs each command on the fixture, renders the HTML report with dr_export, measures the
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
sys.path.insert(0, str(TOOL))

import dr_cisco as cisco  # noqa: E402
from dr_export import render_html  # noqa: E402
from dx_route import parse_command  # noqa: E402

FIXTURE = TOOL / "tests" / "fixtures" / "core_dxgw.json"
IMAGES = HERE / "images"
WIDTH = 1300
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

# name, command, theme, card heading whose bottom ends the capture
SHOTS = [
    ("bgp-entry", "show ip bgp 10.20.30.0/24", "dark", "Path selection"),
    ("bgp-entry-light", "show ip bgp 10.20.30.0/24", "light", "Path selection"),
    ("bgp-table", "show ip bgp", "dark", "Router output"),
    ("route-entry", "show ip route 10.20.30.7", "dark", "Path selection"),
]


def chrome(args: list[str], binary: str) -> str:
    return subprocess.run([binary, "--headless=new", "--disable-gpu", "--hide-scrollbars",
                           "--force-device-scale-factor=1", *args], capture_output=True, text=True, check=True).stdout


def inject(html: str, script: str) -> str:
    """Insert a script before the page's own closing </body>."""
    head, sep, tail = html.rpartition("</body>")
    return f"{head}<script>{script}</script>{sep}{tail}"


def shoot(name: str, command: str, theme: str, heading: str, tmp: Path, binary: str) -> None:
    bundle = json.loads(FIXTURE.read_text())
    cmd = parse_command(command.split())
    html = render_html(bundle, cmd, cisco.render(bundle, cmd), None, theme)
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
