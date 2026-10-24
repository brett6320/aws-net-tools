#!/usr/bin/env python3
"""Regenerate the README screenshots from the synthetic fixtures in tests/fixtures/.

Renders each fixture with ra_export, measures the region to capture in headless
Chrome (--dump-dom with an injected measuring script), takes a full-page
screenshot, and crops it with `sips`. macOS only (Chrome + sips); this is a docs
helper, not part of the tool.

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

from ra_export import render_html  # noqa: E402

FIXTURES = TOOL / "tests" / "fixtures"
IMAGES = HERE / "images"
WIDTH = 1300
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

# JS helpers available to the start/end expressions below.
_JS_HELPERS = """
function card(t){return [...document.querySelectorAll('h3')].find(h=>h.textContent.startsWith(t)).closest('.card');}
function yTop(el){return el.getBoundingClientRect().top+scrollY;}
function yBottom(el){return el.getBoundingClientRect().bottom+scrollY;}
"""

# name, fixture, theme, JS expr for crop top (px), JS expr for crop bottom (px)
SHOTS = [
    ("reachable-overview", "reachable", "dark", "0", "yBottom(card('Forward path').querySelector('.flow'))+24"),
    ("reachable-overview-light", "reachable", "light", "0", "yBottom(card('Forward path').querySelector('.flow'))+24"),
    ("not-reachable", "not_reachable", "dark", "0", "yBottom(card('Explanations'))+16"),
    ("igw-nlb-path", "igw_nlb", "dark", "0", "yBottom(document.querySelectorAll('.comp')[2])+16"),
    ("return-path", "reachable", "dark", "yTop(card('Return path'))-16", "yTop(card('Return path'))+1084"),
    ("cross-account", "cross_account", "dark", "0", "yBottom(card('Forward path').querySelector('.legend'))+24"),
    ("blocked-path", "blocked_midpath", "dark", "yTop(card('Forward path'))-16",
     "yBottom(card('Forward path').querySelector('.flow'))+24"),
]


def chrome(args: list[str], binary: str) -> str:
    return subprocess.run([binary, "--headless=new", "--disable-gpu", "--hide-scrollbars",
                           "--force-device-scale-factor=1", *args],
                          capture_output=True, text=True, check=True).stdout


def shoot(name: str, fixture: str, theme: str, top_js: str, bottom_js: str, tmp: Path, binary: str) -> None:
    bundle = json.loads((FIXTURES / f"{fixture}.json").read_text())
    html = render_html([bundle], "Reachability trace", theme)
    page = tmp / f"{name}.html"
    page.write_text(html, encoding="utf-8")

    measure = tmp / f"{name}-measure.html"
    measure.write_text(html.replace("</body>", (
        f"<script>{_JS_HELPERS}document.body.setAttribute('data-crop',"
        f"Math.round({top_js})+','+Math.round({bottom_js})+','+document.documentElement.scrollHeight)"
        "</script></body>")), encoding="utf-8")
    dom = chrome([f"--window-size={WIDTH},1000", "--dump-dom", measure.as_uri()], binary)
    y0, y1, full = map(int, re.search(r'data-crop="(-?\d+),(-?\d+),(\d+)"', dom).groups())
    y0, y1 = max(0, y0), min(full, y1)

    out = IMAGES / f"{name}.png"
    if y0 == 0:
        # Top of page: capture the viewport at the crop height directly. (sips treats a
        # zero offset as unset and center-crops instead.)
        chrome([f"--window-size={WIDTH},{y1}", f"--screenshot={out}", page.as_uri()], binary)
    else:
        shot = tmp / f"{name}-full.png"
        chrome([f"--window-size={WIDTH},{full}", f"--screenshot={shot}", page.as_uri()], binary)
        subprocess.run(["sips", "--cropOffset", str(y0), "0", "-c", str(y1 - y0), str(WIDTH), str(shot),
                        "--out", str(out)], capture_output=True, check=True)
    print(f"{out.relative_to(TOOL)}  ({WIDTH}x{y1 - y0}, {theme})")


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
