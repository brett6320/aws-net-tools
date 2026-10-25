#!/usr/bin/env python3
"""Regenerate the README screenshots from the synthetic samples in docs/samples/.

Each docs/samples/<tool>.py builds made-up input data, runs it through the
tool's own analysis and render_html(), and returns the report HTML. This script
measures the crop height in headless Chrome (--dump-dom with an injected
script), then captures the viewport at that height in the dark or light color
scheme. macOS/Chrome docs helper, not part of the tools.

    python docs/make_screenshots.py [--chrome PATH] [NAME ...]

A sample module defines:
  SHOTS     [(name, scheme, max_height[, js]), ...]: scheme "dark" or "light";
            the capture is the page height, capped at max_height; optional js
            runs before measuring and capturing (e.g. to open a panel)
  render()  -> str, the report HTML
"""
from __future__ import annotations

import argparse
import importlib
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOL = HERE.parent
sys.path.insert(0, str(TOOL))
sys.path.insert(0, str(HERE))

IMAGES = HERE / "images"
WIDTH = 1600  # html_report max-width, so wide tables are not squeezed
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
SAMPLES = ["fmm_rule_parity", "fmm_nacl_audit", "fmm_compliance", "fmm_policy_snapshot", "nacl_shadow",
           "sg_rule_inventory", "sg_migration_check", "sg_access_gap", "sg_quota_audit", "prefix_list_audit"]
SCHEME = {"dark": 0, "light": 1}


def chrome(args: list[str], binary: str, scheme: str) -> str:
    return subprocess.run([binary, "--headless=new", "--disable-gpu", "--hide-scrollbars",
                           "--force-device-scale-factor=1", f"--blink-settings=preferredColorScheme={SCHEME[scheme]}",
                           "--virtual-time-budget=2000", *args],
                          capture_output=True, text=True, check=True).stdout


def shots() -> list[tuple]:
    """(name, module, scheme, max_height, js) for every sample module."""
    out = []
    for mod_name in SAMPLES:
        try:
            mod = importlib.import_module(f"samples.{mod_name}")
        except ModuleNotFoundError as e:
            if e.name != f"samples.{mod_name}":
                raise
            print(f"no sample for {mod_name}; skipped", file=sys.stderr)
            continue
        for s in mod.SHOTS:
            name, scheme, max_height, *js = s
            out.append((name, mod, scheme, max_height, js[0] if js else ""))
    return out


def inject(html: str, snippet: str) -> str:
    """Insert before the page's closing </body> only; report scripts can contain "</body>" in strings."""
    head, sep, tail = html.rpartition("</body>")
    return f"{head}{snippet}{sep}{tail}"


def shoot(name: str, mod, scheme: str, max_height: int, js: str, tmp: Path, binary: str) -> None:
    html = mod.render()
    setup = f"<script>addEventListener('load',()=>{{{js}}})</script>" if js else ""
    page = tmp / f"{name}.html"
    page.write_text(inject(html, setup), encoding="utf-8")
    measure = tmp / f"{name}-measure.html"
    measure.write_text(inject(html, (
        f"{setup}<script>addEventListener('load',()=>setTimeout(()=>document.body.setAttribute('data-crop',"
        "Math.ceil(document.documentElement.scrollHeight)),0))</script>")), encoding="utf-8")
    dom = chrome([f"--window-size={WIDTH},1000", "--dump-dom", measure.as_uri()], binary, scheme)
    height = min(int(re.search(r'data-crop="(\d+)"', dom).group(1)), max_height)
    out = IMAGES / f"{name}.png"
    chrome([f"--window-size={WIDTH},{height}", f"--screenshot={out}", page.as_uri()], binary, scheme)
    print(f"{out.relative_to(TOOL)}  ({WIDTH}x{height}, {scheme})")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--chrome", default=CHROME, help="Chrome/Chromium binary")
    parser.add_argument("names", nargs="*", help="Only regenerate these shots (default: all)")
    args = parser.parse_args()
    all_shots = shots()
    unknown = set(args.names) - {s[0] for s in all_shots}
    if unknown:
        parser.error(f"unknown shot(s): {', '.join(sorted(unknown))}")
    IMAGES.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as d:
        for shot in all_shots:
            if not args.names or shot[0] in args.names:
                shoot(*shot, Path(d), args.chrome)
    return 0


if __name__ == "__main__":
    sys.exit(main())
