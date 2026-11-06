#!/usr/bin/env python3
"""Regenerate the README screenshot from the synthetic alarm set in tests/fake_cloudwatch.py.

Renders the report with cwah_export and captures it in headless Chrome. macOS/Chrome docs
helper, not part of the tool.

    python docs/make_screenshots.py [--chrome PATH]
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOL = HERE.parent
sys.path.insert(0, str(TOOL))
sys.path.insert(0, str(TOOL / "tests"))

import cw_alarm_history as cwah  # noqa: E402
from fake_cloudwatch import ACCOUNT, NOW, T0, FakeCloudWatch  # noqa: E402

IMAGES = HERE / "images"
WIDTH, HEIGHT = 1300, 1500
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
SHOTS = [("report", "dark"), ("report-light", "light")]


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--chrome", default=CHROME)
    args = p.parse_args()
    report = cwah.collect_alarm_history(
        alarms=["net-dx-bgp-down", "net-tgw-packet-drops", "net-vpn-tunnel-status", "net-quiet", "net-stuck-alarm"],
        start=T0, end=NOW, cw=FakeCloudWatch(), account=ACCOUNT, now=NOW)
    report.overlap_threshold = 2
    IMAGES.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        for name, theme in SHOTS:
            page = Path(td) / f"{name}.html"
            page.write_text(cwah.render_html_report(report, theme), encoding="utf-8")
            out = IMAGES / f"{name}.png"
            subprocess.run([args.chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars",
                            "--force-device-scale-factor=1", f"--window-size={WIDTH},{HEIGHT}",
                            f"--screenshot={out}", page.as_uri()], check=True, capture_output=True)
            print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
