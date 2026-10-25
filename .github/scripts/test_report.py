#!/usr/bin/env python3
"""Turn pytest results into a GitHub job summary and shields.io badge data.

    test_report.py summary --name NAME --python VER --junit FILE [--coverage FILE] [--stats-out FILE]
        Append a Markdown table (tests, passed/failed/skipped, duration, coverage) to
        $GITHUB_STEP_SUMMARY (or stdout), and optionally write the numbers as JSON.

    test_report.py badges --stats FILE --slug SLUG --out DIR
        Write shields.io endpoint files for one tool (<slug>-tests.json, <slug>-coverage.json,
        and <slug>.json with the raw numbers), then rebuild the totals (total-tests.json,
        total-coverage.json) from every <slug>.json in DIR.

Standard library only, so it runs before any project dependency is installed.
"""
import argparse
import json
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def junit_stats(path: str) -> dict:
    """Totals across every <testsuite> in a JUnit XML file."""
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
    n = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0, "time": 0.0}
    for s in suites:
        for k in ("tests", "failures", "errors", "skipped"):
            n[k] += int(s.get(k, 0))
        n["time"] += float(s.get("time", 0))
    xfail = sum(1 for tc in root.iter("testcase") for sk in tc.findall("skipped")
                if (sk.get("type") or "").endswith("xfail"))
    return {"tests": n["tests"], "passed": n["tests"] - n["failures"] - n["errors"] - n["skipped"],
            "failed": n["failures"] + n["errors"], "skipped": n["skipped"] - xfail, "xfailed": xfail,
            "seconds": round(n["time"], 2)}


def coverage_pct(path: str | None) -> float | None:
    """Total line coverage from a coverage.py JSON report, if there is one."""
    if not path or not Path(path).is_file():
        return None
    return round(json.loads(Path(path).read_text())["totals"]["percent_covered"], 1)


def cmd_summary(a) -> int:
    s = junit_stats(a.junit)
    s["coverage"] = coverage_pct(a.coverage)
    s["python"] = a.python
    status = "✅ passed" if s["failed"] == 0 else "❌ failed"
    cov = f"{s['coverage']}%" if s["coverage"] is not None else "n/a"
    md = (f"### {a.name} on Python {a.python}: {status}\n\n"
          "| Tests | Passed | Failed | Skipped | Expected failures | Duration | Coverage |\n"
          "|---:|---:|---:|---:|---:|---:|---:|\n"
          f"| {s['tests']} | {s['passed']} | {s['failed']} | {s['skipped']} | {s['xfailed']} "
          f"| {s['seconds']}s | {cov} |\n\n")
    out = os.environ.get("GITHUB_STEP_SUMMARY")
    if out:
        with open(out, "a", encoding="utf-8") as f:
            f.write(md)
    else:
        sys.stdout.write(md)
    if a.stats_out:
        Path(a.stats_out).write_text(json.dumps(s, indent=2) + "\n")
    return 0


def coverage_color(pct: float) -> str:
    return "brightgreen" if pct >= 90 else "green" if pct >= 80 else "yellow" if pct >= 70 \
        else "orange" if pct >= 50 else "red"


def badge(label: str, message: str, color: str) -> dict:
    return {"schemaVersion": 1, "label": label, "message": message, "color": color}


def tests_badge(label: str, s: dict) -> dict:
    msg = f"{s['passed']} passed" + (f", {s['failed']} failed" if s["failed"] else "")
    return badge(label, msg, "brightgreen" if s["failed"] == 0 else "red")


def cmd_badges(a) -> int:
    s = json.loads(Path(a.stats).read_text())
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    write = lambda name, data: (out / name).write_text(json.dumps(data, indent=2) + "\n")
    write(f"{a.slug}.json", s)
    write(f"{a.slug}-tests.json", tests_badge("tests", s))
    if s.get("coverage") is not None:
        write(f"{a.slug}-coverage.json", badge("coverage", f"{s['coverage']}%", coverage_color(s["coverage"])))

    # Totals over every tool that has published numbers. Coverage is the plain mean of the
    # per-tool percentages (each tool is measured on its own code).
    tools = [json.loads(p.read_text()) for p in sorted(out.glob("*.json"))
             if not p.stem.startswith("total-") and "-" not in p.stem]
    total = {k: sum(t.get(k, 0) for t in tools) for k in ("tests", "passed", "failed")}
    write("total-tests.json", tests_badge("tests", total))
    covs = [t["coverage"] for t in tools if t.get("coverage") is not None]
    if covs:
        mean = round(sum(covs) / len(covs), 1)
        write("total-coverage.json", badge("coverage", f"{mean}%", coverage_color(mean)))
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("summary")
    s.add_argument("--name", required=True)
    s.add_argument("--python", required=True)
    s.add_argument("--junit", required=True)
    s.add_argument("--coverage")
    s.add_argument("--stats-out")
    b = sub.add_parser("badges")
    b.add_argument("--stats", required=True)
    b.add_argument("--slug", required=True)
    b.add_argument("--out", required=True)
    a = p.parse_args()
    return cmd_summary(a) if a.cmd == "summary" else cmd_badges(a)


if __name__ == "__main__":
    sys.exit(main())
