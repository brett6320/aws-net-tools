"""Synthetic sg_effect report: a web tier group used by a load balancer, two instances and a
Lambda function, with a rule removal scenario. The data is the test suite's fake EC2
(tests/sg_effect_fake.py), collected and analyzed by the tool's own collect() and analyze()."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests"))

import sg_effect as sge  # noqa: E402
import sg_effect_fake as fake  # noqa: E402

SHOTS = [("sg-effect", "dark", 1500)]


def render() -> str:
    sge.get_client = lambda service, session: fake.FakeEC2()
    bundle = sge.collect(None, "us-east-1", fake.WEB)
    bundle["generated"] = "2026-10-26T15:00:00+00:00"
    return sge.render_html(sge.analyze(bundle, ["sgr-0web0443"]))
