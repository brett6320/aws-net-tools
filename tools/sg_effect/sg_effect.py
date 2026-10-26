#!/usr/bin/env python3
"""Show what a security group really does on every resource that uses it.

For each resource (EC2 instance, load balancer, Lambda function, RDS, VPC endpoint,
ECS task, ...) whose network interface has the group, sg_effect shows the resource's
net inbound and outbound access across all of its security groups, which rules come
from the target group, and what the resource would lose if the group were removed from
it. With --remove-rule, the HTML report (only) also shows what each resource would lose
if those rules of the target group were deleted, after counting every other rule that
still allows the same traffic. Groups whose rules reference the target are listed too.
Read-only.

    sg_effect.py sg-0123456789abcdef0 --region us-east-1
    sg_effect.py sg-0123456789abcdef0 --remove-rule sgr-0abc... --remove-rule in:tcp:22:10.0.0.0/8
    sg_effect.py sg-0123456789abcdef0 --resource i-0123456789abcdef0

Logs go to stderr; the text output (or --json) goes to stdout.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

import truststore

truststore.inject_into_ssl()

from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound  # noqa: E402
from dotenv import load_dotenv  # noqa: E402

import se_analyze as analyze  # noqa: E402
import se_core as core  # noqa: E402
import se_text  # noqa: E402
from se_export import THEMES, render_html  # noqa: E402

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("sg_effect")

EXIT_OK, EXIT_ERROR, EXIT_LOSES_ACCESS = 0, 1, 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0], formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog="\n".join(__doc__.splitlines()[2:]))
    p.add_argument("group", nargs="?", metavar="SG_ID", help="Security group ID (not needed with --from-json)")
    p.add_argument("--remove-rule", action="append", default=[], metavar="RULE",
                   help="Scenario, shown in the HTML report only: delete this rule of the target group "
                        "(repeatable). An sgr- ID, or "
                        "DIRECTION:PROTOCOL:PORTS:PEER such as in:tcp:443:0.0.0.0/0, out:-1:all:0.0.0.0/0, "
                        "in:tcp:5432:sg-0123... or in:tcp:22:pl-0123...")
    p.add_argument("--resource", action="append", default=[], metavar="ID",
                   help="Only show this resource (instance ID, load balancer or function name, ENI ID; repeatable)")
    p.add_argument("--profile", default=os.getenv("AWS_PROFILE"), help="AWS profile (not included in reports)")
    p.add_argument("--region", default=os.getenv("SGE_REGION") or os.getenv("AWS_REGION")
                   or os.getenv("AWS_DEFAULT_REGION"), help="Region of the security group")
    p.add_argument("--output", "-o", metavar="FILE.html", help="Write the HTML report here")
    p.add_argument("--reports-dir", default=os.getenv("SGE_REPORTS_DIR", "reports"), metavar="DIR",
                   help="Reports root; reports go to DIR/<YYYY-MM-DD>/<account>/ (default: ./reports)")
    p.add_argument("--no-report", action="store_true", help="Print the text output only")
    p.add_argument("--theme", choices=THEMES, default=os.getenv("SGE_THEME", "dark"),
                   help="HTML report theme: dark (default), light, or auto")
    p.add_argument("--title", help="HTML page title")
    p.add_argument("--json", action="store_true", help="Print the analysis as JSON instead")
    p.add_argument("--json-out", metavar="FILE.json", help="Also save the collected bundle for --from-json")
    p.add_argument("--from-json", metavar="FILE.json", help="Analyze a saved bundle, offline")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    return p


def report_path(result: dict, reports_dir: str, scenario: bool) -> Path:
    day = (result.get("generated") or "")[:10] or "undated"
    name = f"sg-effect_{result['target']['id']}" + ("_remove-rules" if scenario else "") + ".html"
    return Path(reports_dir) / day / (result.get("account") or "account") / name


def cli_view(result: dict) -> dict:
    """The analysis without the rule-removal scenario, which only the HTML report shows."""
    view = {k: v for k, v in result.items() if k != "removing"}
    view["resources"] = [{k: v for k, v in r.items() if k != "remove_rules"} for r in result["resources"]]
    return view


def run(args) -> int:
    if args.from_json:
        bundle = json.loads(Path(args.from_json).read_text(encoding="utf-8"))
        if args.group and args.group != bundle.get("target"):
            raise core.ValidationError(f"{args.from_json} is for {bundle.get('target')}, not {args.group}")
    else:
        if not args.group:
            raise core.ValidationError("Pass a security group ID (or --from-json)")
        session = core.get_session(args.profile, args.region)
        bundle = core.collect(session, args.region or session.region_name, args.group)
    if args.remove_rule and args.no_report:
        raise core.ValidationError("--remove-rule results are only in the HTML report; drop --no-report")
    result = analyze.analyze(bundle, args.remove_rule, args.resource)
    if args.resource and not result["resources"]:
        log.warning("No resource using %s matches %s", bundle["target"], ", ".join(args.resource))
    if args.json:
        print(json.dumps(cli_view(result), indent=2, default=str))
    else:
        sys.stdout.write(se_text.render(result))
    for w in result["warnings"]:
        log.warning("%s", w)
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(bundle, indent=2, default=str), encoding="utf-8")
        log.info("Wrote JSON %s", args.json_out)
    if not args.no_report:
        out = Path(args.output) if args.output else report_path(result, args.reports_dir, bool(args.remove_rule))
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(render_html(result, bundle, args.title, args.theme), encoding="utf-8")
        log.info("Wrote HTML report %s", out)
        if args.remove_rule:
            note = f"Rule removal scenario ({', '.join(r['id'] for r in result['removing'])}): see {out}"
            if args.json:
                log.info("%s", note)          # keep stdout valid JSON
            else:
                print(f"\n{note}")
    return EXIT_LOSES_ACCESS if analyze.loses_access(result) else EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.quiet:
        logging.getLogger().setLevel(logging.WARNING)
    try:
        return run(args)
    except (core.ValidationError, LookupError, ValueError, OSError) as e:
        log.error("%s", e)
        return EXIT_ERROR
    except (NoCredentialsError, ProfileNotFound) as e:
        log.error("Credentials error: %s", e)
        return EXIT_ERROR
    except ClientError as e:
        log.error("AWS error %s: %s", e.response["Error"]["Code"], e.response["Error"]["Message"])
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
