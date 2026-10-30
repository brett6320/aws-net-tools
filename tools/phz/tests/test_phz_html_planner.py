"""The HTML report's migration planner (JavaScript), run under Node."""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "phz_review"))

import phz_html  # noqa: E402

NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(not NODE, reason="node is not installed")

HUB, SPOKE, OTHER = "111111111111", "222222222222", "333333333333"
OLD, NEW, ALT = "Z0OLD0000000001", "Z0NEW0000000001", "Z0ALT0000000001"


def zone(zid, name, owner, vpc_count):
    return {"zone_id": zid, "name": name, "owner": owner, "vpc_count": vpc_count}


def assoc(zid, name, owner, vpc, vpc_owner, status="associated", region="us-east-1"):
    return {"zone_id": zid, "zone_name": name, "zone_owner": owner, "vpc_id": vpc, "vpc_region": region,
            "vpc_owner": vpc_owner, "status": status}


def base_data(**kw):
    d = {
        "generated_at": "now", "vpc_counts_complete": True, "authorizations_listed": True,
        "zones": [zone(OLD, "corp.internal", HUB, 3), zone(NEW, "corp.internal", OTHER, 1), zone(ALT, "new.internal", OTHER, 1)],
        "associations": [
            assoc(OLD, "corp.internal", HUB, "vpc-a", HUB),
            assoc(OLD, "corp.internal", HUB, "vpc-b", SPOKE),
            assoc(OLD, "corp.internal", HUB, "vpc-c", SPOKE),
            assoc(NEW, "corp.internal", OTHER, "vpc-n", OTHER),
            assoc(ALT, "new.internal", OTHER, "vpc-n", OTHER),
        ],
    }
    d.update(kw)
    return d


def run(data, selected, **opts):
    o = {"disassociate": True, "disassociateAs": "vpc", "deleteTargetAuth": True, "cleanupSourceAuth": True,
         "vpcOwners": {}, "profiles": {}, **opts}
    js = phz_html.PLANNER_JS + f"""
var data = {json.dumps(data)}, sel = {json.dumps(selected)}, opts = {json.dumps(o)};
var p = planMigration(data, sel, opts);
p.script = (p.errors.length || !p.steps.length) ? "" : renderScript(p, opts, data);
process.stdout.write(JSON.stringify(p));
"""
    out = subprocess.run([NODE, "-e", js], capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def pick(zid, vpc, region="us-east-1"):
    return {"zone_id": zid, "vpc_id": vpc, "vpc_region": region}


def actions(p):
    return [(s["phase"], s["action"], s["account"], s["zone_id"], s["vpc_id"], bool(s["skipped"])) for s in p["steps"]]


def test_cross_account_different_name_associates_before_disassociating():
    p = run(base_data(), [pick(OLD, "vpc-b")], target={"zone_id": ALT, "name": "new.internal", "owner": OTHER})
    assert not p["errors"]
    assert actions(p) == [
        (1, "create-vpc-association-authorization", OTHER, ALT, "vpc-b", False),
        (2, "associate-vpc-with-hosted-zone", SPOKE, ALT, "vpc-b", False),
        (3, "disassociate-vpc-from-hosted-zone", SPOKE, OLD, "vpc-b", False),
        (4, "delete-vpc-association-authorization", OTHER, ALT, "vpc-b", False),
    ]
    assert any("Cross-account" in w for w in p["warnings"])
    script = p["script"]
    assert "run as PHZ owner account 333333333333" in script and "run as VPC owner account 222222222222" in script
    assert "account 222222222222" in script and "# Target PHZ: Z0NEW" not in script


def test_same_name_disassociates_first_back_to_back():
    p = run(base_data(), [pick(OLD, "vpc-b"), pick(OLD, "vpc-c")], target={"zone_id": NEW, "name": "corp.internal", "owner": OTHER})
    assert not p["errors"]
    phase2 = [(s["action"], s["vpc_id"]) for s in p["steps"] if s["phase"] == 2]
    assert phase2 == [
        ("disassociate-vpc-from-hosted-zone", "vpc-b"), ("associate-vpc-with-hosted-zone", "vpc-b"),
        ("disassociate-vpc-from-hosted-zone", "vpc-c"), ("associate-vpc-with-hosted-zone", "vpc-c"),
    ]
    assert any("Same-name" in w for w in p["warnings"])


def test_same_name_requires_disassociation():
    p = run(base_data(), [pick(OLD, "vpc-b")], target={"zone_id": NEW, "name": "corp.internal", "owner": OTHER}, disassociate=False)
    assert any("must be disassociated first" in e for e in p["errors"])


def test_unselected_same_name_zone_blocks():
    d = base_data()
    d["associations"].append(assoc("Z0DUP0000000001", "new.internal", HUB, "vpc-b", SPOKE))
    p = run(d, [pick(OLD, "vpc-b")], target={"zone_id": ALT, "name": "new.internal", "owner": OTHER})
    assert any("ConflictingDomainExists" in e for e in p["errors"])


def test_last_vpc_is_never_disassociated():
    d = base_data()
    d["zones"][0]["vpc_count"] = 2  # vpc-a and vpc-b only
    d["associations"] = [a for a in d["associations"] if a["vpc_id"] != "vpc-c"]
    p = run(d, [pick(OLD, "vpc-a"), pick(OLD, "vpc-b")], target={"zone_id": ALT, "name": "new.internal", "owner": OTHER})
    dis = [(s["vpc_id"], s["skipped"]) for s in p["steps"] if s["action"] == "disassociate-vpc-from-hosted-zone"]
    assert dis[0] == ("vpc-a", "") and "last VPC" in dis[1][1]
    assert "# SKIP disassociate-vpc-from-hosted-zone" in p["script"]


def test_same_name_last_vpc_blocks_the_move():
    d = base_data()
    d["zones"][0]["vpc_count"] = 1
    d["associations"] = [assoc(OLD, "corp.internal", HUB, "vpc-b", SPOKE)]
    p = run(d, [pick(OLD, "vpc-b")], target={"zone_id": NEW, "name": "corp.internal", "owner": OTHER})
    assert any("can't move" in e for e in p["errors"])


def test_same_account_needs_no_authorization_and_existing_ones_are_reused():
    p = run(base_data(), [pick(OLD, "vpc-a")], target={"zone_id": OLD.replace("OLD", "HUB"), "name": "x.internal", "owner": HUB})
    assert [s["action"] for s in p["steps"]] == ["associate-vpc-with-hosted-zone", "disassociate-vpc-from-hosted-zone"]

    d = base_data()
    d["associations"].append(assoc(ALT, "new.internal", OTHER, "vpc-b", SPOKE, status="authorized-pending"))
    p = run(d, [pick(OLD, "vpc-b")], target={"zone_id": ALT, "name": "new.internal", "owner": OTHER})
    create = [s for s in p["steps"] if s["action"] == "create-vpc-association-authorization"][0]
    assert create["skipped"] == "authorization already exists"


def test_unknown_owners_need_input_and_profiles_are_applied():
    d = base_data()
    d["associations"][1]["vpc_owner"] = "unknown"
    target = {"zone_id": ALT, "name": "new.internal", "owner": OTHER}
    p = run(d, [pick(OLD, "vpc-b")], target=target)
    assert any("Enter the account that owns vpc-b" in e for e in p["errors"])
    p = run(d, [pick(OLD, "vpc-b")], target=target, vpcOwners={"vpc-b": SPOKE}, profiles={SPOKE: "spoke-adm", OTHER: "it's"})
    assert not p["errors"]
    assert "--profile spoke-adm" in p["script"] and "--profile 'it'\\''s'" in p["script"]
    p = run(d, [pick(OLD, "vpc-b")], target={**target, "owner": ""})
    assert any("owns the target PHZ" in e for e in p["errors"])


def test_disassociate_as_phz_owner_and_stale_source_authorization():
    d = base_data()
    d["associations"].append(assoc(OLD, "corp.internal", HUB, "vpc-b", SPOKE, status="authorized"))
    p = run(d, [pick(OLD, "vpc-b")], target={"zone_id": ALT, "name": "new.internal", "owner": OTHER}, disassociateAs="phz")
    dis = [s for s in p["steps"] if s["action"] == "disassociate-vpc-from-hosted-zone"][0]
    assert dis["account"] == HUB and dis["side"] == "phz"
    assert (4, "delete-vpc-association-authorization", HUB, OLD, "vpc-b", False) in actions(p)


def test_incomplete_data_warns():
    d = base_data(vpc_counts_complete=False, authorizations_listed=False)
    p = run(d, [pick(OLD, "vpc-b")], target={"zone_id": ALT, "name": "new.internal", "owner": OTHER})
    assert any("last VPC" in w for w in p["warnings"]) and any("weren't listed" in w for w in p["warnings"])


def test_page_scripts_parse(tmp_path):
    page = phz_html.render_html({"command": "zones", "scope": HUB, "zones": [], "associations": [], "notes": ["</script>"]})
    assert page.count("<script>") == 1
    script = page.split("<script>", 1)[1].split("</script>", 1)[0]
    f = tmp_path / "page.js"
    f.write_text(script)
    subprocess.run([NODE, "--check", str(f)], check=True)
