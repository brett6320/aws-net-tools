"""Plan and apply against an in-memory EC2 where each account keeps its own tags on shared resources."""
import io
import json

import pytest
from botocore.exceptions import ClientError

import name_tag_sync as nts
import nts_core as core

OWNER, PART, OTHER = "111111111111", "222222222222", "333333333333"
REGION = "us-east-1"


def client_error(code, op="CreateTags"):
    return ClientError({"Error": {"Code": code, "Message": code}}, op)


# --------------------------------------------------------------------------- fakes


class World:
    """Resources (id -> kind, vpc, owner, cidr), which accounts see each, and each account's Name tags."""

    def __init__(self):
        self.res = {}
        self.visible = {}  # account -> set of ids
        self.tags = {}  # (account, id) -> Name (missing key = no tag)
        self.writes = []  # (account, kwargs) of every create_tags call, DryRun included
        self.deny = set()  # ids whose create_tags is UnauthorizedOperation
        self.dry_run_error = set()  # ids whose DryRun create_tags fails with some other error
        self.before_write = None  # hook(world) run by describe calls made during recheck

    def add(self, rid, kind, vpc, owner, seen_by, names, cidr="10.0.0.0/16"):
        self.res[rid] = {"kind": kind, "vpc": vpc, "owner": owner, "cidr": cidr}
        for acct in seen_by:
            self.visible.setdefault(acct, set()).add(rid)
        for acct, name in names.items():
            self.tags[(acct, rid)] = name

    def item(self, account, rid):
        r = self.res[rid]
        key = "VpcId" if r["kind"] == "vpc" else "SubnetId"
        out = {key: rid, "VpcId": r["vpc"], "OwnerId": r["owner"], "CidrBlock": r["cidr"]}
        if (account, rid) in self.tags:
            out["Tags"] = [{"Key": "Env", "Value": "x"}, {"Key": "Name", "Value": self.tags[(account, rid)]}]
        return out


class Ec2:
    def __init__(self, world, account, page_size=2):
        self.w, self.account, self.page_size = world, account, page_size

    def _list(self, kind, ids=None, vpcs=None):
        out = []
        for rid in sorted(self.w.visible.get(self.account, ())):
            r = self.w.res[rid]
            if r["kind"] != kind or (ids and rid not in ids) or (vpcs and r["vpc"] not in vpcs):
                continue
            out.append(self.w.item(self.account, rid))
        return out

    def get_paginator(self, op):
        ec2 = self

        class P:
            def paginate(self, Filters=None):
                vpcs = Filters[0]["Values"] if Filters else None
                kind, key = ("vpc", "Vpcs") if op == "describe_vpcs" else ("subnet", "Subnets")
                items = ec2._list(kind, vpcs=vpcs)
                for i in range(0, max(len(items), 1), ec2.page_size):
                    yield {key: items[i:i + ec2.page_size]}

        return P()

    def describe_vpcs(self, VpcIds):
        if self.w.before_write:
            self.w.before_write(self.w)
        return {"Vpcs": self._list("vpc", ids=VpcIds)}

    def describe_subnets(self, SubnetIds):
        if self.w.before_write:
            self.w.before_write(self.w)
        return {"Subnets": self._list("subnet", ids=SubnetIds)}

    def create_tags(self, Resources, Tags, DryRun=False):
        self.w.writes.append((self.account, {"Resources": Resources, "Tags": Tags, "DryRun": DryRun}))
        if Resources[0] in self.w.deny:
            raise client_error("UnauthorizedOperation")
        if DryRun and Resources[0] in self.w.dry_run_error:
            raise client_error("InternalError")
        if DryRun:
            raise client_error("DryRunOperation")
        for t in Tags:
            self.w.tags[(self.account, Resources[0])] = t["Value"]


class Sts:
    def __init__(self, session):
        self.s = session

    def get_caller_identity(self):
        return {"Account": self.s.account}


class Session:
    def __init__(self, world, account, region=REGION):
        self.w, self.account, self.region_name = world, account, region

    def client(self, name, region_name=None, config=None):
        return Sts(self) if name == "sts" else Ec2(self.w, self.account)


@pytest.fixture
def world():
    w = World()
    # A VPC owned by OWNER, shared with PART through two of its three subnets.
    w.add("vpc-00000001", "vpc", "vpc-00000001", OWNER, [OWNER, PART], {OWNER: "prod-vpc"})
    w.add("subnet-0001", "subnet", "vpc-00000001", OWNER, [OWNER, PART], {OWNER: "prod-a"})  # PART: none -> set
    w.add("subnet-0002", "subnet", "vpc-00000001", OWNER, [OWNER, PART], {OWNER: "prod-b", PART: ""})  # empty -> set
    w.add("subnet-0003", "subnet", "vpc-00000001", OWNER, [OWNER], {OWNER: "prod-c"})  # not shared
    w.add("subnet-0004", "subnet", "vpc-00000001", OWNER, [OWNER, PART], {OWNER: "prod-d", PART: "mine"})  # populated
    w.add("subnet-0005", "subnet", "vpc-00000001", OWNER, [OWNER, PART], {PART: ""})  # owner has no name
    w.add("subnet-0006", "subnet", "vpc-00000001", OWNER, [OWNER, PART], {OWNER: "prod-f", PART: " "})  # whitespace
    w.add("subnet-0007", "subnet", "vpc-00000001", OWNER, [OWNER, PART], {OWNER: "prod-g", PART: "prod-g"})  # same
    # The participant's own VPC (only it sees it).
    w.add("vpc-00000002", "vpc", "vpc-00000002", PART, [PART], {})
    return w


def sessions(world):
    made = {"own": Session(world, OWNER), "part": Session(world, PART)}
    return lambda profile: made[profile]


def run(world, *args, ask=None, interactive=True, capsys=None):
    argv = ["--owner-profile", "own", "--participant-profile", "part", *args]
    answers = iter(ask or [])
    code = nts.main(argv, session_for=sessions(world), ask=lambda q: next(answers, "q"),
                    interactive=lambda: interactive)
    return code


def accounts(world):
    o = core.Account("owner", "own", OWNER, Session(world, OWNER))
    p = core.Account("participant", "part", PART, Session(world, PART))
    return o, p


def planned(world, vpc_ids=None):
    o, p = accounts(world)
    items, errors = core.build_plan(o, p, [REGION], vpc_ids)
    assert errors == []
    return {i.resource_id: i for i in items}, o, p


def real_writes(world):
    return [w for w in world.writes if not w[1]["DryRun"]]


# --------------------------------------------------------------------------- core helpers


def test_name_tag_and_unset():
    assert core.name_tag(None) is None
    assert core.name_tag([{"Key": "Env", "Value": "x"}]) is None
    assert core.name_tag([{"Key": "Name", "Value": ""}]) == ""
    assert core.is_unset(None) and core.is_unset("")
    assert not core.is_unset(" ") and not core.is_unset("a")


def test_show_escapes_control_characters():
    assert core.show(None) == "(none)"
    assert core.show("") == '""'
    assert core.show(" ") == '" "'
    shown = core.show("evil\x1b[2J\x1b[Hname\r\n")
    assert "\x1b" not in shown and "\r" not in shown and "\n" not in shown
    assert "\\x1b" in shown
    shown = core.show("a\u202eb\u200bc\u2028d")
    assert shown == "a\\u202eb\\u200bc\\u2028d"


def test_input_validation():
    assert core.split_csv(["a,b", "b", " c "]) == ["a", "b", "c"]
    with pytest.raises(ValueError):
        core.check_regions(["useast1"])
    with pytest.raises(ValueError):
        core.check_vpc_ids(["subnet-1234abcd"])


# --------------------------------------------------------------------------- plan


def test_plan_actions(world):
    items, _, _ = planned(world)
    assert set(items) == {"vpc-00000001", "subnet-0001", "subnet-0002", "subnet-0004", "subnet-0005",
                          "subnet-0006", "subnet-0007"}
    assert items["vpc-00000001"].action == core.SET
    assert items["subnet-0001"].action == core.SET and items["subnet-0001"].target_name is None
    assert items["subnet-0002"].action == core.SET and items["subnet-0002"].target_name == ""
    assert items["subnet-0004"].action == core.SKIP_POPULATED
    assert items["subnet-0005"].action == core.SKIP_NO_SOURCE
    assert items["subnet-0006"].action == core.SKIP_WHITESPACE
    assert items["subnet-0007"].action == core.SKIP_SAME
    assert all(i.target == PART for i in items.values() if i.action == core.SET)


def add_third_party(world):
    # A VPC a third account shares with both.
    world.add("vpc-00000009", "vpc", "vpc-00000009", OTHER, [OWNER, PART], {OWNER: "x"})
    world.add("subnet-0009", "subnet", "vpc-00000009", OTHER, [OWNER, PART], {})


def test_third_party_owner_raises(world):
    add_third_party(world)
    with pytest.raises(core.OwnerMismatch, match="owned by 333333333333"):
        planned(world)


def test_plan_vpc_filter_covers_subnets(world):
    add_third_party(world)
    items, _, _ = planned(world, ["vpc-00000001"])
    assert "vpc-00000009" not in items and "subnet-0009" not in items
    assert {"vpc-00000001", "subnet-0001"} <= set(items)


def test_participant_owned_shared_resource_raises(world):
    world.add("vpc-00000003", "vpc", "vpc-00000003", PART, [OWNER, PART], {PART: "theirs"})
    with pytest.raises(core.OwnerMismatch, match="owned by 222222222222"):
        planned(world)


def test_swapped_profiles_raise(world):
    o, p = accounts(world)
    with pytest.raises(core.OwnerMismatch):
        core.build_plan(p, o, [REGION])


def test_owner_disagreement_raises(world):
    o, p = accounts(world)

    def reader(session, region, vpc_ids):
        views = core.read_views(session, region, vpc_ids)
        if session.account == PART:
            v = views["subnet-0001"]
            views["subnet-0001"] = core.View(v.kind, v.resource_id, v.vpc_id, OTHER, v.name)
        return views

    with pytest.raises(core.OwnerMismatch, match="participant sees"):
        core.build_plan(o, p, [REGION], reader=reader)


def test_same_account_raises(world):
    o, _ = accounts(world)
    with pytest.raises(core.OwnerMismatch, match="both account"):
        core.build_plan(o, core.Account("participant", "own2", OWNER, o.session), [REGION])


def test_region_read_error_is_reported(world):
    o, p = accounts(world)

    def reader(session, region, vpc_ids):
        if region == "eu-west-1":
            raise client_error("AuthFailure", "DescribeVpcs")
        return core.read_views(session, region, vpc_ids)

    items, errors = core.build_plan(o, p, [REGION, "eu-west-1"], reader=reader)
    assert items and errors == ["eu-west-1: AuthFailure: AuthFailure"]


# --------------------------------------------------------------------------- write guards


def test_apply_item_writes_only_name_in_participant(world):
    items, o, p = planned(world)
    core.apply_item(items["subnet-0001"], o, p)
    assert real_writes(world) == [(PART, {"Resources": ["subnet-0001"], "Tags": [{"Key": "Name", "Value": "prod-a"}],
                                          "DryRun": False})]
    assert world.tags[(PART, "subnet-0001")] == "prod-a"
    assert world.tags[(OWNER, "subnet-0001")] == "prod-a"


@pytest.mark.parametrize("rid", ["subnet-0004", "subnet-0005", "subnet-0006", "subnet-0007"])
def test_apply_item_refuses_unplanned(world, rid):
    items, o, p = planned(world)
    with pytest.raises(core.SafetyError):
        core.apply_item(items[rid], o, p)
    assert world.writes == []


def test_apply_item_refuses_owner_as_target(world):
    items, o, p = planned(world)
    with pytest.raises(core.OwnerMismatch):
        core.apply_item(items["subnet-0001"], o, o)  # owner passed as the participant
    item = items["subnet-0001"]
    item.target = OWNER
    with pytest.raises(core.OwnerMismatch):
        core.apply_item(item, o, core.Account("participant", "x", OWNER, o.session))
    assert world.writes == []


def test_apply_item_rechecks_participant_name(world):
    items, o, p = planned(world)
    world.tags[(PART, "subnet-0001")] = "set meanwhile"
    with pytest.raises(core.SafetyError, match="participant Name is now"):
        core.apply_item(items["subnet-0001"], o, p)
    assert world.writes == []


def test_apply_item_rechecks_owner_name(world):
    items, o, p = planned(world)
    world.tags[(OWNER, "subnet-0001")] = "renamed"
    with pytest.raises(core.SafetyError, match="owner Name changed"):
        core.apply_item(items["subnet-0001"], o, p)
    assert world.writes == []


def test_apply_item_rechecks_owner(world):
    items, o, p = planned(world)
    world.res["subnet-0001"]["owner"] = PART
    with pytest.raises(core.OwnerMismatch, match="owner is now"):
        core.apply_item(items["subnet-0001"], o, p)
    assert world.writes == []


def test_apply_item_rechecks_identity(world):
    items, o, p = planned(world)
    p.session.account = OTHER
    with pytest.raises(core.OwnerMismatch, match="now authenticates"):
        core.apply_item(items["subnet-0001"], o, p)
    assert world.writes == []


def test_apply_item_resource_gone(world):
    items, o, p = planned(world)
    world.visible[PART].discard("subnet-0001")
    with pytest.raises(core.SafetyError, match="no longer visible"):
        core.apply_item(items["subnet-0001"], o, p)


def test_check_permission(world):
    items, o, p = planned(world)
    assert core.check_permission(items["subnet-0001"], o, p) == "allowed"
    world.deny.add("subnet-0002")
    assert core.check_permission(items["subnet-0002"], o, p) == "denied: UnauthorizedOperation"
    assert real_writes(world) == [] and all(acct == PART for acct, _ in world.writes)
    assert PART not in {a for a, r in world.tags if r == "subnet-0001"}


# --------------------------------------------------------------------------- CLI


def test_dry_run_writes_nothing(world, capsys):
    assert run(world) == 0
    out = capsys.readouterr().out
    assert "subnet-0001" in out and "set" in out and "skip: name already set" in out
    assert world.writes == []


def test_dry_run_json(world, capsys):
    assert run(world, "--json") == 0
    rows = json.loads(capsys.readouterr().out)
    assert {r["resource_id"] for r in rows if r["action"] == "set"} == {"vpc-00000001", "subnet-0001", "subnet-0002"}
    assert world.writes == []


def test_check_permissions_flag(world, capsys):
    world.deny.add("subnet-0002")
    assert run(world, "--check-permissions", "-o", "csv") == nts.ERROR_EXIT
    out = capsys.readouterr().out
    assert "allowed" in out and "denied: UnauthorizedOperation" in out
    assert real_writes(world) == []


def test_apply_with_check_permissions(world, capsys):
    assert run(world, "--apply", "--check-permissions", ask=["y", "y", "y"]) == 0
    out = capsys.readouterr().out
    assert "allowed" in out and "tagged" in out and "denied" not in out
    assert len(real_writes(world)) == 3


def test_apply_skips_denied(world, capsys):
    world.deny.add("subnet-0002")
    asked = []

    def ask(q):
        asked.append(q)
        return "y"

    code = nts.main(["--owner-profile", "own", "--participant-profile", "part", "--apply", "--check-permissions"],
                    session_for=sessions(world), ask=ask, interactive=lambda: True)
    assert code == nts.ERROR_EXIT
    assert not any("subnet-0002" in q for q in asked) and len(asked) == 2
    assert "not asked (denied)" in capsys.readouterr().out
    assert [w[1]["Resources"] for w in real_writes(world)] == [["vpc-00000001"], ["subnet-0001"]]


def test_apply_interrupted_mid_write(world, capsys, monkeypatch):
    def boom(item, owner, participant):
        raise KeyboardInterrupt

    monkeypatch.setattr(core, "apply_item", boom)
    assert run(world, "--apply", "-o", "json", ask=["y"]) == nts.ERROR_EXIT
    rows = {r["resource_id"]: r for r in json.loads(capsys.readouterr().out)}
    assert rows["vpc-00000001"]["result"].startswith("interrupted")
    assert rows["subnet-0001"]["result"] == "not asked (quit)"


def test_apply_requires_terminal(world):
    assert run(world, "--apply", interactive=False) == nts.USAGE_EXIT
    assert world.writes == []


def test_apply_confirms_each(world, capsys):
    # Order: vpc-00000001, subnet-0001, subnet-0002
    assert run(world, "--apply", ask=["y", "n", "yes"]) == 0
    assert world.tags[(PART, "vpc-00000001")] == "prod-vpc"
    assert (PART, "subnet-0001") not in world.tags
    assert world.tags[(PART, "subnet-0002")] == "prod-b"
    assert world.tags[(PART, "subnet-0004")] == "mine"
    assert all(acct == PART for acct, _ in world.writes) and len(world.writes) == 2
    out = capsys.readouterr().out
    assert "tagged" in out and "declined" in out


def test_apply_quit_stops(world, capsys):
    assert run(world, "--apply", ask=["y", "q"]) == 0
    assert len(world.writes) == 1
    assert "not asked (quit)" in capsys.readouterr().out


def test_apply_eof_is_quit(world, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    assert nts.tty_ask("? ") == "q"


def test_apply_unauthorized_continues(world, capsys):
    world.deny.add("subnet-0001")
    assert run(world, "--apply", ask=["y", "y", "y"]) == nts.ERROR_EXIT
    assert world.tags[(PART, "vpc-00000001")] == "prod-vpc"
    assert world.tags[(PART, "subnet-0002")] == "prod-b"
    assert "error: UnauthorizedOperation" in capsys.readouterr().out


def test_apply_owner_change_stops_run(world, capsys):
    def flip(w):
        w.res["subnet-0001"]["owner"] = PART

    answers = iter(["y", "y", "y"])

    def ask(q):
        if "subnet-0001" in q:
            world.before_write = flip
        return next(answers)

    code = nts.main(["--owner-profile", "own", "--participant-profile", "part", "--apply"],
                    session_for=sessions(world), ask=ask, interactive=lambda: True)
    assert code == nts.MISMATCH_EXIT
    assert [w[1]["Resources"] for w in world.writes] == [["vpc-00000001"]]
    assert "not asked (stopped)" in capsys.readouterr().out


def test_cli_mismatch_changes_nothing(world):
    world.add("subnet-0008", "subnet", "vpc-00000001", PART, [OWNER, PART], {})
    assert run(world, "--apply", ask=["y"] * 5) == nts.MISMATCH_EXIT
    assert world.writes == []


def test_cli_usage_errors(world):
    assert nts.main([], session_for=sessions(world)) == nts.USAGE_EXIT
    assert run(world, "--regions", "nope") == nts.USAGE_EXIT
    assert nts.main(["--owner-profile", "own", "--participant-profile", "own"]) == nts.USAGE_EXIT


def test_cli_no_region(world):
    s = sessions(world)
    s("part").region_name = None
    assert nts.main(["--owner-profile", "own", "--participant-profile", "part"], session_for=s) == nts.USAGE_EXIT


def test_prompt_shows_escaped_values(world):
    items, o, p = planned(world)
    item = items["subnet-0001"]
    item.source_name = "x\x1b[31mred"
    text = nts.prompt_text(item, p)
    assert "\x1b" not in text and "subnet-0001" in text and "222222222222" in text


def test_table_marks_nothing_shared(capsys):
    nts.render([], "table")
    assert "no VPCs or subnets shared" in capsys.readouterr().out


# --------------------------------------------------------------------------- color and emojis


def test_table_emojis_and_alignment(world, capsys):
    assert run(world, "--color", "never") == 0
    lines = capsys.readouterr().out.splitlines()
    assert "\033[" not in "\n".join(lines)
    by_id = {line.split()[2]: line for line in lines[2:]}
    assert "❌ set" in by_id["subnet-0001"]
    assert "✅ skip: names match" in by_id["subnet-0007"]
    assert "🔶 skip: name already set" in by_id["subnet-0004"]
    assert "🔶 skip: name is whitespace" in by_id["subnet-0006"]
    assert "➖ skip: owner has no name" in by_id["subnet-0005"]
    # The ACTION column starts at the same terminal column on every row.
    col = nts.width(lines[0][:lines[0].index("ACTION")])
    for line in lines[2:]:
        start = min(line.index(e) for e in ("❌", "✅", "🔶", "➖") if e in line)
        assert nts.width(line[:start]) == col


def test_no_emoji(world, capsys):
    assert run(world, "--no-emoji") == 0
    out = capsys.readouterr().out
    assert not any(e in out for e in ("❌", "✅", "🔶", "➖"))


def test_color_always(world, capsys):
    assert run(world, "--color", "always", "--apply", ask=["y", "n", "q"]) == 0
    out = capsys.readouterr().out
    assert nts.GREEN + "✅ tagged" + nts.RESET in out
    assert nts.DIM + "➖ declined" + nts.RESET in out
    assert nts.RED + "❌ set" + nts.RESET in out
    assert nts.BOLD + "REGION" in out


def test_color_auto(monkeypatch):
    class Tty(io.StringIO):
        def isatty(self):
            return True

    assert nts.use_color("auto", Tty()) is True
    assert nts.use_color("auto", io.StringIO()) is False
    assert nts.use_color("always", io.StringIO()) is True
    assert nts.use_color("never", Tty()) is False
    monkeypatch.setenv("NO_COLOR", "1")
    assert nts.use_color("auto", Tty()) is False


def test_machine_output_has_no_styling(world, capsys):
    assert run(world, "--color", "always", "-o", "csv") == 0
    out = capsys.readouterr().out
    assert "\033[" not in out and "❌" not in out


@pytest.mark.parametrize("text, emoji", [
    ("tagged", "✅"), ("allowed", "✅"), ("denied: UnauthorizedOperation", "⛔"), ("not asked (denied)", "⛔"),
    ("error: x", "❌"), ("stopped: owner mismatch", "❌"), ("interrupted (check its Name tag)", "⚡"),
    ("skipped: x", "🔶"), ("declined", "➖"), ("not asked (quit)", "➖"),
    ("not asked (permission error: x)", "⛔")])
def test_outcome_style(text, emoji):
    assert nts.outcome_style(text)[0] == emoji


def test_prompt_styled(world):
    items, o, p = planned(world)
    text = nts.prompt_text(items["subnet-0001"], p, nts.Style(color=True, emoji=True))
    assert "❌" in text and nts.GREEN + nts.BOLD + "prod-a" + nts.RESET in text
    assert "\033[" not in nts.prompt_text(items["subnet-0001"], p)


# --------------------------------------------------------------------------- --force


def test_force_requires_apply(world):
    assert run(world, "--force") == nts.USAGE_EXIT
    assert world.writes == []


def test_force_writes_without_asking_or_terminal(world, capsys):
    def ask(q):
        raise AssertionError("--force must not prompt")

    code = nts.main(["--owner-profile", "own", "--participant-profile", "part", "--apply", "--force"],
                    session_for=sessions(world), ask=ask, interactive=lambda: False)
    assert code == 0
    assert sorted(w[1]["Resources"][0] for w in real_writes(world)) == ["subnet-0001", "subnet-0002", "vpc-00000001"]
    assert all(acct == PART for acct, _ in world.writes)
    # Populated, whitespace, matching and no-owner-name resources are untouched; owner tags unchanged.
    assert world.tags[(PART, "subnet-0004")] == "mine"
    assert world.tags[(PART, "subnet-0006")] == " "
    assert world.tags[(PART, "subnet-0005")] == ""
    assert world.tags[(OWNER, "subnet-0001")] == "prod-a"
    assert "tagged" in capsys.readouterr().out


def test_force_still_stops_on_owner_mismatch(world):
    world.add("subnet-0008", "subnet", "vpc-00000001", PART, [OWNER, PART], {})
    assert run(world, "--apply", "--force", interactive=False) == nts.MISMATCH_EXIT
    assert world.writes == []


def test_force_still_rechecks(world, capsys):
    def set_meanwhile(w):
        w.tags[(PART, "subnet-0001")] = "set meanwhile"

    world.before_write = set_meanwhile
    assert run(world, "--apply", "--force", interactive=False) == nts.ERROR_EXIT
    assert world.tags[(PART, "subnet-0001")] == "set meanwhile"
    assert "skipped" in capsys.readouterr().out


def test_force_skips_denied(world):
    world.deny.add("subnet-0002")
    assert run(world, "--apply", "--force", "--check-permissions", interactive=False) == nts.ERROR_EXIT
    assert sorted(w[1]["Resources"][0] for w in real_writes(world)) == ["subnet-0001", "vpc-00000001"]


def test_force_skips_permission_errors(world, capsys):
    world.dry_run_error.add("subnet-0001")
    assert run(world, "--apply", "--force", "--check-permissions", "-o", "json", interactive=False) == nts.ERROR_EXIT
    rows = {r["resource_id"]: r for r in json.loads(capsys.readouterr().out)}
    assert rows["subnet-0001"]["result"] == "not asked (permission error: InternalError: InternalError)"
    assert sorted(w[1]["Resources"][0] for w in real_writes(world)) == ["subnet-0002", "vpc-00000001"]


def test_interactive_still_asks_on_permission_error(world):
    world.dry_run_error.add("subnet-0001")
    asked = []
    nts.main(["--owner-profile", "own", "--participant-profile", "part", "--apply", "--check-permissions"],
             session_for=sessions(world), ask=lambda q: asked.append(q) or "n", interactive=lambda: True)
    assert any("subnet-0001" in q for q in asked)


def test_force_warning_count_excludes_denied(world, caplog):
    world.deny.add("subnet-0002")
    run(world, "--apply", "--force", "--check-permissions", interactive=False)
    assert "tagging 2 resource(s)" in caplog.text
    assert "--force: us-east-1 subnet subnet-0001" in caplog.text


def test_force_owner_change_mid_run_stops(world):
    def flip(w):
        if any(r[1]["Resources"] == ["vpc-00000001"] for r in w.writes):
            w.res["subnet-0001"]["owner"] = PART

    world.before_write = flip
    assert run(world, "--apply", "--force", interactive=False) == nts.MISMATCH_EXIT
    assert [w[1]["Resources"] for w in real_writes(world)] == [["vpc-00000001"]]


def test_force_interrupt_after_write_is_recorded(world, capsys, monkeypatch):
    real = core.apply_item
    calls = []

    def apply_then_interrupt(item, owner, participant):
        real(item, owner, participant)
        calls.append(item.resource_id)
        if len(calls) == 2:
            raise KeyboardInterrupt

    monkeypatch.setattr(core, "apply_item", apply_then_interrupt)
    assert run(world, "--apply", "--force", "-o", "json", interactive=False) == nts.ERROR_EXIT
    rows = {r["resource_id"]: r for r in json.loads(capsys.readouterr().out)}
    assert rows["vpc-00000001"]["result"] == "tagged"
    assert rows["subnet-0001"]["result"].startswith("interrupted")
    assert rows["subnet-0002"]["result"] == "not asked (quit)"
