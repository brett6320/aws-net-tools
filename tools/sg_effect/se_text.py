"""Plain-text rendering of an sg_effect analysis (stdout)."""
from __future__ import annotations

IN, OUT = "inbound", "outbound"


def group_label(gid: str, names: dict[str, str]) -> str:
    return f"{gid} ({names[gid]})" if names.get(gid) else gid


def resource_label(res: dict) -> str:
    return f"{res['kind']} {res['id']}" + (f" ({res['name']})" if res.get("name") else "")


def _grants(entry: dict) -> str:
    return ", ".join(dict.fromkeys(g["group"] for g in entry["grants"]))


def _scenario(lines: list[str], title: str, block: dict, names: dict[str, str]) -> None:
    lines.append(f"   {title}")
    any_line = False
    for d in (IN, OUT):
        for item in block.get(d) or []:
            any_line = True
            if item["lost"]:
                lead = "loses" if not item.get("partly") else "partly loses"
                for i, text in enumerate(item["lost"]):
                    lines.append(f"     {lead if i == 0 else ' ' * len(lead)} {d} {text}"
                                 + (f"   [{item['rule']}]" if i == 0 else ""))
            else:
                by = "; ".join(k["text"] + (f" [{group_label(k['group'], names)}]" if k.get("group") else "")
                               for k in item["kept_by"])
                lines.append(f"     keeps {item['text']}   (still allowed by {by})")
    for item in block.get("as_peer") or []:
        any_line = True
        lines.append(f"     {item['text']}")
    if not any_line:
        lines.append("     no change")


def render(result: dict) -> str:
    """The terminal view. Rule-removal scenarios (--remove-rule) are left out: they're only
    in the HTML report."""
    t = result["target"]
    names = {}
    for res in result["resources"]:
        names.update(res.get("group_names") or {})
    names.setdefault(t["id"], t.get("name") or "")
    lines = [f"Security group {group_label(t['id'], names)}, {t.get('vpc') or '?'}, account "
             f"{result.get('account') or '?'}, {result.get('region')}"]
    if t.get("description"):
        lines.append(f"  {t['description']}")
    lines.append(f"  {len(t['rules'])} rules:")
    lines += [f"    {r['id']}  {r['text']}" + (f"   \"{r['description']}\"" if r.get("description") else "")
              for r in t["rules"]]

    res_list = result["resources"]
    lines += ["", f"Resources using {t['id']}: {len(res_list)}" if res_list
              else f"No resources use {t['id']}."]
    for res in res_list:
        lines += ["", f"== {resource_label(res)}" + ("   (ENIs with different groups are listed separately)"
                                                     if res.get("split") else "")]
        for e in res["enis"]:
            ips = ", ".join(e.get("private_ips") or []) + (f", public {e['public_ip']}" if e.get("public_ip") else "")
            lines.append(f"   ENI {e['id']}  {ips}  {e.get('subnet') or ''}".rstrip())
        lines.append("   Groups: " + ", ".join(group_label(g, names) + (" [target]" if g == t["id"] else "")
                                             for g in res["groups"]))
        for d in (IN, OUT):
            entries = res["effective"][d]
            lines.append(f"   {d.capitalize()} ({len(entries)}):" if entries else f"   {d.capitalize()}: nothing allowed")
            width = max((len(f"{e['traffic']} {'to' if d == OUT else 'from'} {e['peer']}") for e in entries), default=0)
            for e in entries:
                what = f"{e['traffic']} {'to' if d == OUT else 'from'} {e['peer']}"
                note = ""
                if e["covered_by"]:
                    note = f"   (covered by {e['covered_by'][0]['text']})"
                lines.append(f"   {'*' if e['from_target'] else ' '} {what:<{width}}  {_grants(e)}{note}")
        _scenario(lines, f"If {t['id']} is removed from it:", res["remove_sg"], names)
    if res_list:
        lines += ["", "   * = allowed by the target group"]

    if res_list and t["rules"]:
        lines += ["", f"Target rules across {len(res_list)} resource{'s' if len(res_list) != 1 else ''}:"]
        for s in result["rule_summary"]:
            u, r = len(s["unique_on"]), len(s["redundant_on"])
            verdict = (f"redundant on all {r}: removing it changes no access" if not u
                       else f"only rule allowing it on {u}" + (f", redundant on {r}" if r else ""))
            lines.append(f"    {s['rule']}  {s['text']}: {verdict}")

    if result["referencing"]:
        lines += ["", f"Groups whose rules reference {t['id']}:"]
        for g in result["referencing"]:
            n = len(g["resources"])
            lines.append(f"    {group_label(g['group'], {g['group']: g['name']})}, used by {n} other "
                         f"resource{'s' if n != 1 else ''}:")
            lines += [f"      {r}" for r in g["rules"]]
    for w in result["warnings"]:
        lines.append(f"\n% {w}")
    return "\n".join(lines) + "\n"
