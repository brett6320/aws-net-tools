"""Turn the differences between a backup (the target) and the current configuration
into a reviewable shell script of AWS CLI commands. Nothing here calls AWS.

What can be put back through the API becomes a command: Direct Connect gateways and
their associations and allowed prefixes, VIFs and extra BGP peers, names, MTU,
SiteLink, LAG minimum links, encryption mode and tags. Physical connections and LAGs,
fields AWS can't change in place (VLAN, ASN, addresses, gateway, public prefixes) and
anything that would delete an object are written as comments with the command to use,
never as live lines. Routes are learned over BGP, so route differences are listed as
notes. BGP auth keys aren't in backups: the script asks for each one as an environment
variable and stops if it isn't set.
"""
from __future__ import annotations

import json
import re
import shlex
from typing import Any

import db_core as core
import db_diff

_VAR = re.compile(r"@@VAR:([A-Za-z_][A-Za-z0-9_]*)@@")


def var_name(prefix: str, ident: str) -> str:
    return prefix + "_" + re.sub(r"[^A-Za-z0-9]", "_", ident).upper()


def ref(name: str) -> str:
    return f"@@VAR:{name}@@"


def sh(value: Any) -> str:
    """Quote a CLI argument. Dicts and lists become JSON; @@VAR:NAME@@ markers become "$NAME"."""
    text = value if isinstance(value, str) else json.dumps(value, separators=(",", ":"))
    out, pos = [], 0
    for m in _VAR.finditer(text):
        if m.start() > pos:
            out.append(shlex.quote(text[pos:m.start()]))
        out.append(f'"${m.group(1)}"')
        pos = m.end()
    if pos < len(text) or not out:
        out.append(shlex.quote(text[pos:]))
    return "".join(out)


def cli(op: str, region: str | None, *args: tuple[str, Any] | str) -> str:
    parts = ["aws", "directconnect", op]
    if region:
        parts += ["--region", region]
    for a in args:
        if isinstance(a, str):
            parts.append(a)
        else:
            parts += [a[0], sh(a[1])]
    return " ".join(parts)


def partition(region: str | None) -> str:
    r = region or ""
    return "aws-cn" if r.startswith("cn-") else "aws-us-gov" if r.startswith("us-gov-") else "aws"


def arn(o: dict, account: str | None, default_region: str | None) -> str:
    item = o.get("item") or {}
    owner = item.get("ownerAccount") or account
    if o["kind"] == "dx-gateway":
        return f"arn:{partition(default_region)}:directconnect::{owner}:dx-gateway/{o['id']}"
    kind = {"connection": "dxcon", "lag": "dxlag", "vif": "dxvif"}[o["kind"]]
    region = o.get("region") or default_region
    return f"arn:{partition(region)}:directconnect:{region}:{owner}:{kind}/{o['id']}"


def _tags(item: dict | None) -> dict[str, str]:
    return {t.get("key"): t.get("value") for t in (item or {}).get("tags") or []}


def _comment(lines: list[str], text: str) -> None:
    lines += [f"# {t}" if t else "#" for t in text.splitlines()]


class Plan:
    def __init__(self, target: dict, current: dict):
        self.target, self.current = target, current
        self.account = target["manifest"].get("account")
        self.region = (target["manifest"].get("regions") or [None])[0]
        self.secrets: list[tuple[str, str]] = []      # (variable, what it is)
        self.creates: list[str] = []
        self.updates: list[str] = []
        self.manual: list[str] = []
        self.deletes: list[str] = []
        self.notes: list[str] = []
        self.gw_vars: dict[str, str] = {}

    def objs(self, snap: dict, kind: str) -> dict[str, dict]:
        return {o["id"]: o for o in snap["objects"].values() if o["kind"] == kind}

    # ----- tags -----
    def tag_lines(self, o: dict, want: dict[str, str], have: dict[str, str], arn_text: str | None = None) -> None:
        a = arn_text or arn(o, self.account, self.region)
        region = o.get("region") or self.region
        add = [{"key": k, "value": v} for k, v in sorted(want.items()) if have.get(k) != v]
        drop = sorted(k for k in have if k not in want)
        if add:
            self.updates.append(cli("tag-resource", region, ("--resource-arn", a), ("--tags", add)))
        if drop:
            self.updates.append(cli("untag-resource", region, ("--resource-arn", a), "--tag-keys",
                                    *[shlex.quote(k) for k in drop]))

    # ----- auth keys -----
    def auth_key(self, vif_id: str, value: Any, peer: str | None = None) -> str | None:
        if not core.is_fingerprint(value):
            return None
        name = var_name("BGP_AUTH_KEY", vif_id + ("_" + peer if peer else ""))
        if name not in [s[0] for s in self.secrets]:
            self.secrets.append((name, f"BGP MD5 key of {vif_id}" + (f" peer {peer}" if peer else "")))
        return ref(name)

    # ----- gateways -----
    def gateways(self) -> None:
        want, have = self.objs(self.target, "dx-gateway"), self.objs(self.current, "dx-gateway")
        for gid, o in want.items():
            item = o["item"]
            if gid not in have:
                v = self.gw_vars[gid] = var_name("DXGW", gid)
                args = [("--direct-connect-gateway-name", item.get("directConnectGatewayName") or gid)]
                if item.get("amazonSideAsn"):
                    args.append(("--amazon-side-asn", str(item["amazonSideAsn"])))
                if item.get("tags"):
                    args.append(("--tags", item["tags"]))
                self.creates += [f"# Direct Connect gateway {gid} ({item.get('directConnectGatewayName')})",
                                 f"{v}=$({cli('create-direct-connect-gateway', self.region, *args)} "
                                 f"--query directConnectGateway.directConnectGatewayId --output text)"]
                for assoc in o.get("associations") or []:
                    self.association(gid, ref(v), assoc, None, item)
                continue
            cur = have[gid]
            if item.get("directConnectGatewayName") != cur["item"].get("directConnectGatewayName"):
                self.updates.append(cli("update-direct-connect-gateway", self.region, ("--direct-connect-gateway-id", gid),
                                        ("--new-direct-connect-gateway-name", item.get("directConnectGatewayName"))))
            if str(item.get("amazonSideAsn")) != str(cur["item"].get("amazonSideAsn")):
                _comment(self.manual, f"{gid}: Amazon side ASN was {item.get('amazonSideAsn')}, now "
                                      f"{cur['item'].get('amazonSideAsn')}; it can't be changed. Recreate the gateway.")
            self.tag_lines(o, _tags(item), _tags(cur["item"]))
            key = db_diff._KEYS["associations"]
            cur_assoc = {key(a): a for a in cur.get("associations") or []}
            want_assoc = {key(a): a for a in o.get("associations") or []}
            for k, assoc in want_assoc.items():
                self.association(gid, gid, assoc, cur_assoc.get(k), item)
            for k, assoc in cur_assoc.items():
                if k not in want_assoc:
                    _comment(self.deletes, cli("delete-direct-connect-gateway-association", self.region,
                                               ("--association-id", assoc.get("associationId")))
                             + f"   # {gid} -> {k}, not in the backup")
            want_att = {a.get("virtualInterfaceId") for a in o.get("attachments") or []}
            cur_att = {a.get("virtualInterfaceId") for a in cur.get("attachments") or []}
            for vid in sorted(want_att - cur_att):
                if vid not in self.objs(self.target, "vif"):
                    _comment(self.manual, f"{gid}: VIF {vid} was attached (owned by another account?); "
                                          "re-create or re-accept it from the VIF owner's side.")
        for gid in have:
            if gid not in want:
                _comment(self.deletes, cli("delete-direct-connect-gateway", self.region,
                                           ("--direct-connect-gateway-id", gid)) + "   # not in the backup")

    def association(self, gid: str, gw_ref: str, assoc: dict, cur: dict | None, gw_item: dict) -> None:
        gateway = assoc.get("associatedGateway") or {}
        target_id = gateway.get("id") or assoc.get("virtualGatewayId")
        prefixes = [p.get("cidr") for p in assoc.get("allowedPrefixesToDirectConnectGateway") or []]
        owner = gateway.get("ownerAccount") or assoc.get("virtualGatewayOwnerAccount")
        if cur is None:
            if owner and gw_item.get("ownerAccount") and owner != gw_item.get("ownerAccount"):
                _comment(self.manual, f"{gid} -> {target_id} is owned by account {owner}: from that account, run\n  "
                         + cli("create-direct-connect-gateway-association-proposal", gateway.get("region"),
                               ("--direct-connect-gateway-id", gid),
                               ("--direct-connect-gateway-owner-account", gw_item.get("ownerAccount")),
                               ("--gateway-id", target_id),
                               "--add-allowed-prefixes-to-direct-connect-gateway",
                               *[f"cidr={p}" for p in prefixes]) + "\n  and accept the proposal here.")
                return
            args: list = [("--direct-connect-gateway-id", gw_ref), ("--gateway-id", target_id)]
            if prefixes:
                args += ["--add-allowed-prefixes-to-direct-connect-gateway", *[f"cidr={p}" for p in prefixes]]
            self.creates.append(cli("create-direct-connect-gateway-association", self.region, *args))
            return
        have = [p.get("cidr") for p in cur.get("allowedPrefixesToDirectConnectGateway") or []]
        add, drop = [p for p in prefixes if p not in have], [p for p in have if p not in prefixes]
        if add or drop:
            args = [("--association-id", cur.get("associationId"))]
            if add:
                args += ["--add-allowed-prefixes-to-direct-connect-gateway", *[f"cidr={p}" for p in add]]
            if drop:
                args += ["--remove-allowed-prefixes-to-direct-connect-gateway", *[f"cidr={p}" for p in drop]]
            self.updates.append(f"# {gid} -> {target_id}: allowed prefixes")
            self.updates.append(cli("update-direct-connect-gateway-association", self.region, *args))

    # ----- VIFs -----
    def vifs(self) -> None:
        want, have = self.objs(self.target, "vif"), self.objs(self.current, "vif")
        for vid, o in want.items():
            if vid not in have:
                self.create_vif(o)
            else:
                self.update_vif(o, have[vid])
        for vid, o in have.items():
            if vid not in want:
                _comment(self.deletes, cli("delete-virtual-interface", o.get("region"), ("--virtual-interface-id", vid))
                         + f"   # {core.object_name(o) or ''} not in the backup".rstrip())

    def _peers(self, item: dict) -> list[dict]:
        peers = item.get("bgpPeers") or []
        if not peers and item.get("customerAddress"):
            peers = [{k: item.get(k) for k in ("asn", "asnLong", "authKey", "addressFamily", "amazonAddress",
                                                "customerAddress")}]
        return peers

    @staticmethod
    def _asn(fields: dict, src: dict) -> None:
        asn = src.get("asnLong") or src.get("asn")
        if asn is not None:
            fields["asnLong" if int(asn) > 2147483647 else "asn"] = int(asn)

    def create_vif(self, o: dict) -> None:
        item, vid = o["item"], o["id"]
        vtype = (item.get("virtualInterfaceType") or "private").lower()
        owner = item.get("ownerAccount")
        peers = self._peers(item)
        first = next((p for p in peers if p.get("addressFamily") == item.get("addressFamily")), peers[0] if peers else {})
        spec: dict[str, Any] = {"virtualInterfaceName": item.get("virtualInterfaceName"), "vlan": item.get("vlan")}
        self._asn(spec, first or item)
        key = self.auth_key(vid, first.get("authKey") if first else item.get("authKey"))
        if key:
            spec["authKey"] = key
        for f in ("amazonAddress", "customerAddress", "addressFamily"):
            if first.get(f) or item.get(f):
                spec[f] = first.get(f) or item.get(f)
        if vtype in ("private", "transit") and item.get("mtu"):
            spec["mtu"] = item["mtu"]
        if vtype == "private" and item.get("virtualGatewayId"):
            spec["virtualGatewayId"] = item["virtualGatewayId"]
        gw = item.get("directConnectGatewayId")
        if vtype in ("private", "transit") and gw:
            spec["directConnectGatewayId"] = ref(self.gw_vars[gw]) if gw in self.gw_vars else gw
        if vtype == "public":
            spec["routeFilterPrefixes"] = item.get("routeFilterPrefixes") or []
        if vtype in ("private", "transit") and item.get("siteLinkEnabled") is not None:
            spec["enableSiteLink"] = bool(item.get("siteLinkEnabled"))
        for f in self.TUNABLE:
            if item.get(f) is not None and (vtype != "public" or f == "rateLimit"):
                spec[f] = item[f]
        if item.get("tags"):
            spec["tags"] = item["tags"]
        op, param = f"create-{vtype}-virtual-interface", f"--new-{vtype}-virtual-interface"
        v = var_name("VIF", vid)
        title = f"# VIF {vid} ({item.get('virtualInterfaceName')}), {vtype}, VLAN {item.get('vlan')} on {item.get('connectionId')}"
        if owner and self.account and owner != self.account:
            _comment(self.manual, f"{title[2:]}\nhosted VIF owned by account {owner}: the connection owner allocates "
                                  f"it (allocate-{vtype}-virtual-interface) and that account accepts it.")
            return
        conn = item.get("connectionId")
        if conn and not any(o2["id"] == conn for o2 in self.current["objects"].values()
                            if o2["kind"] in ("connection", "lag")):
            title += f"\n# note: {conn} isn't in the current configuration; replace it with the new connection ID"
        query = "virtualInterface.virtualInterfaceId" if vtype == "transit" else "virtualInterfaceId"
        self.creates += [title, f"{v}=$({cli(op, o.get('region'), ('--connection-id', conn), (param, spec))} "
                                f"--query {query} --output text)"]
        for p in peers:
            if p is first:
                continue
            self.creates.append(cli("create-bgp-peer", o.get("region"), ("--virtual-interface-id", ref(v)),
                                    ("--new-bgp-peer", self._peer_spec(vid, p))))

    def _peer_spec(self, vid: str, p: dict) -> dict:
        spec: dict[str, Any] = {}
        self._asn(spec, p)
        key = self.auth_key(vid, p.get("authKey"), f"{p.get('addressFamily')}")
        if key:
            spec["authKey"] = key
        for f in ("addressFamily", "amazonAddress", "customerAddress"):
            if p.get(f):
                spec[f] = p[f]
        return spec

    TUNABLE = ("prefixPoolAllocatedCountIpv4", "prefixPoolAllocatedCountIpv6", "rateLimit")
    FIXED = ("vlan", "asn", "asnLong", "connectionId", "virtualGatewayId", "directConnectGatewayId",
             "virtualInterfaceType", "amazonSideAsn")

    def update_vif(self, o: dict, cur: dict) -> None:
        item, have, vid, region = o["item"], cur["item"], o["id"], o.get("region")
        args: list = []
        if item.get("virtualInterfaceName") != have.get("virtualInterfaceName"):
            args.append(("--virtual-interface-name", item.get("virtualInterfaceName")))
        if item.get("mtu") and item.get("mtu") != have.get("mtu"):
            args.append(("--mtu", str(item["mtu"])))
        if item.get("siteLinkEnabled") is not None and item.get("siteLinkEnabled") != have.get("siteLinkEnabled"):
            args.append("--enable-site-link" if item["siteLinkEnabled"] else "--no-enable-site-link")
        for f, flag in zip(self.TUNABLE, ("--prefix-pool-allocated-count-ipv4", "--prefix-pool-allocated-count-ipv6",
                                          "--rate-limit")):
            if item.get(f) is not None and item.get(f) != have.get(f):
                args.append((flag, str(item[f])))
        if args:
            self.updates.append(cli("update-virtual-interface-attributes", region, ("--virtual-interface-id", vid), *args))
        fixed = [f"{f}: {have.get(f)} -> {item.get(f)}" for f in self.FIXED if str(item.get(f)) != str(have.get(f))]
        rfp = sorted(p.get("cidr") for p in item.get("routeFilterPrefixes") or [])
        if rfp != sorted(p.get("cidr") for p in have.get("routeFilterPrefixes") or []):
            fixed.append(f"routeFilterPrefixes -> {', '.join(rfp) or '(none)'} (public VIF prefixes change "
                         "through an AWS Support case)")
        if fixed:
            _comment(self.manual, f"{vid}: can't be changed in place; recreate the VIF to restore:\n  "
                     + "\n  ".join(fixed))
        key = db_diff._KEYS["bgpPeers"]
        want_peers = {key(p): p for p in self._peers(item)}
        have_peers = {key(p): p for p in self._peers(have)}
        for k, p in want_peers.items():
            hp = have_peers.get(k)
            if hp is None:
                self.updates.append(cli("create-bgp-peer", region, ("--virtual-interface-id", vid),
                                        ("--new-bgp-peer", self._peer_spec(vid, p))))
            elif str(p.get("asnLong") or p.get("asn")) != str(hp.get("asnLong") or hp.get("asn")) \
                    or p.get("authKey") != hp.get("authKey"):
                _comment(self.manual, f"{vid} peer {k}: ASN or auth key differs; replace the peer (this drops "
                                      f"the BGP session):\n  " + self._delete_peer(vid, region, hp) + "\n  "
                         + cli("create-bgp-peer", region, ("--virtual-interface-id", vid),
                               ("--new-bgp-peer", self._peer_spec(vid, p))))
        for k, hp in have_peers.items():
            if k not in want_peers:
                _comment(self.deletes, self._delete_peer(vid, region, hp) + f"   # peer {k} not in the backup")
        self.tag_lines(o, _tags(item), _tags(have))

    @staticmethod
    def _delete_peer(vid: str, region: str | None, p: dict) -> str:
        args: list = [("--virtual-interface-id", vid)]
        if p.get("bgpPeerId"):
            args.append(("--bgp-peer-id", p["bgpPeerId"]))
        else:
            args += [("--asn", str(p.get("asnLong") or p.get("asn"))), ("--customer-address", p.get("customerAddress"))]
        return cli("delete-bgp-peer", region, *args)

    # ----- connections and LAGs -----
    def physical(self) -> None:
        for kind, id_op, name_key, update in (("connection", "--connection-id", "connectionName", "update-connection"),
                                              ("lag", "--lag-id", "lagName", "update-lag")):
            want, have = self.objs(self.target, kind), self.objs(self.current, kind)
            for cid, o in want.items():
                item, region = o["item"], o.get("region")
                if cid not in have:
                    if kind == "connection" and item.get("partnerName"):
                        _comment(self.manual, f"hosted connection {cid} ({item.get(name_key)}, {item.get('bandwidth')})"
                                              f" from {item.get('partnerName')}: ask the partner to provision it again.")
                    elif kind == "connection":
                        _comment(self.manual, f"physical connection {cid} needs a new cross-connect:\n  "
                                 + cli("create-connection", region, ("--location", item.get("location")),
                                       ("--bandwidth", item.get("bandwidth")), ("--connection-name", item.get(name_key)),
                                       *([("--lag-id", item["lagId"])] if item.get("lagId") else []),
                                       *([("--tags", item["tags"])] if item.get("tags") else [])))
                    else:
                        _comment(self.manual, f"LAG {cid} needs new connections:\n  "
                                 + cli("create-lag", region, ("--location", item.get("location")),
                                       ("--number-of-connections", str(item.get("numberOfConnections"))),
                                       ("--connections-bandwidth", item.get("connectionsBandwidth")),
                                       ("--lag-name", item.get(name_key)),
                                       *([("--tags", item["tags"])] if item.get("tags") else [])))
                    continue
                cur = have[cid]["item"]
                args: list = []
                if item.get(name_key) != cur.get(name_key):
                    args.append((f"--{'connection' if kind == 'connection' else 'lag'}-name", item.get(name_key)))
                if item.get("encryptionMode") and item.get("encryptionMode") != cur.get("encryptionMode"):
                    args.append(("--encryption-mode", item["encryptionMode"]))
                if kind == "lag" and item.get("minimumLinks") is not None \
                        and item.get("minimumLinks") != cur.get("minimumLinks"):
                    args.append(("--minimum-links", str(item["minimumLinks"])))
                if args:
                    self.updates.append(cli(update, region, (id_op, cid), *args))
                self.tag_lines(o, _tags(item), _tags(cur))
            for cid, o in have.items():
                if cid not in want:
                    _comment(self.deletes, cli(f"delete-{kind}", o.get("region"), (id_op, cid))
                             + "   # not in the backup")

    # ----- routes -----
    def routes(self) -> None:
        want, have = self.objs(self.target, "routes"), self.objs(self.current, "routes")
        for vid, o in want.items():
            cur = have.get(vid) or {}
            for direction in (core.ADVERTISED, core.ACCEPTED):
                a = {r["cidr"] for r in o.get(direction) or []}
                b = {r["cidr"] for r in cur.get(direction) or []}
                if o.get(direction) is None or (cur and cur.get(direction) is None):
                    continue
                missing, extra = sorted(a - b), sorted(b - a)
                if missing or extra:
                    self.notes.append(f"{vid} {direction}: " + "; ".join(
                        x for x in (f"missing {', '.join(missing)}" if missing else "",
                                    f"new {', '.join(extra)}" if extra else "") if x))

    def build(self) -> str:
        self.gateways()
        self.vifs()
        self.physical()
        self.routes()
        t, c = self.target["manifest"], self.current["manifest"]
        out = ["#!/usr/bin/env bash",
               "# dx_backup restore plan. Review every line before running it; nothing has been run.",
               f"# Target (restore to): {db_diff.describe(t)}",
               f"# Current:             {db_diff.describe(c)}",
               "set -euo pipefail",
               ': "${I_REVIEWED_THIS_PLAN:?set I_REVIEWED_THIS_PLAN=yes after reviewing this plan}"']
        live = "\n".join(self.creates + self.updates)
        needed = [(n, w) for n, w in self.secrets if f'"${n}"' in live]
        later = [(n, w) for n, w in self.secrets if (n, w) not in needed]
        if needed:
            out += ["", "# BGP auth keys aren't stored in backups. Export each one before running:"]
            out += [f': "${{{name}:?{what}}}"' for name, what in needed]
        if later:
            out += ["", "# The manual steps below also need: " + ", ".join(n for n, _ in later)]
        sections = (("Create", self.creates), ("Update", self.updates),
                    ("Manual steps (not run)", self.manual), ("Deletes (commented out; uncomment to run)", self.deletes))
        empty = True
        for title, lines in sections:
            if lines:
                empty = False
                out += ["", f"# ---------- {title} ----------", *lines]
        if self.notes:
            out += ["", "# ---------- Route differences (learned over BGP; check the customer router and allowed "
                        "prefixes) ----------", *[f"# {n}" for n in self.notes]]
        if empty and not self.notes:
            out += ["", "# Nothing to do: the current configuration matches the backup."]
        return "\n".join(out) + "\n"

    def empty(self) -> bool:
        return not (self.creates or self.updates or self.manual or self.deletes or self.notes)


def plan(target: dict, current: dict) -> Plan:
    p = Plan(target, current)
    p.text = p.build()
    return p
