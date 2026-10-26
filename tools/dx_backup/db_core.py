"""Direct Connect configuration collection and backup storage for dx_backup.

collect() reads every Direct Connect object an account can see in the Regions asked
for: connections, LAGs, virtual interfaces (with their BGP peers, route filter
prefixes and tags), and the account's Direct Connect gateways with their
associations (allowed prefixes), VIF attachments and association proposals. With
routes on, it also reads the routes each VIF advertises to and accepts from the
customer router (ListVirtualInterfaceRoutes). The result is a *snapshot*:

    {"manifest": {...}, "objects": {"<kind>/<id>": record, ...}}

Secrets are never stored. A BGP MD5 auth key is replaced by a salted scrypt
fingerprint, so a diff can still say the key changed, and the sample router
configuration (customerRouterConfig, which embeds the key) is dropped.

write_backup() stores a snapshot as one JSON file per object plus a manifest with
each file's SHA-256, under <backup_dir>/<account>/<UTC timestamp>/. load_backup()
reads one back and checks those hashes. The AWS profile is never written.
"""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

log = logging.getLogger("dx_backup")

FORMAT = 1
WORKERS = 8
KINDS = ("connection", "lag", "vif", "dx-gateway", "routes")
DIRS = {"connection": "connections", "lag": "lags", "vif": "vifs", "dx-gateway": "dx-gateways", "routes": "routes"}
ADVERTISED, ACCEPTED = "advertised", "accepted"
REDACTIONS = ["authKey: replaced by a salted scrypt fingerprint",
              "customerRouterConfig: removed (the sample router config embeds the auth key)"]
STAMP = "%Y%m%dT%H%M%SZ"
FINGERPRINT_PREFIX = "scrypt:"
SCRYPT_N = 2 ** 15


class ValidationError(ValueError):
    pass


# ---------- sessions ----------

def get_session(profile: str | None, region: str | None) -> boto3.Session:
    return boto3.Session(profile_name=profile, region_name=region)


def get_client(service: str, session: boto3.Session, region: str | None = None):
    config = Config(retries={"max_attempts": 5, "mode": "adaptive"})
    return session.client(service, region_name=region, config=config)


def caller_account(session: boto3.Session) -> str:
    try:
        return get_client("sts", session).get_caller_identity()["Account"]
    except ClientError as e:
        log.warning("Could not identify the caller account: %s", e)
        return "unknown-account"


# ---------- helpers ----------

def _code(e: ClientError) -> str:
    return e.response.get("Error", {}).get("Code", "Error")


def _token_pages(call: Callable[..., dict], key: str, **params) -> Iterator[dict]:
    """Yield items across nextToken pages (Direct Connect has few paginators)."""
    token = None
    while True:
        page = call(**params, **({"nextToken": token} if token else {}))
        yield from page.get(key) or []
        token = page.get("nextToken")
        if not token:
            return


def _parallel(fn: Callable, items: Iterable) -> list:
    items = list(items)
    if len(items) <= 1:
        return [fn(i) for i in items]
    with ThreadPoolExecutor(max_workers=min(WORKERS, len(items))) as pool:
        return list(pool.map(fn, items))


def _jsonable(obj: Any) -> Any:
    return json.loads(json.dumps(obj, default=lambda o: o.isoformat() if hasattr(o, "isoformat") else str(o)))


def tag_name(item: dict) -> str | None:
    return next((t.get("value") for t in item.get("tags") or [] if t.get("key") == "Name"), None)


# ---------- secrets ----------

def fingerprint(salt: str, secret: str) -> str:
    """scrypt (a deliberately slow, memory-hard KDF) so a stolen backup doesn't make short
    keys cheap to brute-force. Salted with the object ID so equal keys on different VIFs
    don't share a fingerprint; stable across backups of the same VIF."""
    digest = hashlib.scrypt(secret.encode(), salt=f"dx_backup:{salt}".encode(), n=SCRYPT_N, r=8, p=1, dklen=32,
                            maxmem=256 * SCRYPT_N * 8 + 2 ** 20)
    return FINGERPRINT_PREFIX + digest.hex()


def is_fingerprint(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(FINGERPRINT_PREFIX)


def redact_vif(item: dict) -> dict:
    v = copy.deepcopy(item)
    vid = v.get("virtualInterfaceId", "")
    v.pop("customerRouterConfig", None)
    if v.get("authKey"):
        v["authKey"] = fingerprint(vid, v["authKey"])
    for p in v.get("bgpPeers") or []:
        if p.get("authKey"):
            p["authKey"] = fingerprint(vid, p["authKey"])
    return v


# ---------- collection ----------

def route_record(r: dict) -> dict:
    installed = r.get("routeInstalledAt")
    if isinstance(installed, (int, float)):
        installed = dt.datetime.fromtimestamp(installed, dt.timezone.utc)
    return {
        "cidr": r.get("cidr"),
        "family": r.get("addressFamily"),
        "as_path": [{"type": s.get("pathType") or "seq", "path": [int(a) for a in s.get("path") or []]}
                    for s in r.get("asPath") or []],
        "communities": sorted(r.get("communities") or []),
        "device": r.get("awsLogicalDeviceId"),
        "installed": installed.isoformat() if hasattr(installed, "isoformat") else installed,
    }


def list_vif_routes(dx, vif_id: str, direction: str) -> list[dict]:
    routes = [route_record(r) for r in _token_pages(dx.list_virtual_interface_routes, "routes",
                                                    virtualInterfaceId=vif_id,
                                                    filters={"routeDirection": direction}, maxResults=100)]
    return sorted(routes, key=lambda r: (r["family"] or "", r["cidr"] or ""))


def _region_objects(session, region: str, routes: bool, warnings: list[str]) -> dict[str, dict]:
    dx = get_client("directconnect", session, region)
    out: dict[str, dict] = {}
    for kind, call, key, id_key in (("connection", dx.describe_connections, "connections", "connectionId"),
                                    ("lag", dx.describe_lags, "lags", "lagId"),
                                    ("vif", dx.describe_virtual_interfaces, "virtualInterfaces", "virtualInterfaceId")):
        try:
            items = list(_token_pages(call, key))
        except ClientError as e:
            warnings.append(f"{region}: {call.__name__} failed: {_code(e)}")
            continue
        for item in items:
            item = redact_vif(item) if kind == "vif" else item
            out[f"{kind}/{item[id_key]}"] = {"kind": kind, "id": item[id_key], "region": item.get("region") or region,
                                             "item": item}

    if routes:
        vifs = [o for o in out.values() if o["kind"] == "vif"]

        def fetch(o):
            rec = {"kind": "routes", "id": o["id"], "region": o["region"]}
            for direction in (ADVERTISED, ACCEPTED):
                try:
                    rec[direction] = list_vif_routes(dx, o["id"], direction)
                except ClientError as e:
                    warnings.append(f"{o['id']}: ListVirtualInterfaceRoutes ({direction}) failed: {_code(e)}")
                    rec[direction] = None
            return rec

        for rec in _parallel(fetch, vifs):
            out[f"routes/{rec['id']}"] = rec
    return out


def _gateways(session, region: str, warnings: list[str]) -> dict[str, dict]:
    """Direct Connect gateways are global; read them once through one Region's endpoint."""
    dx = get_client("directconnect", session, region)
    out: dict[str, dict] = {}
    try:
        gws = list(_token_pages(dx.describe_direct_connect_gateways, "directConnectGateways"))
    except ClientError as e:
        warnings.append(f"DescribeDirectConnectGateways failed: {_code(e)}")
        return out
    for gw in gws:
        gid = gw["directConnectGatewayId"]
        rec = {"kind": "dx-gateway", "id": gid, "region": None, "item": gw}
        for field, call, key in (
                ("associations", dx.describe_direct_connect_gateway_associations, "directConnectGatewayAssociations"),
                ("attachments", dx.describe_direct_connect_gateway_attachments, "directConnectGatewayAttachments"),
                ("proposals", dx.describe_direct_connect_gateway_association_proposals,
                 "directConnectGatewayAssociationProposals")):
            try:
                rec[field] = list(_token_pages(call, key, directConnectGatewayId=gid))
            except ClientError as e:
                warnings.append(f"{gid}: {call.__name__} failed: {_code(e)}")
                rec[field] = None
        out[f"dx-gateway/{gid}"] = rec
    return out


def collect(session, regions: list[str], *, routes: bool = True, account: str | None = None) -> dict:
    """A snapshot of every Direct Connect object the session's account sees in these Regions."""
    if not regions:
        raise ValidationError("No region configured; pass --region or set AWS_REGION")
    warnings: list[str] = []
    objects: dict[str, dict] = {}
    for region in regions:
        objects.update(_region_objects(session, region, routes, warnings))
    objects.update(_gateways(session, regions[0], warnings))
    manifest = {
        "tool": "dx_backup",
        "format": FORMAT,
        "generated": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "account": account or caller_account(session),
        "regions": list(regions),
        "routes": routes,
        "redacted": REDACTIONS,
        "warnings": warnings,
    }
    return _jsonable({"manifest": manifest, "objects": dict(sorted(objects.items()))})


def counts(snapshot: dict) -> dict[str, int]:
    out = {k: 0 for k in KINDS}
    for o in snapshot["objects"].values():
        out[o["kind"]] = out.get(o["kind"], 0) + 1
    return out


# ---------- storage ----------

def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-") or "unknown"


def backup_path(snapshot: dict, backup_dir: str | Path) -> Path:
    m = snapshot["manifest"]
    stamp = dt.datetime.fromisoformat(m["generated"]).astimezone(dt.timezone.utc).strftime(STAMP)
    return Path(backup_dir) / _safe(m["account"]) / stamp


def write_backup(snapshot: dict, backup_dir: str | Path) -> Path:
    """One file per object plus manifest.json. Refuses to overwrite an existing backup."""
    root = backup_path(snapshot, backup_dir)
    if root.exists():
        raise ValidationError(f"{root} already exists")
    files: dict[str, str] = {}
    for o in snapshot["objects"].values():
        rel = f"{DIRS[o['kind']]}/{_safe(o['id'])}.json"
        data = (json.dumps(o, indent=2, sort_keys=True) + "\n").encode()
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(data)
        files[rel] = _sha(data)
    manifest = {**snapshot["manifest"], "counts": counts(snapshot), "files": dict(sorted(files.items()))}
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return root


def load_backup(path: str | Path) -> dict:
    """Read a backup directory (or its manifest.json). A file whose hash doesn't match the
    manifest is still loaded, with a warning."""
    root = Path(path)
    if root.name == "manifest.json":
        root = root.parent
    mpath = root / "manifest.json"
    if not mpath.is_file():
        raise ValidationError(f"{root} is not a dx_backup backup (no manifest.json)")
    manifest = json.loads(mpath.read_text(encoding="utf-8"))
    if manifest.get("tool") != "dx_backup":
        raise ValidationError(f"{mpath} was not written by dx_backup")
    if manifest.get("format", 0) > FORMAT:
        raise ValidationError(f"{mpath} uses backup format {manifest['format']}; this version reads up to {FORMAT}")
    warnings = list(manifest.get("warnings") or [])
    objects: dict[str, dict] = {}
    for rel, digest in (manifest.get("files") or {}).items():
        f = root / rel
        if not f.is_file():
            warnings.append(f"{rel}: listed in the manifest but missing")
            continue
        data = f.read_bytes()
        if _sha(data) != digest:
            warnings.append(f"{rel}: contents don't match the manifest hash (edited after the backup?)")
        o = json.loads(data)
        objects[f"{o['kind']}/{o['id']}"] = o
    manifest = {**manifest, "warnings": warnings, "path": str(root)}
    return {"manifest": manifest, "objects": dict(sorted(objects.items()))}


def list_backups(backup_dir: str | Path) -> list[Path]:
    """Backup directories under backup_dir, oldest first by their manifest's timestamp."""
    found = []
    for m in Path(backup_dir).glob("*/*/manifest.json"):
        try:
            generated = json.loads(m.read_text(encoding="utf-8")).get("generated") or ""
        except (OSError, ValueError):
            continue
        found.append((generated, m.parent))
    return [p for _, p in sorted(found)]


def resolve(ref: str, backup_dir: str | Path, account: str | None = None) -> Path:
    """A path, or 'latest' / 'previous' (newest and second-newest backup, optionally for
    one account)."""
    if ref not in ("latest", "previous"):
        return Path(ref)
    found = [p for p in list_backups(backup_dir) if not account or p.parent.name == account]
    need = 1 if ref == "latest" else 2
    if len(found) < need:
        raise ValidationError(f"No {ref!r} backup under {backup_dir}" + (f" for account {account}" if account else ""))
    if ref == "previous" and not account:
        acct = found[-1].parent.name
        found = [p for p in found if p.parent.name == acct]
        if len(found) < 2:
            raise ValidationError(f"Only one backup of account {acct} under {backup_dir}")
    return found[-need]


def object_name(o: dict | None) -> str | None:
    if not o:
        return None
    item = o.get("item") or {}
    return (item.get("connectionName") or item.get("lagName") or item.get("virtualInterfaceName")
            or item.get("directConnectGatewayName") or tag_name(item))
