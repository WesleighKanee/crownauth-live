"""Signed, deterministic remote-experience control plane.

The service intentionally keeps media bytes out of the manifest.  A manifest
is a canonical JSON payload signed once for a monotonically increasing
revision; readers can therefore use its revision as a stable cache validator.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import sqlite3
import time
import math
from dataclasses import dataclass
from typing import Any, Mapping

from . import db
from .crypto_v2 import load_or_create_keypair

SCHEMA = 1
DEFAULT_CONFIG = {
    "preset": "CALM", "accent": "#7DDCFF", "motion": "BALANCED",
    "parallax": "TOUCH_SENSOR", "particles": "DUST",
    "particle_density": 0.25, "reduced_motion_default": False,
}
_HEX = re.compile(r"^#[0-9A-Fa-f]{6}$")
_PRESETS = {"ETHEREAL", "CYBER", "EMBER", "VOID", "CALM", "CUSTOM"}
_MOTION = {"STATIC", "CALM", "BALANCED"}
_PARALLAX = {"OFF", "TOUCH", "TOUCH_SENSOR"}
_PARTICLES = {"NONE", "DUST", "SPARKS", "GLOW"}


class ExperienceError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


class ConflictError(ExperienceError):
    pass


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def encode_b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def decode_b64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def sign_payload(payload: Mapping[str, Any], private_key: Any = None) -> str:
    body = canonical_json(dict(payload))
    if private_key is None:
        private_key, _ = load_or_create_keypair()
    return encode_b64(body) + "." + encode_b64(private_key.sign(body))


def verify_envelope(envelope: str, public_key: Any = None) -> dict[str, Any]:
    try:
        # Reject ambiguous/malformed envelopes before decoding.  In particular,
        # do not accept extra dot-separated fields or non-canonical JSON.
        encoded, sig = str(envelope).split(".", 1)
        if not encoded or not sig or str(envelope).count(".") != 1:
            raise ValueError("malformed envelope")
        if not re.fullmatch(r"[A-Za-z0-9_-]+", encoded) or not re.fullmatch(r"[A-Za-z0-9_-]+", sig):
            raise ValueError("malformed base64")
        body = decode_b64(encoded)
        signature = decode_b64(sig)
        if len(signature) != 64:
            raise ValueError("invalid signature length")
        if public_key is None:
            _, public_key = load_or_create_keypair()
        public_key.verify(signature, body)
        obj = json.loads(body.decode("utf-8"))
        if canonical_json(obj) != body:
            raise ValueError("non-canonical payload")
        validate_payload(obj)
        return obj
    except Exception as exc:
        raise ExperienceError("invalid_manifest", "manifest signature or schema is invalid") from exc


def validate_payload(payload: Mapping[str, Any]) -> None:
    def strict_int(value: Any, *, minimum: int | None = None) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError
        out = int(value)
        if minimum is not None and out < minimum:
            raise ValueError
        return out

    def strict_real(value: Any, *, minimum: float = 0.0, maximum: float = 1.0) -> float:
        # JSON booleans and numeric strings are not valid signed schema types.
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError
        out = float(value)
        if not math.isfinite(out) or not minimum <= out <= maximum:
            raise ValueError
        return out

    if not isinstance(payload, dict):
        raise ExperienceError("invalid_manifest", "manifest payload must be an object")
    expected_keys = {"schema", "revision", "published_at", "min_client_protocol",
                     "min_client_build_id", "assets", "theme", "library_labels"}
    if set(payload) != expected_keys:
        raise ExperienceError("invalid_manifest", "manifest schema has unexpected fields")
    try:
        schema = strict_int(payload.get("schema"))
    except ValueError:
        raise ExperienceError("invalid_schema", "schema must be an integer")
    if schema != SCHEMA:
        raise ExperienceError("invalid_schema", "unsupported manifest schema")
    try:
        revision = strict_int(payload.get("revision"), minimum=0)
        published_at = strict_int(payload.get("published_at"), minimum=0)
        strict_int(payload.get("min_client_protocol"), minimum=0)
    except ValueError:
        raise ExperienceError("invalid_revision", "revision and publication time must be integers")
    if not isinstance(payload.get("min_client_build_id"), str) or not payload["min_client_build_id"]:
        raise ExperienceError("invalid_schema", "client build id must be a non-empty string")
    # rev-0 is the signed, in-memory bootstrap manifest only.  It must never
    # look like a publication (otherwise the first real publication collides
    # with the fallback's revision number).
    if revision == 0 and published_at != 0:
        raise ExperienceError("invalid_revision", "revision must be non-negative")
    assets = payload.get("assets")
    if not isinstance(assets, dict) or set(assets) != {"login", "library"}:
        raise ExperienceError("invalid_assets", "login and library assets are required")
    for slot, asset in assets.items():
        if not isinstance(asset, dict):
            raise ExperienceError("invalid_assets", f"invalid {slot} asset")
        if set(asset) != {"kind", "focal_x", "focal_y", "renditions"}:
            raise ExperienceError("invalid_assets", f"invalid {slot} asset schema")
        if not isinstance(asset.get("kind"), str) or asset.get("kind") not in ("static", "gif"):
            raise ExperienceError("invalid_assets", "invalid asset kind")
        for axis in ("focal_x", "focal_y"):
            try:
                strict_real(asset.get(axis))
            except ValueError:
                raise ExperienceError("invalid_assets", "focal point is out of range")
        renditions = asset.get("renditions", [])
        if not isinstance(renditions, list) or len(renditions) > 16:
            raise ExperienceError("invalid_rendition", "invalid rendition list")
        for r in renditions:
            if not isinstance(r, dict) or set(r) != {"url", "sha256", "bytes", "width", "height", "format"}:
                raise ExperienceError("invalid_rendition", "incomplete rendition")
            if not isinstance(r["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", r["sha256"]):
                raise ExperienceError("invalid_rendition", "invalid rendition hash")
            if not isinstance(r["url"], str):
                raise ExperienceError("invalid_rendition", "invalid rendition URL")
            url = r["url"]
            if not (url.startswith("/v2/experience/assets/") or url.startswith("https://")):
                raise ExperienceError("invalid_rendition", "invalid rendition URL")
            if not isinstance(r["format"], str) or r["format"] not in {"jpg", "gif"}:
                raise ExperienceError("invalid_rendition", "invalid rendition format")
            for k in ("bytes", "width", "height"):
                try:
                    strict_int(r[k], minimum=1)
                except ValueError:
                    raise ExperienceError("invalid_rendition", "invalid rendition dimensions")
    theme = payload.get("theme") or {}
    if not isinstance(theme, dict) or set(theme) != set(DEFAULT_CONFIG):
        raise ExperienceError("invalid_theme", "invalid theme schema")
    if (not isinstance(theme.get("preset"), str) or theme.get("preset") not in _PRESETS
            or not isinstance(theme.get("motion"), str) or theme.get("motion") not in _MOTION
            or not isinstance(theme.get("parallax"), str) or theme.get("parallax") not in _PARALLAX
            or not isinstance(theme.get("particles"), str) or theme.get("particles") not in _PARTICLES):
        raise ExperienceError("invalid_theme", "invalid theme setting")
    if not isinstance(theme.get("accent"), str) or not _HEX.fullmatch(theme["accent"]):
        raise ExperienceError("invalid_theme", "invalid accent")
    try:
        strict_real(theme.get("particle_density"))
    except ValueError:
        raise ExperienceError("invalid_theme", "invalid particle density")
    if not isinstance(theme.get("reduced_motion_default"), bool):
        raise ExperienceError("invalid_theme", "reduced motion must be boolean")
    labels = payload.get("library_labels")
    if not isinstance(labels, list) or len(labels) > 256:
        raise ExperienceError("invalid_labels", "invalid library labels")
    seen: set[str] = set()
    for label in labels:
        if not isinstance(label, dict) or set(label) != {"id", "display_name"}:
            raise ExperienceError("invalid_labels", "invalid library label")
        sid, display = label["id"], label["display_name"]
        if (not isinstance(sid, str) or not re.fullmatch(r"[A-Z0-9_-]{1,64}", sid)
                or not isinstance(display, str) or not display.strip() or len(display) > 160
                or any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in display)
                or sid in seen):
            raise ExperienceError("invalid_labels", "invalid library label")
        seen.add(sid)


def validate_config(config: Mapping[str, Any] | None) -> dict[str, Any]:
    out = dict(DEFAULT_CONFIG)
    if config:
        out.update({k: config[k] for k in DEFAULT_CONFIG if k in config})
    out["preset"] = str(out["preset"]).upper()
    out["motion"] = str(out["motion"]).upper()
    out["parallax"] = str(out["parallax"]).upper()
    out["particles"] = str(out["particles"]).upper()
    if out["preset"] not in _PRESETS or out["motion"] not in _MOTION:
        raise ExperienceError("invalid_settings", "unknown preset or motion")
    if out["parallax"] not in _PARALLAX or out["particles"] not in _PARTICLES:
        raise ExperienceError("invalid_settings", "unknown parallax or particles mode")
    if not _HEX.fullmatch(str(out["accent"])):
        raise ExperienceError("invalid_settings", "accent must be #RRGGBB")
    try:
        out["particle_density"] = max(0.0, min(1.0, float(out["particle_density"])))
    except Exception as exc:
        raise ExperienceError("invalid_settings", "particle density must be numeric") from exc
    out["reduced_motion_default"] = bool(out["reduced_motion_default"])
    return out


def fallback_manifest() -> dict[str, Any]:
    """Return the signed bootstrap payload without consuming a revision.

    This payload is deliberately not persisted.  Its rev-0 ETag is distinct
    from the first owner publication (rev-1), so a client can never cache a
    fallback envelope as if it were a published revision.
    """
    payload = {"schema": SCHEMA, "revision": 0, "published_at": 0,
               "min_client_protocol": 4, "min_client_build_id": "remote-experience-1",
               "assets": {"login": {"kind": "static", "focal_x": 0.5, "focal_y": 0.5, "renditions": []},
                          "library": {"kind": "static", "focal_x": 0.5, "focal_y": 0.5, "renditions": []}},
               "theme": validate_config(None), "library_labels": []}
    validate_payload(payload)
    return payload


def _asset_dict(con: sqlite3.Connection, row: Mapping[str, Any] | None) -> dict[str, Any]:
    if row is not None and not hasattr(row, "get"):
        row = dict(row)
    if not row:
        return {"kind": "static", "focal_x": 0.5, "focal_y": 0.5, "renditions": []}
    group = row.get("rendition_group")
    if group:
        rows = con.execute("SELECT * FROM experience_assets WHERE rendition_group=? ORDER BY id", (group,)).fetchall()
    else:
        rows = [row]
    try:
        from .lib_cdn import experience_asset_url
        url_for = experience_asset_url
    except Exception:
        url_for = lambda name: "/v2/experience/assets/" + str(name)
    return {
        "kind": "gif" if str(row.get("format", "")).lower() == "gif" else "static",
        "focal_x": 0.5, "focal_y": 0.5,
        "renditions": [{"url": url_for(str(r["cdn_name"])), **{k: r[k] for k in ("sha256", "bytes", "width", "height", "format")}} for r in rows],
    }


def _labels(con: sqlite3.Connection) -> list[dict[str, str]]:
    rows = con.execute("SELECT stable_id,display_name FROM library_labels ORDER BY stable_id").fetchall()
    return [{"id": r["stable_id"], "display_name": r["display_name"]} for r in rows]


def default_draft(con: sqlite3.Connection | None = None) -> int:
    owned = con is None
    con = con or db.connect()
    row = con.execute("SELECT id FROM experience_revisions WHERE status='draft' ORDER BY id DESC LIMIT 1").fetchone()
    if row:
        if owned: con.close()
        return int(row["id"])
    now = int(time.time())
    cur = con.execute("INSERT INTO experience_revisions(status,config_json,labels_json,created_at) VALUES('draft',?,?,?)",
                      (json.dumps(DEFAULT_CONFIG, sort_keys=True), json.dumps(_labels(con)), now))
    if owned: con.commit(); con.close()
    return int(cur.lastrowid)


def current_state() -> dict[str, Any]:
    con = db.connect()
    row = con.execute("SELECT * FROM experience_state WHERE singleton_id=1").fetchone()
    draft = con.execute("SELECT * FROM experience_revisions WHERE status='draft' ORDER BY id DESC LIMIT 1").fetchone()
    if not draft:
        did = default_draft(con); con.commit(); draft = con.execute("SELECT * FROM experience_revisions WHERE id=?", (did,)).fetchone()
    out = {"manifest_revision": int(row["manifest_revision"] if row else 0),
           "published_revision_id": row["current_revision_id"] if row else None,
           "signed_envelope": row["signed_envelope"] if row else "", "draft": dict(draft)}
    con.close(); return out


def manifest_for_revision(con: sqlite3.Connection, revision: Mapping[str, Any], rev_number: int) -> dict[str, Any]:
    revision = dict(revision)
    def get_asset(key: str) -> Mapping[str, Any] | None:
        aid = revision.get(key)
        return con.execute("SELECT * FROM experience_assets WHERE id=?", (aid,)).fetchone() if aid else None
    config = validate_config(json.loads(revision.get("config_json") or "{}"))
    labels = json.loads(revision.get("labels_json") or "[]")
    payload = {"schema": SCHEMA, "revision": int(rev_number), "published_at": int(revision.get("published_at") or time.time()),
               "min_client_protocol": 4, "min_client_build_id": "remote-experience-1",
               "assets": {"login": _asset_dict(con, get_asset("login_asset_id")), "library": _asset_dict(con, get_asset("library_asset_id"))},
               "theme": config, "library_labels": labels}
    # 0.0 is a meaningful focal point; never replace it using ``or``.
    for slot in ("login", "library"):
        for axis in ("x", "y"):
            key = f"{slot}_focal_{axis}"
            value = revision.get(key)
            payload["assets"][slot][f"focal_{axis}"] = 0.5 if value is None else float(value)
    validate_payload(payload)
    return payload


def get_manifest() -> tuple[dict[str, Any] | None, str, int]:
    con = db.connect(); state = con.execute("SELECT * FROM experience_state WHERE singleton_id=1").fetchone()
    if not state or not state["signed_envelope"]:
        con.close(); return None, '"rev-0"', 0
    env, rev = state["signed_envelope"], int(state["manifest_revision"])
    con.close(); return {"ok": True, "manifest": env}, f'"rev-{rev}"', rev


def publish(*, expected_revision: int | None = None, draft_id: int | None = None, idempotency_key: str = "", request_hash: str = "") -> dict[str, Any]:
    priv, _ = load_or_create_keypair(); con = db.connect()
    try:
        con.execute("BEGIN IMMEDIATE")
        state = con.execute("SELECT * FROM experience_state WHERE singleton_id=1").fetchone()
        current = int(state["manifest_revision"] or 0)
        if idempotency_key:
            old = con.execute("SELECT request_hash,response_json FROM idempotency WHERE key=?", (idempotency_key,)).fetchone()
            if old:
                if old["request_hash"] != request_hash: raise ConflictError("idempotency_conflict", "key was used with another request")
                return json.loads(old["response_json"])
        if expected_revision is not None and current != int(expected_revision):
            raise ConflictError("stale_revision", "manifest revision changed")
        did = draft_id or default_draft(con)
        draft = con.execute("SELECT * FROM experience_revisions WHERE id=? AND status='draft'", (did,)).fetchone()
        if not draft: raise ExperienceError("missing_draft", "draft not found")
        newrev = current + 1
        payload = manifest_for_revision(con, draft, newrev)
        envelope = sign_payload(payload, priv)
        now = int(time.time())
        con.execute("UPDATE experience_revisions SET status='archived' WHERE status='published'")
        cur = con.execute("INSERT INTO experience_revisions(manifest_revision,status,login_asset_id,library_asset_id,login_focal_x,login_focal_y,library_focal_x,library_focal_y,config_json,labels_json,created_at,published_at) SELECT ?, 'published',login_asset_id,library_asset_id,login_focal_x,login_focal_y,library_focal_x,library_focal_y,config_json,labels_json,created_at,? FROM experience_revisions WHERE id=?", (newrev, now, did))
        published_id = int(cur.lastrowid)
        con.execute("UPDATE experience_state SET current_revision_id=?,manifest_revision=?,signed_envelope=? WHERE singleton_id=1", (published_id,newrev,envelope))
        result = {"ok": True, "revision": newrev, "manifest": envelope, "etag": f'"rev-{newrev}"'}
        if idempotency_key:
            con.execute("INSERT INTO idempotency(key,request_hash,state,response_json,created_at) VALUES(?,?,?,?,?)", (idempotency_key,request_hash,"done",json.dumps(result,sort_keys=True),now))
        con.commit(); return result
    except Exception:
        con.rollback(); raise
    finally: con.close()


def rollback(target: int, *, expected_revision: int | None = None,
             idempotency_key: str = "", request_hash: str = "") -> dict[str, Any]:
    """Atomically replay a historical revision without touching live drafts.

    A rollback is a new monotonically increasing publication.  The historical
    row is copied into a private draft inside the same SQLite transaction and
    published from that copy; unrelated in-progress drafts remain untouched.
    """
    priv, _ = load_or_create_keypair(); con = db.connect()
    try:
        con.execute("BEGIN IMMEDIATE")
        state = con.execute("SELECT * FROM experience_state WHERE singleton_id=1").fetchone()
        current = int(state["manifest_revision"] or 0)
        if idempotency_key:
            old = con.execute("SELECT request_hash,response_json FROM idempotency WHERE key=?", (idempotency_key,)).fetchone()
            if old:
                if old["request_hash"] != request_hash:
                    raise ConflictError("idempotency_conflict", "key was used with another request")
                return json.loads(old["response_json"])
        if expected_revision is not None and current != int(expected_revision):
            raise ConflictError("stale_revision", "manifest revision changed")
        row = con.execute("SELECT * FROM experience_revisions WHERE (id=? OR manifest_revision=?) AND status IN ('published','archived') ORDER BY id DESC LIMIT 1", (int(target), int(target))).fetchone()
        if not row:
            raise ExperienceError("missing_revision", "revision not found")
        now = int(time.time())
        cur = con.execute("INSERT INTO experience_revisions(status,login_asset_id,library_asset_id,login_focal_x,login_focal_y,library_focal_x,library_focal_y,config_json,labels_json,created_at) VALUES('draft',?,?,?,?,?,?,?,?,?)",
                          (row["login_asset_id"], row["library_asset_id"], row["login_focal_x"], row["login_focal_y"], row["library_focal_x"], row["library_focal_y"], row["config_json"], row["labels_json"], now))
        did = int(cur.lastrowid); newrev = current + 1
        payload = manifest_for_revision(con, con.execute("SELECT * FROM experience_revisions WHERE id=?", (did,)).fetchone(), newrev)
        envelope = sign_payload(payload, priv)
        con.execute("UPDATE experience_revisions SET status='archived' WHERE status='published'")
        cur = con.execute("INSERT INTO experience_revisions(manifest_revision,status,login_asset_id,library_asset_id,login_focal_x,login_focal_y,library_focal_x,library_focal_y,config_json,labels_json,created_at,published_at) SELECT ?, 'published',login_asset_id,library_asset_id,login_focal_x,login_focal_y,library_focal_x,library_focal_y,config_json,labels_json,created_at,? FROM experience_revisions WHERE id=?", (newrev, now, did))
        published_id = int(cur.lastrowid)
        con.execute("UPDATE experience_revisions SET status='archived' WHERE id=?", (did,))
        con.execute("UPDATE experience_state SET current_revision_id=?,manifest_revision=?,signed_envelope=? WHERE singleton_id=1", (published_id, newrev, envelope))
        result = {"ok": True, "revision": newrev, "manifest": envelope, "etag": f'"rev-{newrev}"'}
        if idempotency_key:
            con.execute("INSERT INTO idempotency(key,request_hash,state,response_json,created_at) VALUES(?,?,?,?,?)", (idempotency_key, request_hash, "done", json.dumps(result, sort_keys=True), now))
        con.commit(); return result
    except Exception:
        con.rollback(); raise
    finally:
        con.close()


def update_draft(fields: Mapping[str, Any], expected_revision: int | None = None, draft_id: int | None = None) -> dict[str, Any]:
    con = db.connect()
    try:
        con.execute("BEGIN IMMEDIATE")
        current = int(con.execute("SELECT manifest_revision FROM experience_state WHERE singleton_id=1").fetchone()[0])
        if expected_revision is not None and current != int(expected_revision): raise ConflictError("stale_revision", "manifest revision changed")
        did = draft_id or default_draft(con)
        row = con.execute("SELECT * FROM experience_revisions WHERE id=? AND status='draft'", (did,)).fetchone()
        if not row: raise ExperienceError("missing_draft", "draft not found")
        config = validate_config({**json.loads(row["config_json"] or "{}"), **(fields.get("theme") or fields.get("config") or {})})
        vals = [config, fields.get("login_focal_x", row["login_focal_x"]), fields.get("login_focal_y", row["login_focal_y"]), fields.get("library_focal_x", row["library_focal_x"]), fields.get("library_focal_y", row["library_focal_y"])]
        if any(not 0 <= float(x) <= 1 for x in vals[1:]): raise ExperienceError("invalid_settings", "focal values must be between 0 and 1")
        con.execute("UPDATE experience_revisions SET config_json=?,login_focal_x=?,login_focal_y=?,library_focal_x=?,library_focal_y=? WHERE id=?", (json.dumps(config,sort_keys=True), *vals[1:], did))
        con.commit(); return {"ok": True, "draft_id": did, "manifest_revision": current, "config": config}
    except Exception: con.rollback(); raise
    finally: con.close()


def rename_label(stable_id: str, display_name: str, *, expected_revision: int | None = None,
                 idempotency_key: str = "", request_hash: str = "") -> dict[str, Any]:
    """Atomically rename a label and publish the resulting manifest."""
    priv, _ = load_or_create_keypair()
    con = db.connect()
    try:
        con.execute("BEGIN IMMEDIATE")
        if idempotency_key:
            old = con.execute("SELECT request_hash,response_json FROM idempotency WHERE key=?",
                              (idempotency_key,)).fetchone()
            if old:
                if old["request_hash"] != request_hash:
                    raise ConflictError("idempotency_conflict", "key was used with another request")
                return json.loads(old["response_json"])
        state = con.execute("SELECT * FROM experience_state WHERE singleton_id=1").fetchone()
        current = int(state["manifest_revision"] or 0)
        if expected_revision is not None and current != int(expected_revision):
            raise ConflictError("stale_revision", "manifest revision changed")
        sid, name = db.validate_library_label(con, stable_id, display_name)
        now = int(time.time())
        con.execute("INSERT INTO library_labels(stable_id,display_name,updated_at) VALUES(?,?,?) "
                    "ON CONFLICT(stable_id) DO UPDATE SET display_name=excluded.display_name,updated_at=excluded.updated_at",
                    (sid, name, now))
        # A label rename is its own publication.  Never mutate or publish the
        # owner's unrelated pending draft (theme/assets/focal points).  Base
        # the publication on the currently live revision; before the first
        # publication use a clean bootstrap copy instead of the pending draft.
        live = con.execute("SELECT * FROM experience_revisions WHERE status='published' ORDER BY id DESC LIMIT 1").fetchone()
        labels_json = json.dumps(_labels(con), sort_keys=True)
        now = int(time.time())
        if live:
            source = live
            args = (source["login_asset_id"], source["library_asset_id"],
                    source["login_focal_x"], source["login_focal_y"],
                    source["library_focal_x"], source["library_focal_y"],
                    source["config_json"], labels_json, now)
        else:
            args = (None, None, 0.5, 0.5, 0.5, 0.5,
                    json.dumps(DEFAULT_CONFIG, sort_keys=True), labels_json, now)
        cur = con.execute("INSERT INTO experience_revisions(status,login_asset_id,library_asset_id,login_focal_x,login_focal_y,library_focal_x,library_focal_y,config_json,labels_json,created_at) VALUES('draft',?,?,?,?,?,?,?,?,?)", args)
        did = int(cur.lastrowid)
        draft = con.execute("SELECT * FROM experience_revisions WHERE id=? AND status='draft'", (did,)).fetchone()
        newrev = current + 1
        envelope = sign_payload(manifest_for_revision(con, draft, newrev), priv)
        con.execute("UPDATE experience_revisions SET status='archived' WHERE status='published'")
        cur = con.execute("INSERT INTO experience_revisions(manifest_revision,status,login_asset_id,library_asset_id,"
                          "login_focal_x,login_focal_y,library_focal_x,library_focal_y,config_json,labels_json,created_at,published_at) "
                          "SELECT ?, 'published',login_asset_id,library_asset_id,login_focal_x,login_focal_y,library_focal_x,"
                          "library_focal_y,config_json,labels_json,created_at,? FROM experience_revisions WHERE id=?",
                          (newrev, now, did))
        published_id = int(cur.lastrowid)
        con.execute("UPDATE experience_state SET current_revision_id=?,manifest_revision=?,signed_envelope=? WHERE singleton_id=1",
                    (published_id, newrev, envelope))
        # The private publication copy is no longer a pending draft; retain
        # any pre-existing owner draft for the next explicit publish.
        con.execute("UPDATE experience_revisions SET status='archived' WHERE id=?", (did,))
        result = {"ok": True, "label": {"stable_id": sid, "display_name": name, "updated_at": now},
                  "revision": newrev, "manifest": envelope, "etag": f'"rev-{newrev}"'}
        if idempotency_key:
            con.execute("INSERT INTO idempotency(key,request_hash,state,response_json,created_at) VALUES(?,?,?,?,?)",
                        (idempotency_key, request_hash, "done", json.dumps(result, sort_keys=True), now))
        con.commit()
        return result
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def history(limit: int = 20) -> list[dict[str, Any]]:
    con = db.connect(); rows = con.execute("SELECT id,manifest_revision AS revision,status,created_at,published_at FROM experience_revisions WHERE status IN ('published','archived') ORDER BY id DESC LIMIT ?", (max(1,min(100,int(limit))),)).fetchall(); con.close()
    return [dict(r) for r in rows]
