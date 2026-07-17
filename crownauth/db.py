#!/usr/bin/env python3
"""CrownAuth SQLite control plane — source of truth for commercial licensing."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).resolve().parent.parent
# Cloud volume: CROWNAUTH_DATA=/data  → /data/crownauth.db
_env_data = (os.environ.get("CROWNAUTH_DATA") or "").strip()
if _env_data:
    DATA = Path(_env_data)
else:
    DATA = ROOT / "data"
DATA.mkdir(parents=True, exist_ok=True)
DB_PATH = Path(os.environ.get("CROWNAUTH_DB") or (DATA / "crownauth.db"))

DEFAULT_SETTINGS = {
    "app_name": "WhiteCrown",
    "brand_tagline": "Owner-controlled · real-time secured",
    "support_url": "",
    "discord_url": "",
    "force_online": True,
    "allow_offline_envelope": True,
    # After first online login, phone can play offline until license wall-clock expiry
    "hybrid_lease": True,
    "session_ttl_sec": 900,
    "heartbeat_sec": 120,
    "max_devices_default": 1,
    "hwid_reset_cooldown_sec": 86400,
    "maintenance": False,
    "kill_switch": False,
    "kill_message": "Service temporarily disabled by owner.",
    "maintenance_message": "Maintenance in progress. Try again later.",
    "api_bind": "0.0.0.0",
    "api_port": 8787,
    "require_challenge": True,
    "max_failed_auth": 12,
    "ban_duration_sec": 3600,
    "webhook_url": "",
    # Optional Discord webhook only (off by default — no Telegram)
    "notify_enabled": False,
    "notify_on_activation": False,
    "notify_on_mint": False,
    "notify_on_ban": False,
    "notify_on_backup": False,
    "notify_on_backup_fail": False,
    "notify_on_kill": False,
    "notify_on_auth_fail_flood": False,
    "theme_accent": "#c9a227",
    "seller_note": "Keys are non-transferable. HWID locked by default.",
    "client_api_host": "127.0.0.1",
    "client_api_scheme": "http",   # http | https
    "client_api_port": 8787,       # 0 or null = default (80/443 for scheme)

    # Stealth / release
    "stealth_mode": True,
    "panel_path": "/console",
    "client_api_prefix": "/v2",
    "generic_errors": True,
    "quiet_logs": True,
    "expose_pubkey": False,
    "expose_plain_config": False,
    "server_banner": "cloudflare-nginx",
    "bind_owner_localhost_only": False,
    "enable_owner_ip_allowlist": True,
    "owner_ip_allowlist": ["127.0.0.1", "::1", "192.168.254.0/24"],
    # Panel password: OFF by default on LAN (IP allowlist protects console).
    # Turn ON only when the panel is reachable from the public internet.
    "panel_password_enabled": False,
    "key_prefix": "WC",
    "key_length": 10,
    # Extreme harden — client attestation (af bitfield)
    # bits: 1=debug 2=frida 4=xposed 8=NEVER (root required) 16=emu 32=hook/integrity 64=timing
    # Product = kernel loader plugin → ALL buyers are rooted. Never reject root.
    # Attestation flags are collected but NOT used to hard-deny by default.
    # Magisk kernel-loader buyers false-positive Frida/debugger constantly.
    "require_client_attestation": False,
    "reject_frida": False,
    "reject_xposed": False,
    "reject_debugger": False,
    "reject_integrity_fail": False,
    "reject_rooted": False,
    "reject_emulator": False,
    "expected_app_build": "harden_v2",
    "strict_build_id": False,
    "product_requires_root": True,
    # Clear toasts (not generic Access denied)
    "generic_errors": False,
    "stealth_mode": False,
    # Protocol / OTA — kill old cracked APKs without touching updated buyers
    # Client sends proto + vc (versionCode). Raise min_* to force upgrade.
    "client_protocol_current": 3,
    "min_client_protocol": 3,
    "min_client_version_code": 1,
    "force_update": False,
    "update_apk_url": "https://github.com/WesleighKanee/crownauth-live/releases/latest/download/WhiteCrownsLoaderV2.apk",
    "update_message": "A new update is available — install will open. Allow install, then reopen.",
    "blocked_build_ids": [],  # e.g. ["harden_v1","cracked_build"]
}


def connect() -> sqlite3.Connection:
    DATA.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    return con


def init_db() -> None:
    con = connect()
    cur = con.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS plans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            duration_days INTEGER NOT NULL,
            max_devices INTEGER NOT NULL DEFAULT 1,
            tier TEXT NOT NULL DEFAULT 'std',
            features INTEGER NOT NULL DEFAULT 65535,
            price_note TEXT DEFAULT '',
            active INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE NOT NULL,
            token_fp TEXT UNIQUE NOT NULL,
            plan_id INTEGER,
            customer TEXT DEFAULT '',
            note TEXT DEFAULT '',
            tier TEXT NOT NULL DEFAULT 'std',
            status TEXT NOT NULL DEFAULT 'active',
            max_devices INTEGER NOT NULL DEFAULT 1,
            duration_days INTEGER NOT NULL DEFAULT 30,
            expires_at INTEGER NOT NULL DEFAULT 0,
            activated_at INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            banned_reason TEXT DEFAULT '',
            features INTEGER NOT NULL DEFAULT 65535,
            meta_json TEXT DEFAULT '{}',
            FOREIGN KEY(plan_id) REFERENCES plans(id)
        );
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_id INTEGER NOT NULL,
            hwid_hash TEXT NOT NULL,
            hwid_raw TEXT DEFAULT '',
            label TEXT DEFAULT '',
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            UNIQUE(license_id, hwid_hash),
            FOREIGN KEY(license_id) REFERENCES licenses(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_id INTEGER NOT NULL,
            jti TEXT UNIQUE NOT NULL,
            hwid_hash TEXT NOT NULL,
            token TEXT NOT NULL,
            issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,
            ip TEXT DEFAULT '',
            FOREIGN KEY(license_id) REFERENCES licenses(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,
            value TEXT NOT NULL,
            reason TEXT DEFAULT '',
            created_at INTEGER NOT NULL,
            UNIQUE(kind, value)
        );
        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            detail TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS rate_limit (
            key TEXT PRIMARY KEY,
            fails INTEGER NOT NULL DEFAULT 0,
            window_start INTEGER NOT NULL,
            blocked_until INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS resellers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            api_key TEXT UNIQUE NOT NULL,
            password_hash TEXT DEFAULT '',
            quota INTEGER NOT NULL DEFAULT 100,
            used INTEGER NOT NULL DEFAULT 0,
            max_duration_seconds INTEGER NOT NULL DEFAULT 2592000,
            max_devices INTEGER NOT NULL DEFAULT 1,
            can_reset_hwid INTEGER NOT NULL DEFAULT 1,
            active INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL,
            note TEXT DEFAULT ''
        );
        """
    )
    # migrations — flexible duration (seconds). 0 = lifetime
    for col, ddl in (
        ("duration_seconds", "ALTER TABLE licenses ADD COLUMN duration_seconds INTEGER NOT NULL DEFAULT 0"),
        ("duration_seconds", "ALTER TABLE plans ADD COLUMN duration_seconds INTEGER NOT NULL DEFAULT 0"),
        ("duration_label", "ALTER TABLE licenses ADD COLUMN duration_label TEXT DEFAULT ''"),
        ("start_mode", "ALTER TABLE licenses ADD COLUMN start_mode TEXT DEFAULT 'first_use'"),
        ("reseller", "ALTER TABLE licenses ADD COLUMN reseller TEXT DEFAULT ''"),
        ("prefix_tag", "ALTER TABLE licenses ADD COLUMN prefix_tag TEXT DEFAULT ''"),
    ):
        try:
            cur.execute(ddl)
        except sqlite3.OperationalError:
            pass  # already exists

    # backfill duration_seconds from duration_days where needed
    cur.execute(
        """UPDATE licenses SET duration_seconds = duration_days * 86400
           WHERE (duration_seconds IS NULL OR duration_seconds = 0)
             AND duration_days > 0"""
    )
    cur.execute(
        """UPDATE plans SET duration_seconds = duration_days * 86400
           WHERE (duration_seconds IS NULL OR duration_seconds = 0)
             AND duration_days > 0"""
    )

    # defaults
    for k, v in DEFAULT_SETTINGS.items():
        cur.execute(
            "INSERT OR IGNORE INTO settings(key, value) VALUES(?, ?)",
            (k, json.dumps(v)),
        )
    # default plans (richer catalog)
    now = int(time.time())
    plans = [
        # name, days (legacy), seconds, devices, tier
        ("1 Hour Trial", 0, 3600, 1, "std"),
        ("6 Hours", 0, 6 * 3600, 1, "std"),
        ("12 Hours", 0, 12 * 3600, 1, "std"),
        ("1 Day", 1, 86400, 1, "std"),
        ("3 Days", 3, 3 * 86400, 1, "std"),
        ("7 Days", 7, 7 * 86400, 1, "std"),
        ("30 Days", 30, 30 * 86400, 1, "std"),
        ("90 Days VIP", 90, 90 * 86400, 2, "vip"),
        ("Lifetime VIP", 0, 0, 2, "vip"),
        ("Owner Seat", 0, 0, 5, "owner"),
    ]
    for name, days, secs, devs, tier in plans:
        cur.execute(
            """INSERT OR IGNORE INTO plans(name, duration_days, max_devices, tier, features, created_at, duration_seconds)
               VALUES(?,?,?,?,?,?,?)""",
            (name, days, devs, tier, 0xFFFF, now, secs),
        )
    con.commit()
    con.close()


def duration_to_seconds(value: Any, unit: str = "days") -> int:
    """Convert UI amount + unit → seconds. unit: minutes|hours|days|weeks|months|lifetime."""
    u = (unit or "days").lower().strip()
    if u in ("lifetime", "life", "forever", "0"):
        return 0
    try:
        v = float(value)
    except Exception:
        v = 0
    if v <= 0:
        return 0
    mult = {
        "minute": 60,
        "minutes": 60,
        "min": 60,
        "mins": 60,
        "hour": 3600,
        "hours": 3600,
        "hr": 3600,
        "hrs": 3600,
        "h": 3600,
        "day": 86400,
        "days": 86400,
        "d": 86400,
        "week": 7 * 86400,
        "weeks": 7 * 86400,
        "w": 7 * 86400,
        "month": 30 * 86400,
        "months": 30 * 86400,
        "mo": 30 * 86400,
    }.get(u, 86400)
    return int(v * mult)


def format_duration(seconds: int) -> str:
    s = int(seconds or 0)
    if s <= 0:
        return "Lifetime"
    if s < 3600:
        m = max(1, s // 60)
        return f"{m} min"
    if s < 86400:
        h = s / 3600
        return f"{int(h)}h" if h == int(h) else f"{h:.1f}h"
    d = s / 86400
    if d < 7:
        return f"{int(d)}d" if d == int(d) else f"{d:.1f}d"
    if d < 30:
        w = d / 7
        return f"{int(w)}w" if w == int(w) else f"{w:.1f}w"
    mo = d / 30
    return f"{int(mo)}mo" if mo == int(mo) else f"{mo:.1f}mo"


def license_duration_seconds(lic: dict) -> int:
    sec = int(lic.get("duration_seconds") or 0)
    if sec > 0:
        return sec
    days = int(lic.get("duration_days") or 0)
    return days * 86400 if days > 0 else 0


def get_setting(key: str, default: Any = None) -> Any:
    con = connect()
    row = con.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    con.close()
    if not row:
        return DEFAULT_SETTINGS.get(key, default)
    try:
        return json.loads(row["value"])
    except Exception:
        return row["value"]


def set_setting(key: str, value: Any) -> None:
    con = connect()
    con.execute(
        "INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, json.dumps(value)),
    )
    con.commit()
    con.close()
    audit("owner", "settings.set", f"{key}={value!r}")


def all_settings() -> dict[str, Any]:
    con = connect()
    rows = con.execute("SELECT key, value FROM settings").fetchall()
    con.close()
    out = dict(DEFAULT_SETTINGS)
    for r in rows:
        try:
            out[r["key"]] = json.loads(r["value"])
        except Exception:
            out[r["key"]] = r["value"]
    return out


def audit(actor: str, action: str, detail: str = "") -> None:
    con = connect()
    con.execute(
        "INSERT INTO audit(ts, actor, action, detail) VALUES(?,?,?,?)",
        (int(time.time()), actor, action, detail[:2000]),
    )
    con.commit()
    con.close()


def list_audit(limit: int = 200) -> list[dict]:
    con = connect()
    rows = con.execute(
        "SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]


def list_plans(active_only: bool = False) -> list[dict]:
    con = connect()
    q = "SELECT * FROM plans"
    if active_only:
        q += " WHERE active=1"
    q += " ORDER BY duration_seconds ASC, duration_days ASC, id ASC"
    rows = con.execute(q).fetchall()
    con.close()
    out = []
    for r in rows:
        d = dict(r)
        sec = int(d.get("duration_seconds") or 0)
        if sec <= 0 and int(d.get("duration_days") or 0) > 0:
            sec = int(d["duration_days"]) * 86400
            d["duration_seconds"] = sec
        d["duration_human"] = format_duration(sec)
        out.append(d)
    return out


def upsert_plan(data: dict) -> int:
    con = connect()
    now = int(time.time())
    # accept duration_seconds or value+unit
    if "duration_seconds" in data:
        secs = int(data["duration_seconds"] or 0)
    else:
        secs = duration_to_seconds(data.get("duration_value", data.get("duration_days", 30)), data.get("duration_unit", "days"))
    days_legacy = 0 if secs <= 0 else max(1, secs // 86400) if secs >= 86400 else 0
    if data.get("id"):
        con.execute(
            """UPDATE plans SET name=?, duration_days=?, max_devices=?, tier=?, features=?,
               price_note=?, active=?, duration_seconds=? WHERE id=?""",
            (
                data["name"],
                days_legacy,
                int(data.get("max_devices", 1)),
                data.get("tier", "std"),
                int(data.get("features", 0xFFFF)),
                data.get("price_note", ""),
                1 if data.get("active", True) else 0,
                secs,
                int(data["id"]),
            ),
        )
        pid = int(data["id"])
    else:
        cur = con.execute(
            """INSERT INTO plans(name, duration_days, max_devices, tier, features, price_note, active, created_at, duration_seconds)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                data["name"],
                days_legacy,
                int(data.get("max_devices", 1)),
                data.get("tier", "std"),
                int(data.get("features", 0xFFFF)),
                data.get("price_note", ""),
                1 if data.get("active", True) else 0,
                now,
                secs,
            ),
        )
        pid = cur.lastrowid
    con.commit()
    con.close()
    audit("owner", "plan.upsert", str(data))
    return int(pid)


def create_license(
    token: str,
    token_fp: str,
    *,
    plan_id: Optional[int] = None,
    customer: str = "",
    note: str = "",
    tier: str = "std",
    max_devices: int = 1,
    duration_days: int = 30,
    duration_seconds: Optional[int] = None,
    duration_label: str = "",
    start_mode: str = "first_use",  # first_use | immediate
    reseller: str = "",
    features: int = 0xFFFF,
) -> int:
    now = int(time.time())
    if duration_seconds is None:
        secs = duration_days * 86400 if duration_days and duration_days > 0 else 0
    else:
        secs = int(duration_seconds)
    days_legacy = 0 if secs <= 0 else max(1, secs // 86400) if secs >= 86400 else 0
    label = duration_label or format_duration(secs)
    # immediate start: set expires_at now
    activated = 0
    expires = 0
    if start_mode == "immediate":
        activated = now
        expires = 0 if secs <= 0 else now + secs
    con = connect()
    cur = con.execute(
        """INSERT INTO licenses(token, token_fp, plan_id, customer, note, tier, status,
           max_devices, duration_days, expires_at, activated_at, created_at, features,
           duration_seconds, duration_label, start_mode, reseller)
           VALUES(?,?,?,?,?,?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            token,
            token_fp,
            plan_id,
            customer,
            note,
            tier,
            max_devices,
            days_legacy,
            expires,
            activated,
            now,
            features,
            secs,
            label,
            start_mode,
            reseller,
        ),
    )
    lid = cur.lastrowid
    con.commit()
    con.close()
    audit("owner", "license.create", f"id={lid} customer={customer} tier={tier} dur={label}")
    return int(lid)


def get_license_by_token(token: str) -> Optional[dict]:
    from .crypto_v2 import normalize_token, token_fingerprint

    fp = token_fingerprint(normalize_token(token))
    con = connect()
    row = con.execute("SELECT * FROM licenses WHERE token_fp=?", (fp,)).fetchone()
    con.close()
    return dict(row) if row else None


def get_license(lid: int) -> Optional[dict]:
    con = connect()
    row = con.execute("SELECT * FROM licenses WHERE id=?", (lid,)).fetchone()
    con.close()
    return dict(row) if row else None


def list_licenses(status: Optional[str] = None, q: str = "", limit: int = 500) -> list[dict]:
    con = connect()
    sql = "SELECT * FROM licenses WHERE 1=1"
    args: list[Any] = []
    if status:
        sql += " AND status=?"
        args.append(status)
    if q:
        sql += " AND (customer LIKE ? OR note LIKE ? OR token LIKE ? OR token_fp LIKE ? OR reseller LIKE ?)"
        like = f"%{q}%"
        args.extend([like, like, like, like, like])
    lim = max(1, min(int(limit or 500), 20000))
    sql += f" ORDER BY id DESC LIMIT {lim}"
    rows = con.execute(sql, args).fetchall()
    con.close()
    out = []
    for r in rows:
        d = dict(r)
        sec = license_duration_seconds(d)
        d["duration_seconds"] = sec
        d["duration_label"] = d.get("duration_label") or format_duration(sec)
        out.append(d)
    return out


def licenses_csv(status: Optional[str] = None, q: str = "") -> str:
    """Full CSV export for owner backup / delivery sheets."""
    import csv
    import io

    rows = list_licenses(status, q, limit=20000)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(
        [
            "id",
            "token",
            "customer",
            "note",
            "status",
            "tier",
            "max_devices",
            "duration_label",
            "duration_seconds",
            "start_mode",
            "reseller",
            "created_at",
            "activated_at",
            "expires_at",
            "banned_reason",
        ]
    )
    for d in rows:
        w.writerow(
            [
                d.get("id"),
                d.get("token"),
                d.get("customer") or "",
                d.get("note") or "",
                d.get("status"),
                d.get("tier"),
                d.get("max_devices"),
                d.get("duration_label") or "",
                d.get("duration_seconds") or 0,
                d.get("start_mode") or "",
                d.get("reseller") or "",
                d.get("created_at") or 0,
                d.get("activated_at") or 0,
                d.get("expires_at") or 0,
                d.get("banned_reason") or "",
            ]
        )
    return buf.getvalue()


def update_license(lid: int, **fields: Any) -> None:
    if not fields:
        return
    cols = ", ".join(f"{k}=?" for k in fields)
    con = connect()
    con.execute(f"UPDATE licenses SET {cols} WHERE id=?", (*fields.values(), lid))
    con.commit()
    con.close()
    audit("owner", "license.update", f"id={lid} {fields}")


def ban_license(lid: int, reason: str = "") -> None:
    update_license(lid, status="banned", banned_reason=reason)
    # revoke sessions
    con = connect()
    con.execute("UPDATE sessions SET revoked=1 WHERE license_id=?", (lid,))
    con.commit()
    con.close()
    audit("owner", "license.ban", f"id={lid} {reason}")


def unban_license(lid: int) -> None:
    update_license(lid, status="active", banned_reason="")


def extend_license(lid: int, days: int = 0, seconds: int = 0) -> None:
    lic = get_license(lid)
    if not lic:
        return
    now = int(time.time())
    exp = int(lic["expires_at"] or 0)
    add = int(seconds or 0) or int(days or 0) * 86400
    if add <= 0:
        return
    base = exp if exp > now else now
    # lifetime unused with no expiry — convert to timed from now
    update_license(lid, expires_at=base + add, status="active")


def list_devices(license_id: int) -> list[dict]:
    con = connect()
    rows = con.execute(
        "SELECT * FROM devices WHERE license_id=? ORDER BY last_seen DESC", (license_id,)
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]


def bind_device(license_id: int, hwid_hash: str, hwid_raw: str = "") -> tuple[bool, str]:
    lic = get_license(license_id)
    if not lic:
        return False, "License missing"
    now = int(time.time())
    con = connect()
    existing = con.execute(
        "SELECT * FROM devices WHERE license_id=? AND hwid_hash=?",
        (license_id, hwid_hash),
    ).fetchone()
    if existing:
        con.execute(
            "UPDATE devices SET last_seen=?, hwid_raw=? WHERE id=?",
            (now, hwid_raw, existing["id"]),
        )
        con.commit()
        con.close()
        return True, "ok"
    count = con.execute(
        "SELECT COUNT(*) AS c FROM devices WHERE license_id=?", (license_id,)
    ).fetchone()["c"]
    if count >= int(lic["max_devices"]):
        con.close()
        return False, "Device limit reached — contact owner for HWID reset"
    con.execute(
        """INSERT INTO devices(license_id, hwid_hash, hwid_raw, first_seen, last_seen)
           VALUES(?,?,?,?,?)""",
        (license_id, hwid_hash, hwid_raw, now, now),
    )
    con.commit()
    con.close()
    return True, "bound"


def reset_hwid(license_id: int) -> None:
    con = connect()
    con.execute("DELETE FROM devices WHERE license_id=?", (license_id,))
    con.execute("UPDATE sessions SET revoked=1 WHERE license_id=?", (license_id,))
    con.commit()
    con.close()
    audit("owner", "license.hwid_reset", f"id={license_id}")


def save_session(
    license_id: int,
    jti: str,
    hwid_hash: str,
    token: str,
    issued_at: int,
    expires_at: int,
    ip: str = "",
) -> None:
    con = connect()
    con.execute(
        """INSERT INTO sessions(license_id, jti, hwid_hash, token, issued_at, expires_at, ip)
           VALUES(?,?,?,?,?,?,?)""",
        (license_id, jti, hwid_hash, token, issued_at, expires_at, ip),
    )
    con.commit()
    con.close()


def revoke_session(jti: str) -> None:
    con = connect()
    con.execute("UPDATE sessions SET revoked=1 WHERE jti=?", (jti,))
    con.commit()
    con.close()


def is_session_revoked(jti: str) -> bool:
    con = connect()
    row = con.execute("SELECT revoked FROM sessions WHERE jti=?", (jti,)).fetchone()
    con.close()
    return bool(row and row["revoked"])


def list_sessions(active_only: bool = True) -> list[dict]:
    now = int(time.time())
    con = connect()
    if active_only:
        rows = con.execute(
            """SELECT s.*, l.customer, l.token FROM sessions s
               JOIN licenses l ON l.id=s.license_id
               WHERE s.revoked=0 AND s.expires_at>? ORDER BY s.id DESC LIMIT 200""",
            (now,),
        ).fetchall()
    else:
        rows = con.execute(
            """SELECT s.*, l.customer, l.token FROM sessions s
               JOIN licenses l ON l.id=s.license_id
               ORDER BY s.id DESC LIMIT 200"""
        ).fetchall()
    con.close()
    return [dict(r) for r in rows]


def kick_all_sessions() -> int:
    con = connect()
    cur = con.execute("UPDATE sessions SET revoked=1 WHERE revoked=0")
    n = cur.rowcount
    con.commit()
    con.close()
    audit("owner", "sessions.kick_all", f"n={n}")
    return n


def blacklist_add(kind: str, value: str, reason: str = "") -> None:
    con = connect()
    con.execute(
        "INSERT OR REPLACE INTO blacklist(kind, value, reason, created_at) VALUES(?,?,?,?)",
        (kind, value, reason, int(time.time())),
    )
    con.commit()
    con.close()
    audit("owner", "blacklist.add", f"{kind}:{value}")


def blacklist_remove(bid: int) -> None:
    con = connect()
    con.execute("DELETE FROM blacklist WHERE id=?", (bid,))
    con.commit()
    con.close()


def blacklist_hit(kind: str, value: str) -> bool:
    con = connect()
    row = con.execute(
        "SELECT id FROM blacklist WHERE kind=? AND value=?", (kind, value)
    ).fetchone()
    con.close()
    return row is not None


def list_blacklist() -> list[dict]:
    con = connect()
    rows = con.execute("SELECT * FROM blacklist ORDER BY id DESC").fetchall()
    con.close()
    return [dict(r) for r in rows]


def rate_check(key: str, max_fails: int, ban_sec: int) -> tuple[bool, str]:
    now = int(time.time())
    con = connect()
    row = con.execute("SELECT * FROM rate_limit WHERE key=?", (key,)).fetchone()
    if row and int(row["blocked_until"]) > now:
        con.close()
        return False, "Temporarily blocked — try later"
    if not row or now - int(row["window_start"]) > 3600:
        con.execute(
            "INSERT OR REPLACE INTO rate_limit(key, fails, window_start, blocked_until) VALUES(?,0,?,0)",
            (key, now),
        )
        con.commit()
        con.close()
        return True, "ok"
    con.close()
    return True, "ok"


def rate_fail(key: str, max_fails: int, ban_sec: int) -> None:
    now = int(time.time())
    con = connect()
    row = con.execute("SELECT * FROM rate_limit WHERE key=?", (key,)).fetchone()
    if not row or now - int(row["window_start"]) > 3600:
        con.execute(
            "INSERT OR REPLACE INTO rate_limit(key, fails, window_start, blocked_until) VALUES(?,1,?,0)",
            (key, now),
        )
    else:
        fails = int(row["fails"]) + 1
        blocked = now + ban_sec if fails >= max_fails else 0
        con.execute(
            "UPDATE rate_limit SET fails=?, blocked_until=? WHERE key=?",
            (fails, blocked, key),
        )
    con.commit()
    con.close()


def rate_ok(key: str) -> None:
    con = connect()
    con.execute("DELETE FROM rate_limit WHERE key=?", (key,))
    con.commit()
    con.close()


def stats() -> dict[str, Any]:
    now = int(time.time())
    con = connect()
    def c(q, *a):
        return con.execute(q, a).fetchone()[0]

    out = {
        "licenses_total": c("SELECT COUNT(*) FROM licenses"),
        "licenses_active": c("SELECT COUNT(*) FROM licenses WHERE status='active'"),
        "licenses_banned": c("SELECT COUNT(*) FROM licenses WHERE status='banned'"),
        "licenses_expired": c(
            "SELECT COUNT(*) FROM licenses WHERE status='active' AND expires_at>0 AND expires_at<?",
            now,
        ),
        "sessions_live": c(
            "SELECT COUNT(*) FROM sessions WHERE revoked=0 AND expires_at>?", now
        ),
        "devices": c("SELECT COUNT(*) FROM devices"),
        "blacklist": c("SELECT COUNT(*) FROM blacklist"),
        "plans": c("SELECT COUNT(*) FROM plans WHERE active=1"),
        "resellers": c("SELECT COUNT(*) FROM resellers WHERE active=1"),
    }
    con.close()
    return out


# ---- resellers (least privilege) ----

def _hash_reseller_pw(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)


def create_reseller(
    name: str,
    password: str,
    *,
    quota: int = 50,
    max_duration_seconds: int = 2592000,
    max_devices: int = 1,
    note: str = "",
) -> dict:
    import secrets as _secrets

    name = (name or "").strip()
    if not name or len(password) < 6:
        raise ValueError("name and password (6+ chars) required")
    salt = _secrets.token_bytes(16)
    ph = salt.hex() + ":" + _hash_reseller_pw(password, salt).hex()
    api_key = _secrets.token_urlsafe(24)
    now = int(time.time())
    con = connect()
    try:
        cur = con.execute(
            """INSERT INTO resellers(name, api_key, password_hash, quota, used, max_duration_seconds,
               max_devices, can_reset_hwid, active, created_at, note)
               VALUES(?,?,?,?,0,?,?,1,1,?,?)""",
            (name, api_key, ph, int(quota), int(max_duration_seconds), int(max_devices), now, note),
        )
        rid = int(cur.lastrowid)
        con.commit()
    except Exception as e:
        con.close()
        raise ValueError(str(e)) from e
    con.close()
    audit("owner", "reseller.create", f"id={rid} name={name}")
    return {"id": rid, "name": name, "quota": quota, "used": 0, "max_duration_seconds": max_duration_seconds, "max_devices": max_devices}


def list_resellers() -> list[dict]:
    con = connect()
    rows = con.execute(
        """SELECT id, name, quota, used, max_duration_seconds, max_devices, can_reset_hwid,
                  active, created_at, note FROM resellers ORDER BY id DESC"""
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]


def get_reseller_by_name(name: str) -> Optional[dict]:
    con = connect()
    row = con.execute(
        "SELECT * FROM resellers WHERE name=? COLLATE NOCASE", ((name or "").strip(),)
    ).fetchone()
    con.close()
    return dict(row) if row else None


def get_reseller(rid: int) -> Optional[dict]:
    con = connect()
    row = con.execute("SELECT * FROM resellers WHERE id=?", (rid,)).fetchone()
    con.close()
    return dict(row) if row else None


def verify_reseller_password(name: str, password: str) -> Optional[dict]:
    r = get_reseller_by_name(name)
    if not r or not r.get("active"):
        return None
    ph = r.get("password_hash") or ""
    if ":" not in ph:
        return None
    salt_hex, dk_hex = ph.split(":", 1)
    try:
        salt = bytes.fromhex(salt_hex)
        got = _hash_reseller_pw(password, salt).hex()
    except Exception:
        return None
    if not hmac.compare_digest(got, dk_hex):
        return None
    return r


def reseller_consume_quota(rid: int, n: int = 1) -> tuple[bool, str]:
    con = connect()
    row = con.execute("SELECT quota, used, active FROM resellers WHERE id=?", (rid,)).fetchone()
    if not row or not row["active"]:
        con.close()
        return False, "Reseller inactive"
    if int(row["used"]) + n > int(row["quota"]):
        con.close()
        return False, f"Quota full ({row['used']}/{row['quota']})"
    con.execute("UPDATE resellers SET used = used + ? WHERE id=?", (n, rid))
    con.commit()
    con.close()
    return True, "ok"


def update_reseller(rid: int, **fields: Any) -> None:
    if not fields:
        return
    cols = ", ".join(f"{k}=?" for k in fields)
    con = connect()
    con.execute(f"UPDATE resellers SET {cols} WHERE id=?", (*fields.values(), rid))
    con.commit()
    con.close()
    audit("owner", "reseller.update", f"id={rid} {list(fields.keys())}")


def list_licenses_for_reseller(name: str) -> list[dict]:
    con = connect()
    rows = con.execute(
        "SELECT * FROM licenses WHERE reseller=? COLLATE NOCASE ORDER BY id DESC LIMIT 300",
        (name,),
    ).fetchall()
    con.close()
    out = []
    for r in rows:
        d = dict(r)
        sec = license_duration_seconds(d)
        d["duration_seconds"] = sec
        d["duration_label"] = d.get("duration_label") or format_duration(sec)
        out.append(d)
    return out
