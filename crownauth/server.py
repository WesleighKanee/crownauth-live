#!/usr/bin/env python3
"""
Control plane — owner panel + client auth API.

Release-hardened:
  - Owner panel requires password / API token (not open to the internet)
  - Stealth mode: generic banners, quiet logs, custom panel path
  - Client errors can be generic
  - Real-time settings still apply on heartbeat
"""
from __future__ import annotations

import json
import os
import secrets
import sys
import threading
import time
import traceback
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from crownauth import db  # noqa: E402
from crownauth import owner_auth  # noqa: E402
from crownauth.crypto_v2 import (  # noqa: E402
    SessionClaims,
    SESSION_VERSION,
    check_proof,
    challenge_nonce,
    hwid_hash,
    issue_offline_envelope,
    load_or_create_keypair,
    mint_license_token,
    normalize_token,
    public_raw_bytes,
    sign_config_blob,
    sign_session,
    token_fingerprint,
    verify_session,
)

STATIC = HERE / "static"
CHALLENGES: dict[str, dict[str, Any]] = {}
CHAL_LOCK = threading.Lock()
PRIV, PUB = load_or_create_keypair()


def json_bytes(obj: Any, code: int = 200) -> tuple[int, bytes, str]:
    return code, json.dumps(obj, separators=(",", ":")).encode("utf-8"), "application/json"


def client_err(msg: str, detail: str = "") -> dict:
    s = db.all_settings()
    if s.get("generic_errors") and s.get("stealth_mode"):
        return {"ok": False, "error": "Access denied"}
    return {"ok": False, "error": msg or detail or "Access denied"}


def live_config() -> dict[str, Any]:
    s = db.all_settings()
    return {
        "v": 2,
        "app_name": s.get("app_name"),
        "force_online": bool(s.get("force_online")),
        "allow_offline_envelope": bool(s.get("allow_offline_envelope")),
        "hybrid_lease": bool(s.get("hybrid_lease", True)),
        "session_ttl_sec": int(s.get("session_ttl_sec", 900)),
        "heartbeat_sec": int(s.get("heartbeat_sec", 120)),
        "maintenance": bool(s.get("maintenance")),
        "kill_switch": bool(s.get("kill_switch")),
        "kill_message": s.get("kill_message"),
        "maintenance_message": s.get("maintenance_message"),
        "brand_tagline": s.get("brand_tagline"),
        "support_url": s.get("support_url"),
        "discord_url": s.get("discord_url"),
        "theme_accent": s.get("theme_accent"),
        "cfg_epoch": int(time.time()),
    }


def signed_live_config() -> str:
    return sign_config_blob(PRIV, live_config())


def _attestation_reject(body: dict, s: dict) -> Optional[str]:
    """Return error string if client environment is hostile; None if OK."""
    if not s.get("require_client_attestation", True):
        return None
    try:
        af = int(body.get("af") or 0)
    except Exception:
        af = 0
    # bitfield from Shield.java
    if s.get("reject_debugger", True) and (af & 1):
        return "Access denied"
    if s.get("reject_frida", True) and (af & 2):
        return "Access denied"
    if s.get("reject_xposed", True) and (af & 4):
        return "Access denied"
    # bit 8 = root — product requires root; NEVER reject
    if s.get("reject_emulator", False) and (af & 16):
        return "Access denied"
    if s.get("reject_integrity_fail", True) and (af & 32):
        return "Access denied"
    bid = str(body.get("bid") or "").strip()
    expect = str(s.get("expected_app_build") or "").strip()
    if s.get("strict_build_id") and expect and bid and bid != expect:
        return "Access denied"
    return None


def client_auth(body: dict, ip: str) -> dict:
    s = db.all_settings()
    if s.get("kill_switch"):
        return client_err(s.get("kill_message") or "Unavailable")
    if s.get("maintenance"):
        return client_err(s.get("maintenance_message") or "Unavailable")

    att_err = _attestation_reject(body, s)
    if att_err:
        return client_err(att_err)

    token = normalize_token(body.get("key") or body.get("token") or "")
    hwid = (body.get("hwid") or "").strip()
    challenge = (body.get("challenge") or "").strip()
    proof = (body.get("proof") or "").strip()
    phase = (body.get("phase") or "login").lower()

    if not token:
        return client_err("Enter your license key")
    if not hwid:
        return client_err("Device id missing")

    rk = f"ip:{ip}"
    ok_rate, msg = db.rate_check(rk, int(s.get("max_failed_auth", 12)), int(s.get("ban_duration_sec", 3600)))
    if not ok_rate:
        try:
            from crownauth import notify as _n

            _n.notify_if(
                "notify_on_auth_fail_flood",
                f"🚫 Rate limit hit\nIP: {ip}\n{msg}",
                kind="rate",
            )
        except Exception:
            pass
        return client_err(msg)

    if db.blacklist_hit("hwid", hwid_hash(hwid)) or db.blacklist_hit("ip", ip):
        return client_err("Access denied")

    if phase == "challenge" or (s.get("require_challenge") and not challenge):
        # Fail closed: do not issue challenges for missing/banned keys
        pre = db.get_license_by_token(token)
        if not pre:
            db.rate_fail(rk, int(s.get("max_failed_auth", 12)), int(s.get("ban_duration_sec", 3600)))
            return client_err("Invalid license key")
        if pre["status"] == "banned":
            return client_err("License banned")
        if pre["status"] != "active":
            return client_err("License inactive")
        now_pre = int(time.time())
        exp_pre = int(pre.get("expires_at") or 0)
        if int(pre.get("activated_at") or 0) > 0 and exp_pre > 0 and now_pre > exp_pre:
            db.update_license(pre["id"], status="expired")
            return client_err("License expired")
        ch = challenge_nonce()
        with CHAL_LOCK:
            CHALLENGES[ch] = {"t": time.time(), "ip": ip, "token_fp": token_fingerprint(token)}
            dead = [k for k, v in CHALLENGES.items() if time.time() - v["t"] > 120]
            for k in dead:
                CHALLENGES.pop(k, None)
        return {"ok": True, "phase": "challenge", "challenge": ch, "server_time": int(time.time())}

    if s.get("require_challenge"):
        with CHAL_LOCK:
            meta = CHALLENGES.pop(challenge, None)
        if not meta or time.time() - meta["t"] > 120:
            db.rate_fail(rk, int(s.get("max_failed_auth", 12)), int(s.get("ban_duration_sec", 3600)))
            return client_err("Challenge expired — retry")
        if not check_proof(token, challenge, hwid, proof):
            db.rate_fail(rk, int(s.get("max_failed_auth", 12)), int(s.get("ban_duration_sec", 3600)))
            return client_err("Challenge proof failed")

    lic = db.get_license_by_token(token)
    if not lic:
        db.rate_fail(rk, int(s.get("max_failed_auth", 12)), int(s.get("ban_duration_sec", 3600)))
        return client_err("Invalid license key")
    if lic["status"] == "banned":
        return client_err("License banned")
    if lic["status"] != "active":
        return client_err("License inactive")

    now = int(time.time())
    first_activation = int(lic["activated_at"] or 0) == 0
    if first_activation:
        secs = db.license_duration_seconds(lic)
        exp = 0 if secs <= 0 else now + secs
        db.update_license(lic["id"], activated_at=now, expires_at=exp)
        lic = db.get_license(lic["id"]) or lic

    exp = int(lic["expires_at"] or 0)
    if exp > 0 and now > exp:
        db.update_license(lic["id"], status="expired")
        return client_err("License expired")

    hh = hwid_hash(hwid)
    bound, bmsg = db.bind_device(lic["id"], hh, hwid)
    if not bound:
        return client_err(bmsg)

    ttl = int(s.get("session_ttl_sec", 900))
    jti = secrets.token_hex(16)
    claims = SessionClaims(
        ver=SESSION_VERSION,
        serial=str(lic["id"]),
        hwid_hash=hh,
        exp=now + ttl,
        iat=now,
        jti=jti,
        flags=0,
        tier=lic.get("tier") or "std",
        features=int(lic.get("features") or 0xFFFF),
        nbf=now - 5,
    )
    session = sign_session(PRIV, claims)
    db.save_session(lic["id"], jti, hh, session, now, now + ttl, ip)
    db.rate_ok(rk)
    db.audit("client", "auth.ok", f"lic={lic['id']}")
    if first_activation:
        try:
            from crownauth import notify as _n

            cust = (lic.get("customer") or "").strip() or "—"
            _n.notify_if(
                "notify_on_activation",
                f"🔑 First login\nID: {lic['id']}\nBuyer: {cust}\nIP: {ip}\nTier: {lic.get('tier') or 'std'}",
                kind="activate",
            )
        except Exception:
            pass

    toast = "Login Successfully..."
    if claims.tier == "owner":
        toast = "Login Successfully... (Owner)"
    elif claims.tier == "vip":
        toast = "Login Successfully... (VIP)"

    # Hybrid lease: after first online login, client may use offline until wall-clock expiry
    # (owner PC can be off). Timer already started via first_use / activated_at above.
    offline_env = ""
    offline_until = int(exp or 0)
    if s.get("hybrid_lease", True) or s.get("allow_offline_envelope"):
        flags = 0
        if claims.tier == "vip":
            flags |= 0x04
        if claims.tier == "owner":
            flags |= 0x08
        offline_env = issue_offline_envelope(
            PRIV,
            serial=int(lic["id"]),
            expire_unix=offline_until,
            flags=flags,
            hwid=hwid,
            features=int(claims.features),
        )

    return {
        "ok": True,
        "phase": "session",
        "session": session,
        "message": toast,
        "expires_at": claims.exp,
        "license_expires_at": offline_until,
        "offline_envelope": offline_env,
        "offline_until": offline_until,
        "heartbeat_sec": int(s.get("heartbeat_sec", 120)),
        "tier": claims.tier,
        "features": claims.features,
        "config": signed_live_config(),
        "license": {
            "id": lic["id"],
            "expires_at": exp,
            "max_devices": lic.get("max_devices"),
        },
    }


def client_heartbeat(body: dict, ip: str) -> dict:
    s = db.all_settings()
    if s.get("kill_switch"):
        return {"ok": False, "error": "Access denied", "action": "kill"}
    if s.get("maintenance"):
        return {"ok": False, "error": "Access denied", "action": "pause"}

    att_err = _attestation_reject(body, s)
    if att_err:
        return {"ok": False, "error": "Access denied", "action": "kill"}

    session = body.get("session") or ""
    hwid = (body.get("hwid") or "").strip()
    hh = hwid_hash(hwid)
    ok, msg, claims = verify_session(PUB, session, expect_hwid_hash=hh if hwid else None)
    if not ok or not claims:
        return {"ok": False, "error": "Access denied", "action": "reauth"}
    if db.is_session_revoked(claims.jti):
        return {"ok": False, "error": "Access denied", "action": "reauth"}

    lic = db.get_license(int(claims.serial))
    if not lic or lic["status"] != "active":
        return {"ok": False, "error": "Access denied", "action": "reauth"}
    exp = int(lic["expires_at"] or 0)
    if exp > 0 and int(time.time()) > exp:
        return {"ok": False, "error": "Access denied", "action": "reauth"}

    refresh = bool(body.get("refresh"))
    out: dict[str, Any] = {
        "ok": True,
        "action": "continue",
        "server_time": int(time.time()),
        "config": signed_live_config(),
        "expires_at": claims.exp,
    }
    if refresh or claims.exp - int(time.time()) < 120:
        ttl = int(s.get("session_ttl_sec", 900))
        now = int(time.time())
        jti = secrets.token_hex(16)
        new_claims = SessionClaims(
            ver=SESSION_VERSION,
            serial=claims.serial,
            hwid_hash=claims.hwid_hash,
            exp=now + ttl,
            iat=now,
            jti=jti,
            flags=claims.flags,
            tier=claims.tier,
            features=claims.features,
            nbf=now - 5,
        )
        new_sess = sign_session(PRIV, new_claims)
        db.revoke_session(claims.jti)
        db.save_session(int(claims.serial), jti, claims.hwid_hash, new_sess, now, now + ttl, ip)
        out["session"] = new_sess
        out["expires_at"] = new_claims.exp
    return out


class Handler(BaseHTTPRequestHandler):
    # steganographic banner — not a product fingerprint
    server_version = "cloudflare-nginx"
    sys_version = ""

    def version_string(self) -> str:
        s = db.all_settings()
        return str(s.get("server_banner") or "cloudflare-nginx")

    def log_message(self, fmt: str, *args: Any) -> None:
        if db.get_setting("quiet_logs", True):
            # only log owner API hits + errors lightly
            try:
                path = urllib.parse.urlparse(self.path).path
            except Exception:
                path = ""
            if path.startswith("/api/") or path.startswith("/auth/"):
                sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))
            return
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _cors(self, owner: bool = False) -> None:
        # same-origin panel; client native HTTP ignores CORS
        if owner:
            self.send_header("Access-Control-Allow-Origin", "null")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Owner-Key")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")

    def _send(self, code: int, data: bytes, ctype: str, extra_headers: Optional[dict] = None) -> None:
        self.send_response(code)
        self._cors()
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            return json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            return {}

    def _ip_allowed_owner(self, ip: str) -> bool:
        """Owner panel/API IP allowlist (client /v2 stays open for customers)."""
        s = db.all_settings()
        if not s.get("enable_owner_ip_allowlist"):
            return True
        rules = s.get("owner_ip_allowlist") or []
        if not rules:
            return True
        ip = (ip or "").strip()
        for rule in rules:
            rule = str(rule).strip()
            if not rule:
                continue
            if "/" in rule:
                # simple IPv4 CIDR
                try:
                    net, bits = rule.split("/", 1)
                    bits = int(bits)
                    def ip2int(x: str) -> int:
                        p = [int(n) for n in x.split(".")]
                        return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]
                    mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
                    if ip.count(".") == 3 and (ip2int(ip) & mask) == (ip2int(net) & mask):
                        return True
                except Exception:
                    continue
            elif rule == ip or (rule == "localhost" and ip in ("127.0.0.1", "::1")):
                return True
        return False

    def _owner_ok(self) -> bool:
        return owner_auth.check_owner_header(
            self.headers.get("Authorization"),
            self.headers.get("X-Owner-Key"),
            self.headers.get("Cookie"),
        )

    def _password_required(self) -> bool:
        return bool(db.get_setting("panel_password_enabled", False))

    def _require_owner(self) -> bool:
        if not self._ip_allowed_owner(self._ip()):
            self._json({"ok": False, "error": "Forbidden"}, 403)
            return False
        # LAN mode: no password — IP allowlist is enough
        if not self._password_required():
            return True
        if self._owner_ok():
            return True
        self._json({"ok": False, "error": "Unauthorized"}, 401)
        return False

    def do_HEAD(self) -> None:  # noqa: N802
        """UptimeRobot and similar monitors often use HEAD — was 501 before."""
        path = urllib.parse.urlparse(self.path).path
        cpre = self._client_prefix()
        if path in (cpre + "/health", "/health", "/"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return
        # fall through: same routing as GET but we still may send a body; prefer 200 on known GETs
        try:
            self.do_GET()
        except Exception:
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        try:
            self._route_get()
        except Exception:
            if not db.get_setting("quiet_logs", True):
                traceback.print_exc()
            self._json({"ok": False, "error": "error"}, 500)

    def do_POST(self) -> None:  # noqa: N802
        try:
            self._route_post()
        except Exception:
            if not db.get_setting("quiet_logs", True):
                traceback.print_exc()
            self._json({"ok": False, "error": "error"}, 500)

    def _ip(self) -> str:
        # Cloudflare / reverse proxy client IP
        cf = self.headers.get("CF-Connecting-IP")
        if cf:
            return cf.strip()
        xff = self.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
        return self.client_address[0]

    def _reseller_session(self) -> Optional[dict]:
        auth = self.headers.get("Authorization") or ""
        tok = ""
        if auth.lower().startswith("bearer "):
            tok = auth[7:].strip()
        if not tok:
            cookie = self.headers.get("Cookie") or ""
            for part in cookie.split(";"):
                part = part.strip()
                if part.startswith("rs_session="):
                    tok = part.split("=", 1)[1].strip()
        return owner_auth.get_reseller_session(tok)

    def _client_prefix(self) -> str:
        p = str(db.get_setting("client_api_prefix") or "/v2").rstrip("/") or "/v2"
        if not p.startswith("/"):
            p = "/" + p
        return p

    def _panel_path(self) -> str:
        p = str(db.get_setting("panel_path") or "/console").rstrip("/") or "/console"
        if not p.startswith("/"):
            p = "/" + p
        return p

    def _owner_paths(self) -> set[str]:
        """Fixed MetaPlus-style owner URLs + legacy aliases."""
        pp = self._panel_path()
        paths = {
            pp,
            pp + "/",
            pp + "/index.html",
            "/panel",
            "/console",
            "/app/owner/auth/login",
            "/app/owner/auth/login/",
            "/app/member/auth/login",
            "/app/member/auth/login/",
        }
        return paths

    def _user_paths(self) -> set[str]:
        """Fixed MetaPlus-style reseller/user portal URLs + legacy aliases."""
        return {
            "/reseller",
            "/reseller/",
            "/reseller/index.html",
            "/app/user/auth/login",
            "/app/user/auth/login/",
            "/app/reseller/auth/login",
            "/app/reseller/auth/login/",
        }

    def _route_get(self) -> None:
        path = urllib.parse.urlparse(self.path).path
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        cpre = self._client_prefix()
        pp = self._panel_path()
        owner_login = "/app/owner/auth/login"
        user_login = "/app/user/auth/login"

        # root — friendly landing (fixed links, MetaPlus-style)
        if path == "/":
            host = (db.get_setting("client_api_host") or "").strip()
            scheme = (db.get_setting("client_api_scheme") or "https").strip()
            base = f"{scheme}://{host}" if host else ""
            html = f"""<!DOCTYPE html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>WhiteCrown Auth</title>
<style>body{{font-family:system-ui,sans-serif;background:#0a0a0c;color:#eee;max-width:520px;margin:48px auto;padding:0 16px;line-height:1.5}}
a{{color:#e8c547}} .card{{background:#14141a;border:1px solid #222;border-radius:14px;padding:20px;margin:16px 0}}
code{{background:#222;padding:2px 6px;border-radius:6px;font-size:13px;word-break:break-all}}</style></head><body>
<h1>WhiteCrown Auth</h1>
<p>API is online. Bookmark the fixed links for your role:</p>
<div class=card><b>Owner</b><br>
<code>{owner_login}</code><br>
<a href="{owner_login}">Open owner login →</a>
{f'<br><small style=opacity:.7>{base}{owner_login}</small>' if base else ''}</div>
<div class=card><b>Reseller / seller</b><br>
<code>{user_login}</code><br>
<a href="{user_login}">Open seller login →</a>
{f'<br><small style=opacity:.7>{base}{user_login}</small>' if base else ''}</div>
<div class=card><b>App (phones)</b><br>Health: <a href="{cpre}/health">{cpre}/health</a></div>
</body></html>"""
            return self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")

        # owner panel (fixed + legacy paths)
        if path in self._owner_paths():
            if db.get_setting("enable_owner_ip_allowlist") and not self._ip_allowed_owner(self._ip()):
                return self._send(403, b"Forbidden from this network", "text/plain")
            return self._file(STATIC / "index.html", "text/html; charset=utf-8")

        # reseller / user portal (fixed + legacy)
        if path in self._user_paths():
            return self._file(STATIC / "reseller.html", "text/html; charset=utf-8")

        if path.startswith("/static/"):
            rel = path[len("/static/") :]
            fp = (STATIC / rel).resolve()
            if not str(fp).startswith(str(STATIC.resolve())):
                return self._send(403, b"forbidden", "text/plain")
            if not fp.exists():
                return self._send(404, b"missing", "text/plain")
            ctype = "text/plain"
            if fp.suffix == ".css":
                ctype = "text/css"
            elif fp.suffix == ".js":
                ctype = "application/javascript"
            elif fp.suffix == ".html":
                ctype = "text/html; charset=utf-8"
            return self._file(fp, ctype)

        # client public API
        if path == cpre + "/health":
            s = db.all_settings()
            # minimal fingerprint + build stamp (confirms Render deploy)
            return self._json(
                {
                    "ok": True,
                    "m": 1 if s.get("maintenance") else 0,
                    "k": 1 if s.get("kill_switch") else 0,
                    "t": int(time.time()),
                    "b": "harden_v2",
                }
            )
        if path == cpre + "/config":
            out: dict[str, Any] = {"ok": True, "config": signed_live_config()}
            if db.get_setting("expose_plain_config"):
                out["plain"] = live_config()
            return self._json(out)
        if path == cpre + "/pubkey":
            if not db.get_setting("expose_pubkey"):
                return self._send(404, b"Not Found", "text/plain")
            return self._json({"ok": True, "k": public_raw_bytes(PUB).hex()})

        # auth status for panel (no secret leak)
        if path == "/auth/status":
            allowed = self._ip_allowed_owner(self._ip())
            pwd_on = self._password_required()
            authed = False
            if allowed and not pwd_on:
                authed = True
            elif allowed and (self._owner_ok()):
                authed = True
            return self._json(
                {
                    "ok": True,
                    "authed": authed,
                    "password_required": pwd_on,
                    "ip_allowed": allowed,
                    "has_password": owner_auth.has_password(),
                    "panel_path": pp,
                    "app_name": db.get_setting("app_name") or "Console",
                }
            )

        # reseller API (read)
        if path == "/reseller/api/me":
            rs = self._reseller_session()
            if not rs:
                return self._json({"ok": False, "error": "Please log in"}, 401)
            r = db.get_reseller(int(rs["id"]))
            if not r:
                return self._json({"ok": False, "error": "Account missing"}, 401)
            return self._json(
                {
                    "ok": True,
                    "name": r["name"],
                    "quota": r["quota"],
                    "used": r["used"],
                    "left": int(r["quota"]) - int(r["used"]),
                    "max_duration_seconds": r.get("max_duration_seconds") or 2592000,
                    "max_devices": r.get("max_devices") or 1,
                    "can_reset_hwid": bool(r.get("can_reset_hwid", 1)),
                }
            )
        if path == "/reseller/api/licenses":
            rs = self._reseller_session()
            if not rs:
                return self._json({"ok": False, "error": "Please log in"}, 401)
            return self._json({"ok": True, "items": db.list_licenses_for_reseller(rs["name"])})

        # owner API
        if path.startswith("/api/"):
            if not self._require_owner():
                return
            if path == "/api/dashboard":
                return self._json(
                    {
                        "ok": True,
                        "stats": db.stats(),
                        "settings": db.all_settings(),
                        "time": int(time.time()),
                    }
                )
            if path == "/api/resellers":
                return self._json({"ok": True, "items": db.list_resellers()})
            if path == "/api/licenses":
                status = (qs.get("status") or [None])[0]
                q = (qs.get("q") or [""])[0]
                return self._json({"ok": True, "items": db.list_licenses(status, q)})
            if path == "/api/licenses/export.csv":
                status = (qs.get("status") or [None])[0]
                q = (qs.get("q") or [""])[0]
                csv_text = db.licenses_csv(status, q)
                extra = {
                    "Content-Disposition": 'attachment; filename="whitecrown_licenses.csv"',
                    "Cache-Control": "no-store",
                }
                return self._send(200, csv_text.encode("utf-8"), "text/csv; charset=utf-8", extra_headers=extra)
            if path == "/api/plans":
                return self._json({"ok": True, "items": db.list_plans()})
            if path == "/api/sessions":
                return self._json({"ok": True, "items": db.list_sessions(True)})
            if path == "/api/blacklist":
                return self._json({"ok": True, "items": db.list_blacklist()})
            if path == "/api/audit":
                return self._json({"ok": True, "items": db.list_audit(300)})
            if path == "/api/settings":
                return self._json({"ok": True, "settings": db.all_settings()})
            if path == "/api/ops/status":
                # free-tier ops glance for panel
                return self._json(
                    {
                        "ok": True,
                        "github_backup": bool(
                            (os.environ.get("GITHUB_TOKEN") or "").strip()
                            and (os.environ.get("GITHUB_BACKUP_REPO") or "").strip()
                        ),
                        "public_host": (os.environ.get("PUBLIC_HOST") or db.get_setting("client_api_host") or ""),
                        "build": "launch_pack_v1",
                    }
                )
            if path.startswith("/api/licenses/") and path.endswith("/devices"):
                lid = int(path.split("/")[3])
                return self._json({"ok": True, "items": db.list_devices(lid)})
            if path == "/api/me":
                return self._json({"ok": True, "token_hint": owner_auth.load_or_create_api_token()[:6] + "…"})

        return self._send(404, b"Not Found", "text/plain")

    def _route_post(self) -> None:
        path = urllib.parse.urlparse(self.path).path
        body = self._read_json()
        ip = self._ip()
        cpre = self._client_prefix()

        # owner login (no LAN-only block when public Cloudflare)
        if path == "/auth/login":
            if db.get_setting("enable_owner_ip_allowlist") and not self._ip_allowed_owner(ip):
                return self._json({"ok": False, "error": "Forbidden from this network"}, 403)
            pw = body.get("password") or ""
            if not owner_auth.has_password():
                owner_auth.bootstrap_if_needed()
            if owner_auth.verify_password(pw):
                sess = owner_auth.issue_session()
                db.audit("owner", "login.ok", ip)
                return self._json(
                    {"ok": True, "session": sess},
                    extra={"Set-Cookie": f"oc_session={sess}; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200"},
                )
            db.audit("owner", "login.fail", ip)
            return self._json({"ok": False, "error": "Invalid password"}, 401)

        # reseller login
        if path == "/reseller/api/login":
            name = (body.get("name") or body.get("username") or "").strip()
            pw = body.get("password") or ""
            r = db.verify_reseller_password(name, pw)
            if not r:
                return self._json({"ok": False, "error": "Wrong name or password"}, 401)
            sess = owner_auth.issue_reseller_session(int(r["id"]), r["name"])
            db.audit("reseller", "login.ok", r["name"])
            return self._json(
                {"ok": True, "session": sess, "name": r["name"]},
                extra={"Set-Cookie": f"rs_session={sess}; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200"},
            )

        if path == "/reseller/api/logout":
            return self._json(
                {"ok": True},
                extra={"Set-Cookie": "rs_session=; Path=/; Max-Age=0"},
            )

        if path == "/reseller/api/licenses/create":
            rs = self._reseller_session()
            if not rs:
                return self._json({"ok": False, "error": "Please log in"}, 401)
            r = db.get_reseller(int(rs["id"]))
            if not r or not r.get("active"):
                return self._json({"ok": False, "error": "Inactive"}, 403)
            qty = max(1, min(50, int(body.get("qty") or 1)))
            # duration limits
            if body.get("duration_unit") == "lifetime" or body.get("lifetime"):
                secs = 0
            elif body.get("duration_value") is not None:
                secs = db.duration_to_seconds(body.get("duration_value"), body.get("duration_unit") or "days")
            else:
                secs = int(body.get("duration_seconds") or 86400)
            max_sec = int(r.get("max_duration_seconds") or 2592000)
            if secs <= 0 or secs > max_sec:
                # block lifetime unless owner allowed max=0 meaning unlimited — treat 0 max as no lifetime for resellers
                if secs <= 0:
                    return self._json({"ok": False, "error": "Resellers cannot mint lifetime keys"}, 400)
                if secs > max_sec:
                    return self._json(
                        {"ok": False, "error": f"Max length for you is {db.format_duration(max_sec)}"},
                        400,
                    )
            maxd = min(int(body.get("max_devices") or 1), int(r.get("max_devices") or 1))
            ok_q, msg_q = db.reseller_consume_quota(int(r["id"]), qty)
            if not ok_q:
                return self._json({"ok": False, "error": msg_q}, 400)
            created = []
            for _ in range(qty):
                tok = mint_license_token(
                    prefix=str(body.get("key_prefix") or "WC"),
                    length=int(body.get("key_length") or 8),
                )
                lid = db.create_license(
                    tok,
                    token_fingerprint(tok),
                    customer=body.get("customer") or "",
                    note=body.get("note") or f"via reseller {r['name']}",
                    tier="std",
                    max_devices=maxd,
                    duration_seconds=secs,
                    duration_label=db.format_duration(secs),
                    start_mode=body.get("start_mode") or "first_use",
                    reseller=r["name"],
                )
                created.append({"id": lid, "token": tok, "duration": db.format_duration(secs)})
            return self._json({"ok": True, "created": created})

        if path == "/reseller/api/licenses/hwid_reset":
            rs = self._reseller_session()
            if not rs:
                return self._json({"ok": False, "error": "Please log in"}, 401)
            r = db.get_reseller(int(rs["id"]))
            if not r or not r.get("can_reset_hwid"):
                return self._json({"ok": False, "error": "Not allowed"}, 403)
            lic = db.get_license(int(body.get("id") or 0))
            if not lic or (lic.get("reseller") or "").lower() != r["name"].lower():
                return self._json({"ok": False, "error": "Not your key"}, 403)
            db.reset_hwid(int(lic["id"]))
            return self._json({"ok": True})

        if path == "/auth/logout":
            return self._json(
                {"ok": True},
                extra={"Set-Cookie": "oc_session=; Path=/; Max-Age=0"},
            )

        if path == "/auth/change_password":
            if not self._require_owner():
                return
            old = body.get("old_password") or ""
            new = body.get("new_password") or ""
            if not owner_auth.verify_password(old):
                return self._json({"ok": False, "error": "Old password wrong"}, 400)
            try:
                owner_auth.set_password(new)
            except ValueError as e:
                return self._json({"ok": False, "error": str(e)}, 400)
            db.audit("owner", "password.changed", "")
            persist_msg = "local only"
            try:
                from crownauth.persist import schedule_backup, sync_owner_password_to_render

                ok_s, persist_msg = sync_owner_password_to_render(new)
                schedule_backup()
            except Exception as e:
                persist_msg = str(e)
            return self._json({"ok": True, "persist": persist_msg})

        # client
        if path == cpre + "/auth":
            return self._json(client_auth(body, ip))
        if path == cpre + "/heartbeat":
            return self._json(client_heartbeat(body, ip))

        # owner mutations
        if path.startswith("/api/"):
            if not self._require_owner():
                return

            if path == "/api/settings":
                for k, v in body.items():
                    if k in db.DEFAULT_SETTINGS or k in db.all_settings():
                        db.set_setting(k, v)
                try:
                    from crownauth.persist import schedule_backup

                    schedule_backup()
                except Exception:
                    pass
                return self._json({"ok": True, "settings": db.all_settings(), "config": signed_live_config()})

            if path == "/api/licenses/create":
                plan_id = body.get("plan_id")
                plan = None
                if plan_id not in (None, "", "custom", "0", 0):
                    plans = {p["id"]: p for p in db.list_plans()}
                    try:
                        plan = plans.get(int(plan_id))
                    except Exception:
                        plan = None
                qty = max(1, min(500, int(body.get("qty") or 1)))

                # duration: prefer value+unit, then seconds, then plan, then days legacy
                if body.get("duration_unit") == "lifetime" or body.get("lifetime"):
                    secs = 0
                elif body.get("duration_seconds") is not None and str(body.get("duration_seconds")) != "":
                    secs = int(body.get("duration_seconds") or 0)
                elif body.get("duration_value") is not None and body.get("duration_unit"):
                    secs = db.duration_to_seconds(body.get("duration_value"), body.get("duration_unit"))
                elif plan is not None:
                    secs = int(plan.get("duration_seconds") or 0)
                    if secs <= 0 and int(plan.get("duration_days") or 0) > 0:
                        secs = int(plan["duration_days"]) * 86400
                elif body.get("duration_days") is not None:
                    secs = db.duration_to_seconds(body.get("duration_days"), "days")
                else:
                    secs = 30 * 86400

                tier = body.get("tier") or (plan["tier"] if plan else "std")
                maxd = int(body.get("max_devices") or (plan["max_devices"] if plan else 1))
                start_mode = body.get("start_mode") or "first_use"
                if start_mode not in ("first_use", "immediate"):
                    start_mode = "first_use"
                created = []
                key_prefix = (body.get("key_prefix") or db.get_setting("key_prefix") or "WC")
                key_length = int(body.get("key_length") or db.get_setting("key_length") or 10)
                # bulk: optional customer prefix + sequential note tags
                base_customer = (body.get("customer") or "").strip()
                base_note = (body.get("note") or "").strip()
                batch_tag = (body.get("batch_tag") or "").strip()
                for i in range(qty):
                    tok = mint_license_token(prefix=str(key_prefix), length=key_length)
                    fp = token_fingerprint(tok)
                    cust = base_customer
                    note = base_note
                    if qty > 1:
                        if base_customer:
                            cust = f"{base_customer} #{i + 1}"
                        if batch_tag:
                            note = (note + " " if note else "") + f"batch:{batch_tag}"
                        elif not note:
                            note = f"bulk {time.strftime('%Y%m%d')}"
                    lid = db.create_license(
                        tok,
                        fp,
                        plan_id=int(plan["id"]) if plan else None,
                        customer=cust,
                        note=note,
                        tier=tier,
                        max_devices=maxd,
                        duration_seconds=secs,
                        duration_label=db.format_duration(secs),
                        start_mode=start_mode,
                        reseller=body.get("reseller") or "",
                        features=int(body.get("features") or (plan["features"] if plan else 0xFFFF)),
                    )
                    offline = None
                    if body.get("also_offline") and db.get_setting("allow_offline_envelope"):
                        exp = 0 if secs <= 0 else int(time.time()) + secs
                        flags = 0
                        if secs <= 0:
                            flags |= 1
                        if tier == "vip":
                            flags |= 4
                        if tier == "owner":
                            flags |= 8 | 4
                        offline = issue_offline_envelope(
                            PRIV,
                            serial=lid,
                            expire_unix=exp,
                            flags=flags,
                            hwid=body.get("hwid") or "",
                        )
                    created.append(
                        {
                            "id": lid,
                            "token": tok,
                            "offline": offline,
                            "duration": db.format_duration(secs),
                            "tier": tier,
                            "max_devices": maxd,
                            "start_mode": start_mode,
                            "customer": cust,
                            "note": note,
                        }
                    )
                try:
                    from crownauth.persist import schedule_backup

                    schedule_backup()
                except Exception:
                    pass
                try:
                    from crownauth import notify as _n

                    _n.notify_if(
                        "notify_on_mint",
                        f"🧾 Minted {len(created)} key(s)\n"
                        f"Duration: {db.format_duration(secs)}\n"
                        f"Devices: {maxd} · Tier: {tier}"
                        + (f"\nBatch: {batch_tag}" if batch_tag else ""),
                        kind="mint",
                    )
                except Exception:
                    pass
                return self._json({"ok": True, "created": created})

            def _persist() -> None:
                try:
                    from crownauth.persist import schedule_backup

                    schedule_backup()
                except Exception:
                    pass

            if path == "/api/licenses/ban":
                lid = int(body["id"])
                reason = body.get("reason") or ""
                db.ban_license(lid, reason)
                _persist()
                try:
                    from crownauth import notify as _n

                    lic = db.get_license(lid) or {}
                    _n.notify_if(
                        "notify_on_ban",
                        f"⛔ Banned key #{lid}\nBuyer: {lic.get('customer') or '—'}\nReason: {reason or '—'}",
                        kind="ban",
                    )
                except Exception:
                    pass
                return self._json({"ok": True})
            if path == "/api/licenses/unban":
                db.unban_license(int(body["id"]))
                _persist()
                return self._json({"ok": True})
            if path == "/api/licenses/extend":
                secs = int(body.get("seconds") or 0)
                if not secs and body.get("duration_value") is not None:
                    secs = db.duration_to_seconds(body.get("duration_value"), body.get("duration_unit") or "days")
                if not secs:
                    secs = int(body.get("days") or 7) * 86400
                db.extend_license(int(body["id"]), seconds=secs)
                _persist()
                return self._json({"ok": True})
            if path == "/api/licenses/hwid_reset":
                db.reset_hwid(int(body["id"]))
                _persist()
                return self._json({"ok": True})
            if path == "/api/licenses/update":
                lid = int(body.pop("id"))
                allowed = {
                    k: body[k]
                    for k in ("customer", "note", "tier", "max_devices", "duration_days", "features")
                    if k in body
                }
                for ik in ("max_devices", "duration_days", "features"):
                    if ik in allowed:
                        allowed[ik] = int(allowed[ik])
                db.update_license(lid, **allowed)
                _persist()
                return self._json({"ok": True})
            if path == "/api/licenses/delete":
                lid = int(body["id"])
                # Full revoke: sessions + devices + row (offline cache dies on next online reject)
                con = db.connect()
                con.execute("UPDATE sessions SET revoked=1 WHERE license_id=?", (lid,))
                con.execute("DELETE FROM devices WHERE license_id=?", (lid,))
                con.execute("DELETE FROM sessions WHERE license_id=?", (lid,))
                con.execute("DELETE FROM licenses WHERE id=?", (lid,))
                con.commit()
                con.close()
                db.audit("owner", "license.delete", str(lid))
                _persist()
                return self._json({"ok": True})

            if path == "/api/sessions/kick":
                db.revoke_session(body.get("jti") or "")
                return self._json({"ok": True})
            if path == "/api/sessions/kick_all":
                n = db.kick_all_sessions()
                return self._json({"ok": True, "n": n})

            if path == "/api/blacklist/add":
                db.blacklist_add(body.get("kind") or "hwid", body.get("value") or "", body.get("reason") or "")
                return self._json({"ok": True})
            if path == "/api/blacklist/remove":
                db.blacklist_remove(int(body["id"]))
                return self._json({"ok": True})

            if path == "/api/plans/upsert":
                pid = db.upsert_plan(body)
                return self._json({"ok": True, "id": pid})

            if path == "/api/kill":
                en = bool(body.get("enabled", True))
                db.set_setting("kill_switch", en)
                if body.get("message"):
                    db.set_setting("kill_message", body["message"])
                n = db.kick_all_sessions()
                try:
                    from crownauth import notify as _n

                    _n.notify_if(
                        "notify_on_kill",
                        f"{'🛑 KILL SWITCH ON' if en else '✅ Kill switch OFF'} — kicked {n}",
                        kind="kill",
                    )
                except Exception:
                    pass
                return self._json({"ok": True, "kicked": n, "config": signed_live_config()})

            if path == "/api/maintenance":
                db.set_setting("maintenance", bool(body.get("enabled", True)))
                if body.get("message"):
                    db.set_setting("maintenance_message", body["message"])
                return self._json({"ok": True, "config": signed_live_config()})

            if path == "/api/backup/now":
                from crownauth.persist import backup_now

                ok, msg = backup_now(force=True, notify=True)
                return self._json({"ok": ok, "message": msg})

            if path == "/api/backup/drill":
                from crownauth.persist import restore_drill

                result = restore_drill()
                return self._json(result)

            if path == "/api/notify/test":
                from crownauth import notify as _n

                ok, msg = _n.test_ping()
                return self._json({"ok": ok, "message": msg})

            if path == "/api/resellers/create":
                try:
                    row = db.create_reseller(
                        body.get("name") or "",
                        body.get("password") or "",
                        quota=int(body.get("quota") or 50),
                        max_duration_seconds=int(
                            body.get("max_duration_seconds")
                            or db.duration_to_seconds(body.get("max_duration_value") or 30, body.get("max_duration_unit") or "days")
                        ),
                        max_devices=int(body.get("max_devices") or 1),
                        note=body.get("note") or "",
                    )
                except ValueError as e:
                    return self._json({"ok": False, "error": str(e)}, 400)
                return self._json({"ok": True, "reseller": row})

            if path == "/api/resellers/update":
                rid = int(body.get("id") or 0)
                fields = {}
                for k in ("quota", "used", "max_duration_seconds", "max_devices", "active", "note", "can_reset_hwid"):
                    if k in body:
                        fields[k] = body[k]
                if "password" in body and body["password"]:
                    import secrets as _sec
                    salt = _sec.token_bytes(16)
                    fields["password_hash"] = salt.hex() + ":" + db._hash_reseller_pw(body["password"], salt).hex()
                db.update_reseller(rid, **fields)
                return self._json({"ok": True})

        return self._send(404, b"Not Found", "text/plain")

    def _json(self, obj: Any, code: int = 200, extra: Optional[dict] = None) -> None:
        c, b, t = json_bytes(obj, code)
        self._send(c, b, t, extra_headers=extra)

    def _file(self, path: Path, ctype: str) -> None:
        data = path.read_bytes()
        self._send(200, data, ctype)


def main() -> None:
    db.init_db()
    load_or_create_keypair()
    once = owner_auth.bootstrap_if_needed()
    owner_auth.load_or_create_api_token()
    s = db.all_settings()
    host = str(s.get("api_bind") or "0.0.0.0")
    port = int(s.get("api_port") or 8787)
    # One canonical owner URL (MetaPlus-style). Legacy panel_path still works if opened manually.
    panel = "/app/owner/auth/login"
    httpd = ThreadingHTTPServer((host, port), Handler)
    url = f"http://127.0.0.1:{port}{panel}"
    print("=" * 60)
    print("  Control plane online")
    print(f"  Panel:  {url}")
    print(f"  Seller: http://127.0.0.1:{port}/app/user/auth/login")
    print(f"  Client: http://<host>:{port}{s.get('client_api_prefix') or '/v2'}/auth")
    if once:
        print("  FIRST-RUN PASSWORD written to owner_panel/secrets/OWNER_PASSWORD_ONCE.txt")
        print(f"  Password: {once}")
    print("  Owner API requires login. Do not expose /api without HTTPS proxy.")
    print("=" * 60)
    # JustStart sets WC_NO_BROWSER=1 so only one tab is opened by the script.
    if not str(__import__("os").environ.get("WC_NO_BROWSER", "")).strip() in ("1", "true", "yes"):
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutdown")


if __name__ == "__main__":
    main()
