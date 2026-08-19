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
import base64
import ipaddress
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
from crownauth import experience  # noqa: E402
from crownauth import payload_security  # noqa: E402
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
PUBLIC_RATE: dict[str, tuple[int, int]] = {}
PUBLIC_RATE_LOCK = threading.Lock()
MAX_PUBLIC_RATE_KEYS = 10000
PRIV, PUB = load_or_create_keypair()
DEFAULT_LIB_CDN_BASE = "https://github.com/WesleighKanee/crownauth-live/releases/download/library-cdn-v1"
_PAYLOAD_SECURITY = None
_PAYLOAD_SECURITY_DB = None


def payload_service():
    global _PAYLOAD_SECURITY, _PAYLOAD_SECURITY_DB
    db_path = str(db.DB_PATH)
    store_root = Path(os.environ.get("CROWNAUTH_PAYLOAD_STORE") or (Path(db.DB_PATH).parent / "payload_store"))
    service_key = db_path + "|" + str(store_root)
    if _PAYLOAD_SECURITY is None or _PAYLOAD_SECURITY_DB != service_key:
        # The payload service must always have the deployment-provided master
        # key and an immutable content-addressed store.  Never silently fall
        # back to plaintext/local-only payload handling.
        store = payload_security.EncryptedContentStore(store_root)
        _PAYLOAD_SECURITY = payload_security.PayloadSecurity(store=store)
        _PAYLOAD_SECURITY_DB = service_key
    return _PAYLOAD_SECURITY


def _production_mode() -> bool:
    env = str(os.environ.get("APP_ENV") or os.environ.get("ENVIRONMENT") or "").strip().lower()
    return env in {"prod", "production"}


def _session_cookie(name: str, value: str, *, max_age: int = 43200) -> str:
    flags = f"{name}={urllib.parse.quote(value, safe='')}; Path=/; HttpOnly; SameSite=Strict; Max-Age={int(max_age)}"
    # Local HTTP tests/development must remain usable; production cookies are
    # never sent over cleartext, even when a proxy terminates TLS upstream.
    if _production_mode():
        flags += "; Secure"
    return flags


def json_bytes(obj: Any, code: int = 200) -> tuple[int, bytes, str]:
    return code, json.dumps(obj, separators=(",", ":")).encode("utf-8"), "application/json"


def public_rate(ip: str, limit: int = 240) -> bool:
    """Process-local limiter; public reads must not mutate the experience DB."""
    now = int(time.time()); key = str(ip or "")
    with PUBLIC_RATE_LOCK:
        # Bound process memory even when an attacker rotates source addresses.
        expired = [k for k, (started, _) in PUBLIC_RATE.items() if now - started >= 60]
        for k in expired[: max(0, len(expired) - MAX_PUBLIC_RATE_KEYS // 2)]:
            PUBLIC_RATE.pop(k, None)
        if len(PUBLIC_RATE) >= MAX_PUBLIC_RATE_KEYS and key not in PUBLIC_RATE:
            oldest = min(PUBLIC_RATE, key=lambda k: PUBLIC_RATE[k][0])
            PUBLIC_RATE.pop(oldest, None)
        start, count = PUBLIC_RATE.get(key, (now, 0))
        if now - start >= 60: start, count = now, 0
        if count >= limit:
            PUBLIC_RATE[key] = (start, count)
            return False
        PUBLIC_RATE[key] = (start, count + 1)
        return True


def client_err(msg: str, detail: str = "") -> dict:
    s = db.all_settings()
    if s.get("generic_errors") and s.get("stealth_mode"):
        return {"ok": False, "error": "Access denied"}
    return {"ok": False, "error": msg or detail or "Access denied"}


def live_config() -> dict[str, Any]:
    s = db.all_settings()
    return {
        "v": 3,
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
        "min_proto": int(s.get("min_client_protocol") or 0),
        "min_vc": int(s.get("min_client_version_code") or 0),
        "cur_proto": int(s.get("client_protocol_current") or 3),
        "force_update": bool(s.get("force_update")),
        "update_url": s.get("update_apk_url") or "",
        "update_msg": s.get("update_message") or "",
    }


def client_update_gate(body: dict) -> Optional[dict]:
    """Forced OTA is permanently disabled.

    Forever policy (owner request 2026-07-18): never return action=update.
    Buyers must log in on whatever sideload build they already have.
    Manual APK distribution only — no Chrome force loop.
    """
    return None




def signed_live_config() -> str:
    return sign_config_blob(PRIV, live_config())


def _attestation_reject(body: dict, s: dict) -> Optional[str]:
    """Optional environment policy. OFF by default (require_client_attestation=False).

    Kernel-loader + Magisk false-positives made hard-deny unusable for real buyers.
    """
    if not s.get("require_client_attestation", False):
        return None
    try:
        af = int(body.get("af") or 0)
    except Exception:
        af = 0
    if s.get("reject_debugger", False) and (af & 1):
        return "Environment blocked (debugger)"
    if s.get("reject_frida", False) and (af & 2):
        return "Environment blocked (instrumentation)"
    if s.get("reject_xposed", False) and (af & 4):
        return "Environment blocked (framework)"
    if s.get("reject_emulator", False) and (af & 16):
        return "Environment blocked (emulator)"
    if s.get("reject_integrity_fail", False) and (af & 32):
        return "Environment blocked (integrity)"
    bid = str(body.get("bid") or "").strip()
    expect = str(s.get("expected_app_build") or "").strip()
    if s.get("strict_build_id") and expect and bid and bid != expect:
        return "Environment blocked (build)"
    return None


def client_auth(body: dict, ip: str) -> dict:
    s = db.all_settings()
    if s.get("kill_switch"):
        return client_err(s.get("kill_message") or "Unavailable")
    if s.get("maintenance"):
        return client_err(s.get("maintenance_message") or "Unavailable")

    gate = client_update_gate(body)
    if gate:
        return gate

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
        # Bind challenge to the key it was issued for
        try:
            if meta.get("token_fp") and meta["token_fp"] != token_fingerprint(token):
                db.rate_fail(rk, int(s.get("max_failed_auth", 12)), int(s.get("ban_duration_sec", 3600)))
                return client_err("Challenge expired — retry")
        except Exception:
            pass
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
        "server_time": int(time.time()),
        "license_status": lic.get("status") or "active",
        "license_tier": lic.get("tier") or claims.tier,
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


def _session_claims_from_headers(handler: "Handler") -> tuple[bool, str, Any]:
    """Validate client session from Authorization Bearer / X-Crown-Session / X-Session."""
    session = ""
    auth = handler.headers.get("Authorization") or ""
    if auth.lower().startswith("bearer "):
        session = auth[7:].strip()
    if not session:
        session = (handler.headers.get("X-Crown-Session") or handler.headers.get("X-Session") or "").strip()
    if not session:
        # query fallback for stubborn clients
        q = urllib.parse.urlparse(handler.path).query
        qs = urllib.parse.parse_qs(q)
        session = (qs.get("session") or qs.get("s") or [""])[0].strip()
    if not session or len(session) < 10:
        return False, "session required", None
    hwid = (handler.headers.get("X-HWID") or "").strip()
    hh = hwid_hash(hwid) if hwid else None
    ok, msg, claims = verify_session(PUB, session, expect_hwid_hash=hh if hwid else None)
    if not ok or not claims:
        return False, "invalid session", None
    if db.is_session_revoked(claims.jti):
        return False, "revoked session", None
    lic = db.get_license(int(claims.serial))
    if not lic or lic.get("status") != "active":
        return False, "license inactive", None
    exp = int(lic.get("expires_at") or 0)
    if exp > 0 and int(time.time()) > exp:
        return False, "license expired", None
    return True, "ok", claims


def client_heartbeat(body: dict, ip: str) -> dict:
    s = db.all_settings()
    if s.get("kill_switch"):
        return {"ok": False, "error": "Access denied", "action": "kill"}
    if s.get("maintenance"):
        return {"ok": False, "error": "Access denied", "action": "pause"}

    gate = client_update_gate(body)
    if gate:
        gate["action"] = "update"
        return gate

    att_err = _attestation_reject(body, s)
    if att_err:
        return {"ok": False, "error": att_err, "action": "kill"}

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
        "license_expires_at": int(lic.get("expires_at") or 0),
        "tier": lic.get("tier") or claims.tier,
        "license_status": lic.get("status") or "active",
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

    def _stream_ota_apk(self) -> None:
        """Proxy APK so the client URL never shows the private GitHub username."""
        import urllib.request

        s = db.all_settings()
        upstream = str(
            s.get("update_apk_upstream")
            or "https://github.com/WesleighKanee/crownauth-live/releases/latest/download/WhiteCrownsLoaderV2.apk"
        ).strip()
        try:
            req = urllib.request.Request(
                upstream,
                headers={"User-Agent": "CrownAuth-OTA-Proxy/3", "Accept": "*/*"},
            )
            with urllib.request.urlopen(req, timeout=180) as r:
                data = r.read()
                ctype = r.headers.get("Content-Type") or "application/vnd.android.package-archive"
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header(
                "Content-Disposition",
                'attachment; filename="WhiteCrownsLoaderV2.apk"',
            )
            self.send_header("Cache-Control", "public, max-age=300")
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            msg = f"OTA unavailable: {e}".encode("utf-8")
            self._send(502, msg, "text/plain; charset=utf-8")

    def _read_json(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        # Cap body to reduce free-tier memory DoS
        if n > 262144:
            return {}
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
        # IP allowlisting is defense in depth, never an authentication
        # substitute.  Every owner API request must carry a valid token or
        # authenticated owner session, including LAN deployments.
        if self._owner_ok():
            return True
        self._json({"ok": False, "error": "Unauthorized"}, 401)
        return False

    def do_HEAD(self) -> None:  # noqa: N802
        """UptimeRobot and similar monitors often use HEAD — was 501 before."""
        path = urllib.parse.urlparse(self.path).path
        cpre = self._client_prefix()
        if path == cpre + "/experience/manifest":
            payload, etag, _ = experience.get_manifest()
            # Public reads are strictly side-effect free.  A first-run server
            # returns an unavailable manifest until an owner publishes one.
            if payload is None:
                if self.headers.get("If-None-Match") == etag:
                    self.send_response(304); self._cors(); self.send_header("ETag", etag); self.send_header("Content-Length", "0"); self.end_headers(); return
                # Return a signed, in-memory safe baseline for older clients;
                # importantly this does not create a draft or advance state.
                base = experience.fallback_manifest()
                payload = {"ok": True, "manifest": experience.sign_payload(base)}
                self.send_response(200); self._cors(); self.send_header("ETag", etag); self.send_header("Content-Length", str(len(json.dumps(payload, separators=(",", ":")).encode()))); self.end_headers(); return
            if self.headers.get("If-None-Match") == etag:
                self.send_response(304); self._cors(); self.send_header("ETag", etag); self.send_header("Content-Length", "0"); self.end_headers(); return
            raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            self.send_response(200); self._cors(); self.send_header("Content-Type", "application/json"); self.send_header("ETag", etag); self.send_header("Content-Length", str(len(raw))); self.end_headers(); return
        if path in (cpre + "/health", cpre + "/ping", "/health", "/ping", "/"):
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
        """Resolve the peer address without trusting spoofable proxy headers.

        Forwarded headers are accepted only when the immediate TCP peer is in
        TRUSTED_PROXY_CIDRS (or the equivalent setting).  This is fail-closed
        by default, which is important for rate limits and owner allowlists.
        """
        peer = str(self.client_address[0] or "").strip()
        try:
            peer_ip = ipaddress.ip_address(peer)
        except ValueError:
            return peer
        trusted = self._trusted_proxy_networks()
        if not any(peer_ip in n for n in trusted):
            return peer
        cf = (self.headers.get("CF-Connecting-IP") or "").strip()
        xff = self.headers.get("X-Forwarded-For") or ""
        chain = [x.strip() for x in xff.split(",") if x.strip()]
        if cf:
            chain.append(cf)
        # Walk from the proxy toward the client and select the first address
        # that is not itself a trusted proxy.  Invalid values are ignored.
        for candidate in reversed(chain):
            try:
                addr = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if not any(addr in n for n in trusted):
                return str(addr)
        return peer

    @staticmethod
    def _trusted_proxy_networks() -> tuple[Any, ...]:
        raw = os.environ.get("TRUSTED_PROXY_CIDRS") or db.get_setting("trusted_proxy_cidrs", "") or ""
        out = []
        for item in str(raw).replace(";", ",").split(","):
            item = item.strip()
            if not item:
                continue
            try:
                network = ipaddress.ip_network(item, strict=False)
                # A default route would make every client-controlled header
                # authoritative and is therefore never a trusted proxy rule.
                if network.prefixlen == 0:
                    continue
                out.append(network)
            except ValueError:
                continue
        return tuple(out)

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

        # Authenticated v3 payload reads.  The bearer token is bound to every
        # requested hash/lib/revision before either metadata or ciphertext is
        # returned; errors intentionally collapse to 404/403.
        if path.startswith("/v3/payload/metadata/") or path.startswith("/v3/payload/content/"):
            try:
                token = str(self.headers.get("Authorization") or "")
                if not token.startswith("Bearer "):
                    return self._json({"ok": False, "error": "payload unavailable"}, 403)
                token = token[7:].strip()
                parts = token.split(".")
                if len(parts) != 3 or parts[0] != "PAS1":
                    return self._json({"ok": False, "error": "payload unavailable"}, 403)
                raw_claims = base64.urlsafe_b64decode(parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4))
                claims = json.loads(raw_claims.decode("utf-8"))
                digest = path.rsplit("/", 1)[-1].lower()
                svc = payload_service()
                svc.verify_authorization(token, install_id=str(claims["install_id"]), lib_id=str(claims["lib_id"]), revision=str(claims["revision"]), payload_hash=digest, nonce=str(claims.get("nonce") or ""))
                metadata = svc.payload_metadata(digest)
                if path.startswith("/v3/payload/metadata/"):
                    return self._json({"ok": True, "metadata": metadata})
                ciphertext = svc.store.read_ciphertext(metadata)
                return self._send(200, ciphertext, "application/octet-stream", extra_headers={"Cache-Control": "no-store", "X-Payload-SHA256": digest})
            except Exception:
                return self._json({"ok": False, "error": "payload unavailable"}, 404)

        if path == "/v3/libs":
            # Catalog contains only immutable identifiers/hashes. Payload
            # bytes still require an enrolled installation authorization.
            try:
                items = []
                svc = payload_service()
                for row in db.lib_list(enabled_only=True):
                    name = str(row.get("name") or "")
                    digest = str(row.get("sha256") or "").lower()
                    if name and len(digest) == 64:
                        # Never advertise a v3 item unless its encrypted object
                        # and signed metadata actually exist.  The stable v3
                        # identity is the normalized library name; database
                        # row ids are deployment-local and must not enter the
                        # authorization contract.
                        try:
                            meta = svc.payload_metadata(digest)
                        except payload_security.PayloadNotFound:
                            continue
                        signed = meta.get("metadata") or {}
                        lib_id = name
                        revision = str(row.get("version") or "1")
                        if str(signed.get("lib_id")) != lib_id or str(signed.get("revision")) != revision:
                            continue
                        items.append({"name": name, "lib_id": lib_id, "revision": revision, "sha256": digest})
                return self._json({"ok": True, "items": items})
            except Exception:
                return self._json({"ok": False, "error": "catalog unavailable"}, 503)

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
        if path == cpre + "/experience/manifest":
            if not public_rate(self._ip()):
                return self._json({"ok": False, "error": "too many requests"}, 429)
            payload, etag, _ = experience.get_manifest()
            if payload is None:
                if self.headers.get("If-None-Match") == etag:
                    return self._send(304, b"", "application/json", extra_headers={"ETag": etag})
                base = experience.fallback_manifest()
                return self._send(200, json.dumps({"ok":True,"manifest":experience.sign_payload(base)}, separators=(",", ":")).encode(), "application/json", extra_headers={"ETag": etag, "Cache-Control": "no-store"})
            if self.headers.get("If-None-Match") == etag:
                self.send_response(304); self._cors(); self.send_header("ETag", etag); self.send_header("Content-Length", "0"); self.end_headers(); return
            raw = json.dumps(payload or {"ok": False, "error": "manifest unavailable"}, separators=(",", ":")).encode("utf-8")
            return self._send(200, raw, "application/json", extra_headers={"ETag": etag, "Cache-Control": "public, max-age=30"})
        # CRON / UptimeRobot keep-alive: cheapest wake. No DB. Render sleep
        # needs EXTERNAL hits — 127.0.0.1 ticks in cloud_entry do not count.
        if path in (cpre + "/ping", "/ping"):
            return self._json({"ok": True, "pong": 1})
        if path == cpre + "/health":
            s = db.all_settings()
            lib_rows = []
            local_disk_ok = True
            try:
                lib_rows = db.lib_list()
                for r in lib_rows:
                    fp = db.lib_data_path(r.get("name") or "")
                    if not fp.is_file() or fp.stat().st_size <= 0:
                        local_disk_ok = False
                        break
            except Exception:
                local_disk_ok = False
            cdn_base = (os.environ.get("LIB_CDN_BASE") or DEFAULT_LIB_CDN_BASE).strip()
            try:
                from crownauth.lib_cdn import configured as lib_cdn_configured
                cdn_write_configured = lib_cdn_configured()
            except Exception:
                cdn_write_configured = False
            disk_ok = local_disk_ok or bool(cdn_base)
            return self._json(
                {
                    "ok": True,
                    "t": int(time.time()),
                    "b": "panel_libs_v28_github_cdn",
                    "min_proto": int(s.get("min_client_protocol") or 0),
                    "min_vc": int(s.get("min_client_version_code") or 0),
                    "lib_count": len(lib_rows),
                    "disk_ok": disk_ok,
                    "local_cache_ok": local_disk_ok,
                    "cdn": bool(cdn_base),
                    "cdn_write_configured": cdn_write_configured,
                }
            )
        if path == cpre + "/version":
            s = db.all_settings()
            pub_url = str(s.get("update_apk_url") or "").strip() or "https://crownauth-live.onrender.com/v2/apk"
            return self._json(
                {
                    "ok": True,
                    "proto": int(s.get("client_protocol_current") or 3),
                    "min_proto": int(s.get("min_client_protocol") or 0),
                    "min_vc": int(s.get("min_client_version_code") or 0),
                    "force_update": bool(s.get("force_update")),
                    "url": pub_url,
                    "message": s.get("update_message") or "",
                    "blocked": s.get("blocked_build_ids") or [],
                }
            )
        # Anonymous OTA download — buyers only see onrender, not GitHub username
        if path in (cpre + "/apk", cpre + "/download/apk", "/ota/WhiteCrownsLoaderV2.apk"):
            return self._stream_ota_apk()
        if path == cpre + "/config":
            out: dict[str, Any] = {"ok": True, "config": signed_live_config()}
            if db.get_setting("expose_plain_config"):
                out["plain"] = live_config()
            return self._json(out)
        if path == cpre + "/pubkey":
            if not db.get_setting("expose_pubkey"):
                return self._send(404, b"Not Found", "text/plain")
            return self._json({"ok": True, "k": public_raw_bytes(PUB).hex()})

        # Keep the legacy feed available for existing clients until the
        # operator explicitly cuts it off after v3 dual delivery.
        if path == cpre + "/libs" or path.startswith(cpre + "/libs/"):
            if db.get_setting("legacy_libs_cutoff", False) or not db.get_setting("legacy_libs_migration_enabled", True):
                return self._send(404, b"Not Found", "text/plain")

        # mod library manifest — public read of ENABLED mods only.
        # Session lock broke the APK sync (401 → keep old shelf → delete never applied).
        # Owner upload/delete stays on /api/libs*.
        if path == cpre + "/libs":
            host = str(db.get_setting("client_api_host") or "").strip()
            scheme = str(db.get_setting("client_api_scheme") or "https").strip()
            base = "%s://%s" % (scheme, host) if host else ""
            libs = []
            for r in db.lib_list(enabled_only=True):
                nm = r["name"]
                cdn = (os.environ.get("LIB_CDN_BASE") or DEFAULT_LIB_CDN_BASE).strip().rstrip("/")
                if cdn:
                    url = "%s/%s?v=%s" % (cdn, urllib.parse.quote(nm), r.get("md5") or "0")
                else:
                    url = "%s%s/libs/%s" % (base, cpre, nm) if base else "%s/libs/%s" % (cpre, nm)
                card = r.get("card") or db.lib_card_name(nm)
                has_cover = bool(r.get("cover") or db.lib_has_cover(nm))
                if has_cover and db.lib_cdn_only():
                    from crownauth.lib_cdn import cover_url as cdn_cover_url

                    cover_url = cdn_cover_url(card, db.lib_cover_fmt(card)) + "?v=" + urllib.parse.quote(db.lib_cover_ver(card))
                elif has_cover and base:
                    cover_url = "%s%s/libs/%s/cover" % (base, cpre, card)
                elif has_cover:
                    cover_url = "%s/libs/%s/cover" % (cpre, card)
                else:
                    cover_url = ""
                libs.append({
                    "name": nm,
                    "card": card,
                    "version": r.get("version") or "",
                    "size": int(r.get("size") or 0),
                    "md5": r.get("md5") or "",
                    "id": card,
                    "display_name": next((x["display_name"] for x in db.library_labels() if x["stable_id"] == card), card),
                    "sha256": r.get("sha256") or "",
                    "enabled": True,
                    "url": url,
                    "cover": has_cover,
                    "cover_url": cover_url,
                })
            return self._json({"ok": True, "feed": "public", "libs": libs})
        # mod library download — enabled .so public (same as the working sync). covers public.
        if path.startswith(cpre + "/libs/"):
            name = urllib.parse.unquote(path[len(cpre) + len("/libs/"):]).strip("/")
            if name.lower().endswith("/cover") or name.lower().endswith(".cover.jpg"):
                stem = name
                if stem.lower().endswith("/cover"):
                    stem = stem[: -len("/cover")]
                elif stem.lower().endswith(".cover.jpg"):
                    stem = stem[: -len(".cover.jpg")]
                if db.lib_cdn_only():
                    from crownauth.lib_cdn import cover_url as cdn_cover_url

                    if not db.lib_has_cover(stem):
                        return self._send(404, b"no cover", "text/plain")
                    location = cdn_cover_url(db.lib_card_name(stem), db.lib_cover_fmt(stem)) + "?v=" + urllib.parse.quote(db.lib_cover_ver(stem))
                    self.send_response(302)
                    self._cors()
                    self.send_header("Location", location)
                    self.send_header("Content-Length", "0")
                    self.send_header("Cache-Control", "public, max-age=300")
                    self.end_headers()
                    return
                fp = db.lib_cover_path(stem, db.lib_cover_fmt(stem))
                if not fp.is_file():
                    return self._send(404, b"no cover", "text/plain")
                data = fp.read_bytes()
                ctype = "image/jpeg"
                if data.startswith(b"GIF8"):
                    ctype = "image/gif"
                elif data.startswith(b"\x89PNG"):
                    ctype = "image/png"
                elif data.startswith(b"RIFF"):
                    ctype = "image/webp"
                self.send_response(200)
                self._cors()
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "public, max-age=30")
                self.end_headers()
                self.wfile.write(data)
                return
            lib = db.lib_get(name)
            if not lib or not lib.get("enabled"):
                return self._send(404, b"not found", "text/plain")
            out_name = lib.get("name") or name
            # Optional zero-egress object-store handoff. The Android client follows
            # this redirect, while auth, manifest, and owner controls remain here.
            cdn = (os.environ.get("LIB_CDN_BASE") or DEFAULT_LIB_CDN_BASE).strip().rstrip("/")
            if cdn:
                location = "%s/%s?v=%s" % (
                    cdn, urllib.parse.quote(out_name), lib.get("md5") or "0"
                )
                self.send_response(302)
                self._cors()
                self.send_header("Location", location)
                self.send_header("Content-Length", "0")
                self.send_header("Cache-Control", "public, max-age=300")
                self.end_headers()
                return
            fp = db.lib_data_path(out_name)
            if not fp.is_file():
                return self._send(404, b"not found", "text/plain")
            with open(fp, "rb") as f:
                data = f.read()
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Disposition", 'attachment; filename="%s"' % out_name)
            self.send_header("ETag", '"%s"' % (lib.get("md5") or ""))
            self.send_header("Cache-Control", "no-store, private")
            self.end_headers()
            self.wfile.write(data)
            return

        if path.startswith(cpre + "/experience/assets/"):
            name = urllib.parse.unquote(path[len(cpre + "/experience/assets/"):])
            if not name or "/" in name or "\\" in name or name.startswith("."):
                return self._send(404, b"not found", "text/plain")
            root = Path(os.environ.get("EXPERIENCE_CDN_DIR") or str(db.DATA / "experience_cdn")); fp = (root / name).resolve()
            if not str(fp).startswith(str(root.resolve())) or not fp.is_file(): return self._send(404, b"not found", "text/plain")
            data = fp.read_bytes(); ctype = "image/gif" if fp.suffix.lower() == ".gif" else "image/jpeg"
            return self._send(200, data, ctype, extra_headers={"ETag": '"%s"' % __import__('hashlib').sha256(data).hexdigest(), "Cache-Control": "public, max-age=31536000, immutable"})

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
            if path == "/api/experience/draft":
                state = experience.current_state(); d = dict(state["draft"]); d["config"] = json.loads(d.get("config_json") or "{}"); d["labels"] = json.loads(d.get("labels_json") or "[]")
                return self._json({"ok": True, "draft": d, "manifest_revision": state["manifest_revision"], "published_revision_id": state["published_revision_id"]})
            if path == "/api/experience/history":
                return self._json({"ok": True, "items": experience.history((qs.get("limit") or [20])[0])})

            if path == "/api/libs":
                return self._json({"ok": True, "libs": db.lib_list()})
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
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        # Authenticate owner routes before touching an upload stream.  This is
        # deliberately before parsing Content-Length/body to prevent unauth
        # callers from forcing an arbitrary body allocation/read.
        owner_route = path.startswith("/api/")
        if owner_route and not self._require_owner():
            return
        if owner_route:
            ok_rl, rl_msg = db.rate_check(f"owner_api:{self._ip()}", 120, 60)
            if not ok_rl:
                return self._json({"ok": False, "error": rl_msg}, 429)
            db.rate_fail(f"owner_api:{self._ip()}", 120, 60)
        try:
            _body_len = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            return self._json({"ok": False, "error": "invalid content length"}, 400)
        if _body_len < 0 or (owner_route and _body_len > 60 * 1024 * 1024):
            return self._json({"ok": False, "error": "upload exceeds limit"}, 413)
        # Read in bounded chunks into a temporary spool rather than one
        # unbounded socket read.  The media decoder still receives bytes, but
        # the transport itself is bounded and rejects short/oversized bodies.
        import tempfile
        _raw_body = b"{}"
        if _body_len:
            with tempfile.SpooledTemporaryFile(max_size=1 * 1024 * 1024, mode="w+b") as _spool:
                remaining = _body_len
                while remaining:
                    chunk = self.rfile.read(min(1024 * 1024, remaining))
                    if not chunk:
                        return self._json({"ok": False, "error": "incomplete body"}, 400)
                    _spool.write(chunk); remaining -= len(chunk)
                _spool.seek(0); _raw_body = _spool.read()
        body = {}
        if _body_len <= 262144:
            try:
                body = json.loads(_raw_body.decode("utf-8") or "{}")
            except Exception:
                body = {}
        ip = self._ip()
        cpre = self._client_prefix()

        # Payload-security v3 is separate from the legacy client bridge.
        if path == "/v3/install/challenge":
            try:
                return self._json(payload_service().begin_enrollment(install_id=body.get("install_id"), license_id=body.get("license_id"), token=body.get("token")))
            except Exception:
                return self._json({"ok": False, "error": "enrollment unavailable"}, 403)
        if path == "/v3/payload/challenge":
            try:
                return self._json(payload_service().challenge_authorization(install_id=body.get("install_id"), lib_id=body.get("lib_id"), revision=body.get("revision"), payload_hash=body.get("payload_hash"), nonce=body.get("nonce")))
            except Exception:
                return self._json({"ok": False, "error": "authorization unavailable"}, 403)
        if path == "/v3/install/enroll":
            try:
                return self._json(payload_service().complete_enrollment(install_id=body.get("install_id"), challenge=body.get("challenge"), signing_public_key=body.get("signing_public_key"), encryption_public_key=body.get("encryption_public_key"), proof=body.get("proof")))
            except Exception:
                return self._json({"ok": False, "error": "enrollment failed"}, 403)
        if path == "/v3/payload/authorize":
            try:
                out = payload_service().authorize(install_id=body.get("install_id"), challenge=body.get("challenge"), proof=body.get("proof"), nonce=body.get("nonce"), ttl=body.get("ttl", 300))
                if body.get("include_key"):
                    out["wrapped_key"] = payload_service().content_key_for_authorization(out["authorization"], install_id=body.get("install_id"))
                return self._json(out)
            except Exception:
                return self._json({"ok": False, "error": "authorization failed"}, 403)
        if path == "/v3/payload/lease":
            try:
                return self._json(payload_service().issue_offline_lease(authorization=body.get("authorization"), install_id=body.get("install_id"), seconds=body.get("seconds", 3600)))
            except Exception:
                return self._json({"ok": False, "error": "lease unavailable"}, 403)

        # owner login (no LAN-only block when public Cloudflare)
        if path == "/auth/login":
            if db.get_setting("enable_owner_ip_allowlist") and not self._ip_allowed_owner(ip):
                return self._json({"ok": False, "error": "Forbidden from this network"}, 403)
            # Rate-limit panel password sprays
            ok_rl, rl_msg = db.rate_check(f"owner_login:{ip}", 8, 900)
            if not ok_rl:
                return self._json({"ok": False, "error": rl_msg or "Too many attempts"}, 429)
            pw = body.get("password") or ""
            if not owner_auth.has_password():
                owner_auth.bootstrap_if_needed()
            if owner_auth.verify_password(pw):
                sess = owner_auth.issue_session()
                db.audit("owner", "login.ok", ip)
                return self._json(
                    {"ok": True, "session": sess},
                    extra={"Set-Cookie": _session_cookie("oc_session", sess)},
                )
            db.rate_fail(f"owner_login:{ip}", 8, 900)
            db.audit("owner", "login.fail", ip)
            return self._json({"ok": False, "error": "Invalid password"}, 401)

        # reseller login
        if path == "/reseller/api/login":
            name = (body.get("name") or body.get("username") or "").strip()
            pw = body.get("password") or ""
            ok_rl, rl_msg = db.rate_check(f"reseller_login:{ip}", 8, 900)
            if not ok_rl:
                return self._json({"ok": False, "error": rl_msg or "Too many attempts"}, 429)
            r = db.verify_reseller_password(name, pw)
            if not r:
                db.rate_fail(f"reseller_login:{ip}", 8, 900)
                return self._json({"ok": False, "error": "Wrong name or password"}, 401)
            sess = owner_auth.issue_reseller_session(int(r["id"]), r["name"])
            db.audit("reseller", "login.ok", r["name"])
            return self._json(
                {"ok": True, "session": sess, "name": r["name"]},
                extra={"Set-Cookie": _session_cookie("rs_session", sess)},
            )

        if path == "/reseller/api/logout":
            return self._json(
                {"ok": True},
                extra={"Set-Cookie": _session_cookie("rs_session", "", max_age=0)},
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
            custom = (body.get("duration_custom") or body.get("duration_clock") or "").strip()
            if body.get("duration_unit") == "lifetime" or body.get("lifetime"):
                secs = 0
            elif custom:
                parsed = db.parse_duration_input(custom)
                if parsed is None:
                    return self._json({"ok": False, "error": "Bad custom duration (e.g. 30:00, 1h, 2d)"}, 400)
                secs = int(parsed)
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
                extra={"Set-Cookie": _session_cookie("oc_session", "", max_age=0)},
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

        if path == "/api/payload/revoke":
            try:
                count = payload_service().revoke(install_id=body.get("install_id"), authorization_id=body.get("authorization_id"), lease_id=body.get("lease_id"), license_id=body.get("license_id"))
                return self._json({"ok": True, "revoked": count})
            except Exception:
                return self._json({"ok": False, "error": "revocation failed"}, 400)

        # client
        if path == cpre + "/auth":
            return self._json(client_auth(body, ip))
        if path == cpre + "/heartbeat":
            return self._json(client_heartbeat(body, ip))

        # owner mutations
        if path.startswith("/api/"):
            if not self._require_owner():
                return
            if (path.startswith("/api/experience/") or path == "/api/library/display-name") and not self._owner_ok():
                return self._json({"ok": False, "error": {"code": "unauthenticated", "message": "owner authentication required"}}, 401)

            if path == "/api/experience/draft":
                try:
                    out = experience.update_draft(body, expected_revision=body.get("expected_revision")); db.audit("owner", "experience.draft", "revision=%s" % out.get("manifest_revision")); return self._json(out)
                except experience.ConflictError as e: return self._json({"ok": False, "error": {"code": e.code, "message": e.message}}, 409)
                except experience.ExperienceError as e: return self._json({"ok": False, "error": {"code": e.code, "message": e.message}}, 422)
            if path == "/api/experience/assets":
                slot = (qs.get("slot") or [""])[0].strip().lower()
                if slot not in ("login", "library"): return self._json({"ok": False, "error": {"code": "slot", "message": "slot must be login or library"}}, 400)
                # Theme Director uploads are optimistic-concurrency writes.
                # Read the revision directly (without current_state(), which
                # may create a draft) and reject stale/missing coordinates
                # before decoding media or touching the CDN.
                query_revision = (qs.get("expected_revision") or [""])[0].strip()
                header_revision = (self.headers.get("X-Expected-Revision") or "").strip()
                if not query_revision and not header_revision:
                    return self._json({"ok": False, "error": {"code": "expected_revision", "message": "expected revision is required"}}, 400)
                if query_revision and header_revision and query_revision != header_revision:
                    return self._json({"ok": False, "error": {"code": "expected_revision", "message": "revision coordinates disagree"}}, 400)
                try:
                    expected_upload_revision = int(query_revision or header_revision)
                    if expected_upload_revision < 0:
                        raise ValueError
                except (TypeError, ValueError):
                    return self._json({"ok": False, "error": {"code": "expected_revision", "message": "revision must be a non-negative integer"}}, 400)
                rev_con = db.connect()
                try:
                    rev_row = rev_con.execute("SELECT manifest_revision FROM experience_state WHERE singleton_id=1").fetchone()
                    current_upload_revision = int((rev_row[0] if rev_row else 0) or 0)
                finally:
                    rev_con.close()
                if current_upload_revision != expected_upload_revision:
                    return self._json({"ok": False, "error": {"code": "stale_revision", "message": "manifest revision changed", "current_revision": current_upload_revision}}, 409)
                if _body_len <= 0 or _body_len > 60 * 1024 * 1024: return self._json({"ok": False, "error": {"code": "too_large", "message": "upload exceeds limit"}}, 413)
                try:
                    from crownauth.experience_media import validate_and_render
                    from crownauth.lib_cdn import LocalContentCDN, publish_immutable, experience_cdn, content_address
                    media = validate_and_render(_raw_body, slot=slot)
                    # Explicit production requires a configured object CDN;
                    # tests/dev use the isolated DB data directory.
                    prod = str(os.environ.get("APP_ENV") or os.environ.get("ENVIRONMENT") or "").lower() in {"prod", "production"}
                    cdn = (experience_cdn(staging=True) if os.environ.get("EXPERIENCE_CDN_DIR")
                           else LocalContentCDN(str(db.DATA / "experience_cdn"))) if not prod else experience_cdn(staging=False)
                    records = []
                    import uuid
                    group = uuid.uuid4().hex
                    created_names = []
                    try:
                        # Stage every immutable object before touching SQLite.
                        # If any rendition fails, discard only objects created
                        # by this request; pre-existing content-addressed data
                        # remains available to other revisions.
                        staged_names = []
                        for r in media.renditions:
                            name, _ = content_address(r.data, slot=slot, edge=max(r.width, r.height), fmt=r.format)
                            existed = False
                            try:
                                probe = getattr(cdn, "exists", None)
                                if callable(probe):
                                    existed = bool(probe(name))
                                else:
                                    cdn.get(name)
                                    existed = True
                            except Exception:
                                pass
                            name = publish_immutable(cdn, r.data, slot=slot, edge=max(r.width, r.height), fmt=r.format)["name"]
                            staged_names.append(name)
                            if not existed:
                                created_names.append(name)
                        con = db.connect()
                        try:
                            con.execute("BEGIN IMMEDIATE")
                            locked_state = con.execute("SELECT manifest_revision FROM experience_state WHERE singleton_id=1").fetchone()
                            locked_revision = int((locked_state[0] if locked_state else 0) or 0)
                            if locked_revision != expected_upload_revision:
                                raise experience.ConflictError("stale_revision", "manifest revision changed")
                            now = int(time.time())
                            for r, name in zip(media.renditions, staged_names):
                                con.execute("INSERT OR IGNORE INTO experience_assets(slot,sha256,format,width,height,frame_count,duration_ms,bytes,cdn_name,created_at,rendition_group) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                                            (slot, r.sha256, r.format, r.width, r.height, media.frame_count, media.duration_ms, len(r.data), name, now, group))
                                # The digest is not globally unique: an
                                # identical rendition in the other slot has a
                                # different manifest identity and CDN name.
                                row = con.execute("SELECT * FROM experience_assets WHERE slot=? AND sha256=?", (slot, r.sha256)).fetchone()
                                records.append(dict(row))
                            did = experience.default_draft(con)
                            col = "login_asset_id" if slot == "login" else "library_asset_id"
                            con.execute(f"UPDATE experience_revisions SET {col}=? WHERE id=?", (records[0]["id"], did))
                            con.commit()
                        except Exception:
                            con.rollback()
                            raise
                        finally:
                            con.close()
                    except Exception:
                        cleanup_many = getattr(cdn, "discard_many", None)
                        if callable(cleanup_many):
                            try: cleanup_many(created_names)
                            except Exception: pass
                        else:
                            discard = getattr(cdn, "discard", None) or getattr(cdn, "remove", None)
                            if callable(discard):
                                for name in created_names:
                                    try: discard(name)
                                    except Exception: pass
                        raise
                    db.audit("owner", "experience.upload", "%s bytes=%d" % (slot,_body_len)); return self._json({"ok": True,"slot":slot,"asset":records[0],"renditions":records})
                except Exception as e:
                    if hasattr(e, "code"): return self._json({"ok": False,"error":{"code":e.code,"message":str(e)}},422)
                    return self._json({"ok": False,"error":{"code":"media_failed","message":"media validation failed"}},422)
            if path == "/api/experience/publish":
                try:
                    out = experience.publish(expected_revision=body.get("expected_revision"), idempotency_key=self.headers.get("Idempotency-Key") or "", request_hash=__import__('hashlib').sha256(_raw_body).hexdigest()); db.audit("owner", "experience.publish", "revision=%s" % out.get("revision")); return self._json(out)
                except experience.ConflictError as e: return self._json({"ok": False,"error":{"code":e.code,"message":e.message}},409)
                except experience.ExperienceError as e: return self._json({"ok": False,"error":{"code":e.code,"message":e.message}},422)
            if path == "/api/experience/rollback":
                try:
                    target = int(body.get("revision_id") or body.get("id") or 0)
                    out = experience.rollback(target, expected_revision=body.get("expected_revision"), idempotency_key=self.headers.get("Idempotency-Key") or "", request_hash=__import__('hashlib').sha256(_raw_body).hexdigest())
                    db.audit("owner", "experience.rollback", "target=%s revision=%s" % (target, out.get("revision"))); return self._json(out)
                except experience.ConflictError as e: return self._json({"ok":False,"error":{"code":e.code,"message":e.message}},409)
                except Exception: return self._json({"ok":False,"error":{"code":"rollback_failed","message":"rollback failed"}},422)
            if path == "/api/library/display-name":
                try:
                    sid = str(body.get("stable_id") or body.get("id") or "").upper()
                    out = experience.rename_label(
                        sid, str(body.get("display_name") or ""),
                        expected_revision=body.get("expected_revision"),
                        idempotency_key=self.headers.get("Idempotency-Key") or "",
                        request_hash=__import__('hashlib').sha256(_raw_body).hexdigest(),
                    )
                    db.audit("owner", "library.rename", sid)
                    return self._json(out)
                except experience.ConflictError as e: return self._json({"ok":False,"error":{"code":e.code,"message":e.message}},409)
                except ValueError as e: return self._json({"ok":False,"error":{"code":"invalid_label","message":str(e)}},422)

            if path == "/api/libs/cover":
                _qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                name = (_qs.get("name") or [""])[0].strip()
                n = _body_len
                if not name:
                    return self._json({"ok": False, "error": "name required"}, 400)
                if n <= 0 or n > 15 * 1024 * 1024:
                    return self._json({"ok": False, "error": "cover must be under 15 MB"}, 400)
                try:
                    stem = db.lib_card_name(name)
                    if not stem:
                        return self._json({"ok": False, "error": "bad name"}, 400)
                    out = db.lib_save_cover(stem, _raw_body)
                except ValueError as e:
                    return self._json({"ok": False, "error": str(e)}, 400)
                except Exception as e:
                    return self._json({"ok": False, "error": "cover save failed: %s" % e}, 400)
                return self._json({"ok": True, "cover": out})

            if path == "/api/libs/cover/delete":
                _qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                name = (_qs.get("name") or [""])[0].strip()
                if not name:
                    return self._json({"ok": False, "error": "name required"}, 400)
                try:
                    stem = db.lib_card_name(name)
                    if not stem:
                        return self._json({"ok": False, "error": "bad name"}, 400)
                    out = db.lib_remove_cover(stem)
                except Exception as e:
                    return self._json({"ok": False, "error": "cover remove failed: %s" % e}, 400)
                return self._json(out)

            if path == "/api/libs/upload":
                _qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                name = (_qs.get("name") or [""])[0].strip()
                version = (_qs.get("version") or [""])[0].strip()
                note = (_qs.get("note") or [""])[0].strip()
                n = _body_len
                if n <= 0 or n > 64 * 1024 * 1024:
                    return self._json({"ok": False, "error": "bad body size"}, 400)
                try:
                    # normalize before save so panel + app share STEM.so
                    name = db.lib_normalize_name(name)
                    # Dual-publish when the v3 master key is configured.  The
                    # encrypted object is created before either public legacy
                    # publication or DB mutation, so a v3 failure cannot leave
                    # a newly-advertised plaintext-only library.  Existing
                    # 1.6.62 deployments without the new key keep their legacy
                    # behavior until migration is explicitly configured.
                    secure_result = None
                    if str(os.environ.get("CROWNAUTH_PAYLOAD_MASTER_KEY") or "").strip():
                        secure_result = payload_service().publish_payload(
                            _raw_body, lib_id=name, revision=str(version or "1"),
                            metadata={"name": name},
                        )
                    from crownauth.lib_cdn import publish as publish_lib
                    cdn_result = publish_lib(name, _raw_body)
                    lib = db.lib_save(name, _raw_body, version, note)
                    if secure_result and str(secure_result.get("sha256") or "").lower() != str(lib.get("sha256") or "").lower():
                        raise RuntimeError("secure payload hash mismatch")
                except ValueError as e:
                    return self._json({"ok": False, "error": str(e) or "bad name"}, 400)
                except Exception as e:
                    return self._json({"ok": False, "error": "CDN publish failed; library was not changed: %s" % e}, 502)
                try:
                    from crownauth.persist import schedule_backup
                    schedule_backup()
                except Exception:
                    pass
                return self._json({
                    "ok": True,
                    "lib": lib,
                    "cdn": cdn_result,
                    "payload_v3": secure_result,
                    "card": lib.get("card") or db.lib_card_name(lib["name"]),
                })

            if path == "/api/libs/toggle":
                name = (body.get("name") or "").strip()
                if not name:
                    return self._json({"ok": False, "error": "missing name"}, 400)
                row = db.lib_get(name)
                if not row:
                    return self._json({"ok": False, "error": "not found"}, 404)
                db.lib_set_enabled(row["name"], bool(body.get("enabled")))
                try:
                    from crownauth.persist import schedule_backup
                    schedule_backup()
                except Exception:
                    pass
                return self._json({"ok": True, "name": row["name"], "enabled": bool(body.get("enabled"))})

            if path == "/api/libs/delete":
                name = (body.get("name") or "").strip()
                if not name:
                    return self._json({"ok": False, "error": "missing name"}, 400)
                row = db.lib_get(name)
                key = (row or {}).get("name") or name
                db.lib_delete(key)
                cdn_removed = False
                cdn_warning = ""
                try:
                    from crownauth.lib_cdn import remove as remove_lib
                    cdn_removed = remove_lib(key)
                    if db.lib_cdn_only():
                        from crownauth.lib_cdn import remove as remove_cover_asset
                        remove_cover_asset(db.lib_card_name(key) + ".cover.jpg")
                except Exception as e:
                    cdn_warning = str(e)
                try:
                    from crownauth.persist import schedule_backup
                    schedule_backup()
                except Exception:
                    pass
                return self._json({
                    "ok": True,
                    "name": key,
                    "cdn_removed": cdn_removed,
                    "cdn_warning": cdn_warning,
                })

            if path == "/api/settings":
                # FOREVER lock — panel/scripts cannot re-enable buyer-breaking gates
                locked_false = {
                    "force_update", "ota_enabled", "rate_limit_enabled",
                    "kill_switch",  # still allow via /api/kill intentionally
                }
                # kill_switch stays controllable via dedicated endpoint only
                for k, v in body.items():
                    if k in ("force_update", "ota_enabled", "rate_limit_enabled"):
                        continue  # ignore attempts to re-enable
                    if k in ("min_client_version_code", "min_client_protocol"):
                        # never raise floors that force OTA
                        try:
                            if int(v) > 0:
                                continue
                        except Exception:
                            continue
                    if k in db.DEFAULT_SETTINGS or k in db.all_settings():
                        db.set_setting(k, v)
                # re-assert safe forever values after any settings write
                db.set_setting("force_update", False)
                db.set_setting("ota_enabled", False)
                db.set_setting("rate_limit_enabled", False)
                db.set_setting("min_client_version_code", 0)
                db.set_setting("min_client_protocol", 0)
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

                # duration: custom clock (30:00 / 1:30:00), value+unit, seconds, plan, days
                custom = (body.get("duration_custom") or body.get("duration_clock") or body.get("custom_duration") or "").strip()
                if body.get("duration_unit") == "lifetime" or body.get("lifetime"):
                    secs = 0
                elif custom:
                    parsed = db.parse_duration_input(custom)
                    if parsed is None:
                        return self._json(
                            {"ok": False, "error": "Bad custom duration. Use 30:00 (30 min), 1:30:00, 45m, 2h, 1d"},
                            400,
                        )
                    secs = int(parsed)
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
            if path == "/api/rate/clear":
                n = db.rate_clear_all()
                return self._json({"ok": True, "cleared": n})
            if path == "/api/licenses/unban":
                db.unban_license(int(body["id"]))
                _persist()
                return self._json({"ok": True})
            if path == "/api/licenses/extend":
                secs = int(body.get("seconds") or 0)
                custom = (body.get("duration_custom") or body.get("duration_clock") or "").strip()
                if not secs and custom:
                    parsed = db.parse_duration_input(custom)
                    secs = int(parsed or 0)
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
