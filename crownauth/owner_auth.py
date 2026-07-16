#!/usr/bin/env python3
"""Owner panel authentication — required before public release."""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent
_env_data = (os.environ.get("CROWNAUTH_DATA") or "").strip()
if _env_data:
    SECRETS = Path(_env_data) / "secrets"
elif os.environ.get("CROWNAUTH_SECRETS"):
    SECRETS = Path(os.environ["CROWNAUTH_SECRETS"])
else:
    SECRETS = ROOT / "secrets"
PASS_PATH = SECRETS / "owner_password.hash"
TOKEN_PATH = SECRETS / "owner_api_token"
SESSIONS: dict[str, float] = {}  # token -> exp
RESELLER_SESSIONS: dict[str, dict] = {}  # token -> {exp, id, name}
SESSION_TTL = 12 * 3600


def ensure_dirs() -> None:
    SECRETS.mkdir(parents=True, exist_ok=True)


def _hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=32,
    )


def has_password() -> bool:
    return PASS_PATH.exists()


def set_password(password: str) -> None:
    ensure_dirs()
    if len(password) < 10:
        raise ValueError("Owner password must be at least 10 characters")
    salt = secrets.token_bytes(16)
    dk = _hash_password(password, salt)
    PASS_PATH.write_bytes(salt + dk)
    try:
        os.chmod(PASS_PATH, 0o600)
    except OSError:
        pass


def verify_password(password: str) -> bool:
    if not PASS_PATH.exists():
        return False
    raw = PASS_PATH.read_bytes()
    if len(raw) < 48:
        return False
    salt, dk = raw[:16], raw[16:48]
    try:
        got = _hash_password(password, salt)
    except Exception:
        return False
    return hmac.compare_digest(got, dk)


def load_or_create_api_token() -> str:
    ensure_dirs()
    if TOKEN_PATH.exists():
        return TOKEN_PATH.read_text(encoding="utf-8").strip()
    tok = secrets.token_urlsafe(32)
    TOKEN_PATH.write_text(tok + "\n", encoding="utf-8")
    try:
        os.chmod(TOKEN_PATH, 0o600)
    except OSError:
        pass
    return tok


def issue_session() -> str:
    tok = secrets.token_urlsafe(24)
    SESSIONS[tok] = time.time() + SESSION_TTL
    # GC
    now = time.time()
    dead = [k for k, exp in SESSIONS.items() if exp < now]
    for k in dead:
        SESSIONS.pop(k, None)
    return tok


def check_session(tok: str) -> bool:
    if not tok:
        return False
    exp = SESSIONS.get(tok)
    if not exp:
        return False
    if time.time() > exp:
        SESSIONS.pop(tok, None)
        return False
    # sliding
    SESSIONS[tok] = time.time() + SESSION_TTL
    return True


def issue_reseller_session(reseller_id: int, name: str) -> str:
    tok = secrets.token_urlsafe(24)
    RESELLER_SESSIONS[tok] = {
        "exp": time.time() + SESSION_TTL,
        "id": int(reseller_id),
        "name": name,
    }
    now = time.time()
    dead = [k for k, v in RESELLER_SESSIONS.items() if v.get("exp", 0) < now]
    for k in dead:
        RESELLER_SESSIONS.pop(k, None)
    return tok


def get_reseller_session(tok: str) -> Optional[dict]:
    if not tok:
        return None
    meta = RESELLER_SESSIONS.get(tok)
    if not meta:
        return None
    if time.time() > float(meta.get("exp", 0)):
        RESELLER_SESSIONS.pop(tok, None)
        return None
    meta["exp"] = time.time() + SESSION_TTL
    return meta


def check_owner_header(auth_header: Optional[str], x_owner_key: Optional[str], cookie: Optional[str] = None) -> bool:
    api = load_or_create_api_token()
    # Bearer session or static API token
    if auth_header and auth_header.lower().startswith("bearer "):
        val = auth_header[7:].strip()
        if hmac.compare_digest(val, api) or check_session(val):
            return True
    if x_owner_key and (hmac.compare_digest(x_owner_key, api) or check_session(x_owner_key)):
        return True
    if cookie:
        # oc_session=...
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("oc_session="):
                if check_session(part.split("=", 1)[1].strip()):
                    return True
    return False


def bootstrap_if_needed() -> str:
    """Create password if missing — returns plaintext once (or env override)."""
    ensure_dirs()
    note = SECRETS / "OWNER_PASSWORD_ONCE.txt"
    # Cloud: OWNER_PASSWORD env always wins on boot (survives free-tier disk wipe)
    env_pw = (os.environ.get("OWNER_PASSWORD") or "").strip()
    if env_pw and len(env_pw) >= 8:
        set_password(env_pw)
        note.write_text(
            "Owner password is set from OWNER_PASSWORD env (cloud).\n"
            "Change it in panel Settings after login if you want.\n",
            encoding="utf-8",
        )
        load_or_create_api_token()
        return env_pw
    if has_password():
        return ""
    pw = secrets.token_urlsafe(14)
    set_password(pw)
    note.write_text(
        "ONE-TIME owner panel password (change after login):\n"
        f"{pw}\n\n"
        "Delete this file after you save the password elsewhere.\n",
        encoding="utf-8",
    )
    try:
        os.chmod(note, 0o600)
    except OSError:
        pass
    load_or_create_api_token()
    return pw
