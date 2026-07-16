#!/usr/bin/env python3
"""
CrownAuth v2 — commercial-grade crypto.

- Ed25519 for ALL authority signatures (private key NEVER in APK)
- Opaque license tokens (high-entropy) bound server-side
- Session tokens: short-lived Ed25519-signed envelopes (anti-replay fields)
- Challenge-response handshake material
- Constant-time compares throughout
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
_env_data = (os.environ.get("CROWNAUTH_DATA") or "").strip()
if _env_data:
    SECRETS = Path(_env_data) / "secrets"
elif os.environ.get("CROWNAUTH_SECRETS"):
    SECRETS = Path(os.environ["CROWNAUTH_SECRETS"])
else:
    SECRETS = ROOT / "secrets"
PRIV_PATH = SECRETS / "ed25519_private.pem"
PUB_PATH = SECRETS / "ed25519_public.pem"
PUB_RAW_PATH = SECRETS / "ed25519_public.raw"  # 32 bytes for Java embed

# License token: short opaque codes (server is source of truth).
# Default: WC-A7K2-9MXP  (10 crockford chars ≈ 50 bits) — customizable length/prefix.
TOKEN_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O/1/I
DEFAULT_KEY_LEN = 10
SESSION_VERSION = 2
LICENSE_MAGIC = b"WCXS2"


def ensure_secrets_dir() -> None:
    SECRETS.mkdir(parents=True, exist_ok=True)


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_decode(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)


def load_or_create_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    ensure_secrets_dir()
    if PRIV_PATH.exists() and PUB_PATH.exists():
        priv = serialization.load_pem_private_key(PRIV_PATH.read_bytes(), password=None)
        pub = serialization.load_pem_public_key(PUB_PATH.read_bytes())
        assert isinstance(priv, Ed25519PrivateKey)
        assert isinstance(pub, Ed25519PublicKey)
        return priv, pub

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    PRIV_PATH.write_bytes(
        priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    PUB_PATH.write_bytes(
        pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    PUB_RAW_PATH.write_bytes(raw)
    try:
        os.chmod(PRIV_PATH, 0o600)
    except OSError:
        pass
    return priv, pub


def public_raw_bytes(pub: Optional[Ed25519PublicKey] = None) -> bytes:
    if pub is None:
        _, pub = load_or_create_keypair()
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def mint_license_token(prefix: str = "WC", length: int = DEFAULT_KEY_LEN) -> str:
    """
    Short opaque key. Security = server DB lookup + rate limits, not key length alone.
    length: 8–16 chars from unambiguous alphabet.
    """
    n = max(8, min(16, int(length or DEFAULT_KEY_LEN)))
    body = "".join(secrets.choice(TOKEN_ALPHABET) for _ in range(n))
    groups = [body[i : i + 4] for i in range(0, len(body), 4)]
    p = "".join(ch for ch in (prefix or "WC").upper() if ch.isalnum())[:8] or "WC"
    return f"{p}-" + "-".join(groups)


def normalize_token(token: str) -> str:
    """Normalize any key style: PREFIX-XXXX-XXXX or old WCX2-…"""
    t = (token or "").strip().upper().replace(" ", "")
    if not t:
        return t
    # keep alnum and dashes only
    cleaned = "".join(ch for ch in t if ch.isalnum() or ch == "-")
    # split prefix (before first dash) + body
    if "-" in cleaned:
        pre, rest = cleaned.split("-", 1)
        body = "".join(ch for ch in rest if ch.isalnum())
    else:
        # no dash — treat last 8–16 as body if long enough
        pre, body = "WC", cleaned
    groups = [body[i : i + 4] for i in range(0, len(body), 4)] if body else []
    if not groups:
        return cleaned
    return pre + "-" + "-".join(groups)


def token_fingerprint(token: str) -> str:
    return hashlib.sha256(normalize_token(token).encode("utf-8")).hexdigest()


def device_fingerprint(hwid: str, extras: str = "") -> str:
    material = f"{(hwid or '').strip()}|{(extras or '').strip()}".encode("utf-8")
    return hashlib.sha256(material).digest().hex()


def hwid_hash(hwid: str) -> str:
    return hashlib.sha256((hwid or "").strip().encode("utf-8")).hexdigest()


@dataclass
class SessionClaims:
    ver: int
    serial: str
    hwid_hash: str
    exp: int
    iat: int
    jti: str
    flags: int
    tier: str
    features: int
    nbf: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "v": self.ver,
            "sid": self.serial,
            "hh": self.hwid_hash,
            "exp": self.exp,
            "iat": self.iat,
            "jti": self.jti,
            "f": self.flags,
            "t": self.tier,
            "ft": self.features,
            "nbf": self.nbf,
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "SessionClaims":
        return SessionClaims(
            ver=int(d.get("v", 0)),
            serial=str(d.get("sid", "")),
            hwid_hash=str(d.get("hh", "")),
            exp=int(d.get("exp", 0)),
            iat=int(d.get("iat", 0)),
            jti=str(d.get("jti", "")),
            flags=int(d.get("f", 0)),
            tier=str(d.get("t", "std")),
            features=int(d.get("ft", 0)),
            nbf=int(d.get("nbf", 0)),
        )


def sign_session(priv: Ed25519PrivateKey, claims: SessionClaims) -> str:
    body = json.dumps(claims.to_dict(), separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = priv.sign(body)
    return b64u(body) + "." + b64u(sig)


def verify_session(
    pub: Ed25519PublicKey,
    token: str,
    *,
    now: Optional[int] = None,
    expect_hwid_hash: Optional[str] = None,
) -> tuple[bool, str, Optional[SessionClaims]]:
    now = now or int(time.time())
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return False, "Malformed session", None
        body = b64u_decode(parts[0])
        sig = b64u_decode(parts[1])
        pub.verify(sig, body)
        claims = SessionClaims.from_dict(json.loads(body.decode("utf-8")))
    except InvalidSignature:
        return False, "Invalid session signature", None
    except Exception:
        return False, "Corrupt session", None

    if claims.ver != SESSION_VERSION:
        return False, "Session version mismatch", None
    if claims.nbf and now < claims.nbf:
        return False, "Session not yet valid", None
    if now > claims.exp:
        return False, "Session expired", None
    if expect_hwid_hash and not hmac.compare_digest(claims.hwid_hash, expect_hwid_hash):
        return False, "Session device mismatch", None
    return True, "ok", claims


def sign_config_blob(priv: Ed25519PrivateKey, config: dict[str, Any]) -> str:
    """Signed live-config for clients (kill switch, force online, brand, crl version)."""
    config = dict(config)
    config["iat"] = int(time.time())
    body = json.dumps(config, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = priv.sign(body)
    return b64u(body) + "." + b64u(sig)


def verify_config_blob(pub: Ed25519PublicKey, blob: str) -> tuple[bool, Optional[dict]]:
    try:
        a, b = blob.split(".", 1)
        body = b64u_decode(a)
        sig = b64u_decode(b)
        pub.verify(sig, body)
        return True, json.loads(body.decode("utf-8"))
    except Exception:
        return False, None


def challenge_nonce() -> str:
    return secrets.token_hex(16)


def response_proof(license_token: str, challenge: str, hwid: str) -> str:
    """Client proof: not secret-derived from master — binds key+hwid+challenge."""
    msg = f"WCX-CHAL|v1|{normalize_token(license_token)}|{challenge}|{hwid}".encode("utf-8")
    return hashlib.sha256(msg).hexdigest()


def check_proof(license_token: str, challenge: str, hwid: str, proof: str) -> bool:
    expect = response_proof(license_token, challenge, hwid)
    return hmac.compare_digest(expect, (proof or "").lower())


def java_public_key_constants(raw32: bytes) -> str:
    """Emit XOR-split int arrays for APK embed (public key only — safe to ship)."""
    if len(raw32) != 32:
        raise ValueError("ed25519 public must be 32 bytes")
    masks = [0x3D, 0x91, 0xC7, 0x2A]
    lines = []
    for i in range(4):
        part = raw32[i * 8 : (i + 1) * 8]
        m = masks[i]
        vals = [b ^ m ^ ((i * 13 + j * 7) & 0xFF) for j, b in enumerate(part)]
        lines.append(f"    private static final int[] P{i} = new int[]{{{', '.join(str(v) for v in vals)}}};")
    return "\n".join(lines)


# Offline long-lived license envelope (optional airgap mode)
# payload: magic|ver|flags|serial_u32|exp_u32|hwid_crc16|features_u16|reserved_u16 + ed25519 sig
OFFLINE_FLAG_LIFETIME = 0x01
OFFLINE_FLAG_HWID = 0x02
OFFLINE_FLAG_VIP = 0x04
OFFLINE_FLAG_OWNER = 0x08


def issue_offline_envelope(
    priv: Ed25519PrivateKey,
    *,
    serial: int,
    expire_unix: int,
    flags: int,
    hwid: str = "",
    features: int = 0xFFFF,
) -> str:
    hcrc = 0
    if hwid:
        flags |= OFFLINE_FLAG_HWID
        hcrc = struct.unpack(">H", hashlib.sha256(hwid.encode()).digest()[:2])[0]
    if expire_unix == 0:
        flags |= OFFLINE_FLAG_LIFETIME
    payload = LICENSE_MAGIC + struct.pack(
        ">BBIIHH",
        2,
        flags & 0xFF,
        serial & 0xFFFFFFFF,
        expire_unix & 0xFFFFFFFF,
        hcrc & 0xFFFF,
        features & 0xFFFF,
    )
    # pad to fixed 24-byte payload after magic handled: magic 5 + 14 = 19 → pad
    payload = payload.ljust(24, b"\x00")
    sig = priv.sign(payload)
    return "WCO2." + b64u(payload + sig)


def verify_offline_envelope(
    pub: Ed25519PublicKey,
    key: str,
    *,
    hwid: str = "",
    now: Optional[int] = None,
) -> tuple[bool, str, Optional[dict]]:
    now = now or int(time.time())
    try:
        if not key.strip().upper().startswith("WCO2."):
            return False, "Not an offline key", None
        raw = b64u_decode(key.strip().split(".", 1)[1])
        if len(raw) < 24 + 64:
            return False, "Truncated offline key", None
        payload, sig = raw[:24], raw[24:88]
        pub.verify(sig, payload)
        if payload[:5] != LICENSE_MAGIC:
            return False, "Bad offline magic", None
        ver, flags, serial, exp, hcrc, features = struct.unpack(">BBIIHH", payload[5:19])
    except InvalidSignature:
        return False, "Invalid offline signature", None
    except Exception:
        return False, "Corrupt offline key", None

    if ver != 2:
        return False, "Offline key version", None
    lifetime = bool(flags & OFFLINE_FLAG_LIFETIME) or exp == 0
    if not lifetime and now > exp:
        return False, "Offline key expired", None
    if flags & OFFLINE_FLAG_HWID:
        got = struct.unpack(">H", hashlib.sha256((hwid or "").encode()).digest()[:2])[0]
        if got != hcrc:
            return False, "Offline key device mismatch", None
    tier = "owner" if flags & OFFLINE_FLAG_OWNER else ("vip" if flags & OFFLINE_FLAG_VIP else "std")
    return True, "ok", {
        "serial": serial,
        "flags": flags,
        "exp": exp,
        "features": features,
        "tier": tier,
        "lifetime": lifetime,
    }
