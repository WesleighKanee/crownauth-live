"""Server-side payload security primitives for CrownAuth.

This module deliberately contains no client bridge code.  It provides a small,
stateful control plane for enrolling an installation, authorizing immutable
payloads, and returning only an encrypted content-key envelope.  All signed
messages are domain separated and all persistent identifiers are opaque.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import db
from .crypto_v2 import load_or_create_keypair, normalize_token, token_fingerprint

VERSION = 1
MAX_OFFLINE_LEASE_SECONDS = 7 * 24 * 60 * 60
DEFAULT_CHALLENGE_SECONDS = 120
MAX_PAYLOAD_BYTES = 128 * 1024 * 1024


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError("invalid encoding")
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(dict(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _domain(domain: str, body: bytes) -> bytes:
    # Length prefix prevents concatenation/domain ambiguity.
    d = domain.encode("ascii")
    return b"CROWNAUTH-DOMAIN\x00" + len(d).to_bytes(2, "big") + d + b"\x00" + body


def sign_domain(private: Ed25519PrivateKey, domain: str, body: Mapping[str, Any] | bytes) -> str:
    raw = body if isinstance(body, bytes) else canonical(body)
    return _b64(private.sign(_domain(domain, raw)))


def verify_domain(public: Ed25519PublicKey, domain: str, body: Mapping[str, Any] | bytes, signature: str | bytes) -> bool:
    try:
        raw = body if isinstance(body, bytes) else canonical(body)
        sig = signature if isinstance(signature, bytes) else _unb64(signature)
        public.verify(sig, _domain(domain, raw))
        return True
    except (InvalidSignature, ValueError, TypeError, Exception) as exc:
        # Do not leak parser/signature distinctions at an authorization boundary.
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        return False


# Explicit aliases make the boundary obvious to callers and avoid accidental
# reuse of the legacy, non-domain-separated signing helpers.
domain_sign = sign_domain
domain_verify = verify_domain


def generate_install_keys() -> dict[str, Any]:
    """Generate client-side keys for tests/tools; private values never leave caller."""
    sign = Ed25519PrivateKey.generate()
    enc = X25519PrivateKey.generate()
    return {
        "signing_private": sign,
        "signing_public": sign.public_key(),
        "encryption_private": enc,
        "encryption_public": enc.public_key(),
        "signing_public_b64": _b64(sign.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
        "encryption_public_b64": _b64(enc.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
    }


def unwrap_content_key(envelope: Mapping[str, Any], *, encryption_private: X25519PrivateKey, install_id: str) -> bytes:
    """Client/tool helper used by security tests; no server endpoint exposes this."""
    try:
        eph = X25519PublicKey.from_public_bytes(_unb64(str(envelope["ephemeral_public_key"])))
        shared = encryption_private.exchange(eph)
        info = _domain(PayloadSecurity.WRAP_DOMAIN, canonical({"jti": envelope["jti"], "install_id": install_id}))
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared)
        aad = canonical({"jti": envelope["jti"], "payload_hash": envelope["payload_hash"], "install_id": install_id})
        return AESGCM(key).decrypt(_unb64(str(envelope["nonce"])), _unb64(str(envelope["ciphertext"])), aad)
    except (KeyError, ValueError, InvalidTag) as exc:
        raise PayloadSecurityError("invalid wrapped content key") from exc


def _ed_public(value: Any) -> Ed25519PublicKey:
    if isinstance(value, Ed25519PublicKey):
        return value
    raw = value if isinstance(value, bytes) else _unb64(str(value))
    if len(raw) != 32:
        raise ValueError("invalid signing public key")
    return Ed25519PublicKey.from_public_bytes(raw)


def _x_public(value: Any) -> X25519PublicKey:
    if isinstance(value, X25519PublicKey):
        return value
    raw = value if isinstance(value, bytes) else _unb64(str(value))
    if len(raw) != 32:
        raise ValueError("invalid encryption public key")
    return X25519PublicKey.from_public_bytes(raw)


def _raw_public(key: Ed25519PublicKey | X25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _now(clock: Any = time.time) -> int:
    return int(clock())


class PayloadSecurityError(Exception):
    code = "payload_security"


class EnrollmentError(PayloadSecurityError):
    code = "enrollment_failed"


class AuthorizationError(PayloadSecurityError):
    code = "authorization_failed"


class PayloadNotFound(PayloadSecurityError):
    code = "payload_not_found"


class EncryptedContentStore:
    """Immutable filesystem adapter storing ciphertext and non-secret metadata."""
    def __init__(self, root: str | Path, master_key: bytes | None = None):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.master_key = bytes(master_key) if master_key is not None else self._master_from_env()
        if len(self.master_key) != 32:
            raise ValueError("payload master key must be 32 bytes")

    @staticmethod
    def _master_from_env() -> bytes:
        encoded = os.environ.get("CROWNAUTH_PAYLOAD_MASTER_KEY", "").strip()
        if not encoded:
            raise ValueError("CROWNAUTH_PAYLOAD_MASTER_KEY is required")
        try:
            raw = _unb64(encoded)
        except Exception:
            try:
                raw = bytes.fromhex(encoded)
            except Exception as exc:
                raise ValueError("invalid payload master key") from exc
        if len(raw) != 32 and len(encoded) == 32:
            raw = encoded.encode("ascii")
        return raw

    def _path(self, digest: str) -> Path:
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest.lower()):
            raise ValueError("invalid payload hash")
        p = (self.root / digest.lower()).resolve()
        p.relative_to(self.root)
        return p

    def encrypt(self, payload: bytes, *, metadata: Mapping[str, Any], content_key: bytes | None = None) -> dict[str, Any]:
        payload = bytes(payload)
        if not payload or len(payload) > MAX_PAYLOAD_BYTES:
            raise ValueError("payload size out of bounds")
        digest = hashlib.sha256(payload).hexdigest()
        key = bytes(content_key) if content_key is not None else AESGCM.generate_key(bit_length=256)
        if len(key) != 32:
            raise ValueError("content key must be 32 bytes")
        nonce = secrets.token_bytes(12)
        aad = canonical({"v": VERSION, "sha256": digest, **dict(metadata)})
        ciphertext = AESGCM(key).encrypt(nonce, payload, aad)
        # The server stores the content key only under an AEAD envelope keyed by
        # the deployment-provided master key; it is never returned by this API.
        key_nonce = secrets.token_bytes(12)
        wrapped = AESGCM(self.master_key).encrypt(key_nonce, key, canonical({"sha256": digest, "v": VERSION}))
        path = self._path(digest)
        if path.exists():
            existing = path.read_bytes()
            if existing != ciphertext:
                raise ValueError("immutable payload collision")
        else:
            tmp = path.with_name("." + path.name + "." + secrets.token_hex(8))
            tmp.write_bytes(ciphertext)
            os.replace(tmp, path)
        return {"sha256": digest, "bytes": len(payload), "ciphertext_bytes": len(ciphertext),
                "nonce": _b64(nonce), "key_nonce": _b64(key_nonce), "wrapped_key": _b64(wrapped),
                "metadata": dict(metadata)}

    def read(self, metadata: Mapping[str, Any]) -> tuple[bytes, bytes]:
        digest = str(metadata.get("sha256") or "").lower()
        path = self._path(digest)
        if not path.is_file():
            raise PayloadNotFound("payload not found")
        try:
            key = AESGCM(self.master_key).decrypt(_unb64(str(metadata["key_nonce"])), _unb64(str(metadata["wrapped_key"])), canonical({"sha256": digest, "v": VERSION}))
            ciphertext = path.read_bytes()
            payload = AESGCM(key).decrypt(_unb64(str(metadata["nonce"])), ciphertext, canonical({"v": VERSION, "sha256": digest, **dict(metadata.get("metadata") or {})}))
        except (KeyError, ValueError, InvalidTag) as exc:
            raise PayloadSecurityError("payload integrity failure") from exc
        if hashlib.sha256(payload).hexdigest() != digest:
            raise PayloadSecurityError("payload hash mismatch")
        return payload, key

    def read_ciphertext(self, metadata: Mapping[str, Any]) -> bytes:
        """Return immutable AEAD ciphertext only; plaintext never crosses HTTP."""
        digest = str(metadata.get("sha256") or "").lower()
        path = self._path(digest)
        if not path.is_file():
            raise PayloadNotFound("payload not found")
        data = path.read_bytes()
        if not data or len(data) > MAX_PAYLOAD_BYTES + 16:
            raise PayloadSecurityError("payload size out of bounds")
        return data


# Names used by integrations; all point to the same immutable adapter.
ContentAddressedPayloadStore = EncryptedContentStore
EncryptedPayloadStore = EncryptedContentStore


@dataclass(frozen=True)
class Authorization:
    token: str
    claims: dict[str, Any]


class PayloadSecurity:
    """Stateful server control plane. Uses the existing CrownAuth database."""
    ENROLL_DOMAIN = "CrownAuth/InstallEnrollment/v1"
    AUTH_DOMAIN = "CrownAuth/PayloadAuthorization/v1"
    LEASE_DOMAIN = "CrownAuth/OfflineLease/v1"
    WRAP_DOMAIN = "CrownAuth/ContentKeyWrap/v1"
    METADATA_DOMAIN = "CrownAuth/PayloadMetadata/v1"
    MAX_OFFLINE_LEASE_SECONDS = MAX_OFFLINE_LEASE_SECONDS

    def __init__(self, *, signing_private: Ed25519PrivateKey | None = None, store: EncryptedContentStore | None = None, clock: Any = time.time, audit_key: bytes | None = None):
        self.private, self.public = (signing_private, signing_private.public_key()) if signing_private else load_or_create_keypair()
        self.store = store
        self.clock = clock
        self.audit_key = bytes(audit_key) if audit_key is not None else None
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        con = db.connect()
        con.executescript("""
        CREATE TABLE IF NOT EXISTS payload_installations (
            install_id TEXT PRIMARY KEY, license_id INTEGER NOT NULL, signing_public_key BLOB NOT NULL,
            encryption_public_key BLOB NOT NULL, created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL,
            revoked_at INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS payload_challenges (
            nonce TEXT PRIMARY KEY, install_id TEXT NOT NULL, purpose TEXT NOT NULL, claims_json TEXT NOT NULL,
            created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS payload_authorizations (
            jti TEXT PRIMARY KEY, install_id TEXT NOT NULL, license_id INTEGER NOT NULL,
            lib_id TEXT NOT NULL, revision TEXT NOT NULL, payload_hash TEXT NOT NULL,
            nonce TEXT NOT NULL, issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked_at INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS payload_objects (
            sha256 TEXT PRIMARY KEY, metadata_json TEXT NOT NULL, created_at INTEGER NOT NULL, revoked_at INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS payload_leases (
            lease_id TEXT PRIMARY KEY, install_id TEXT NOT NULL, license_id INTEGER NOT NULL,
            payload_hash TEXT NOT NULL, nonce TEXT NOT NULL, issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked_at INTEGER NOT NULL DEFAULT 0
        );
        """)
        con.commit(); con.close()

    def _license(self, license_id: int | None = None, token: str | None = None) -> dict[str, Any]:
        lic = db.get_license(int(license_id)) if license_id is not None else db.get_license_by_token(normalize_token(token or ""))
        if not lic or lic.get("status") != "active":
            raise AuthorizationError("license inactive")
        exp = int(lic.get("expires_at") or 0)
        if exp and _now(self.clock) > exp:
            raise AuthorizationError("license expired")
        return lic

    def _audit(self, action: str, install_id: str, detail: str = "") -> None:
        # Install IDs are caller-controlled. Store a keyed pseudonym, never raw identity.
        pseudo = hmac.new(self._audit_key(), install_id.encode(), hashlib.sha256).hexdigest()[:24]
        db.audit("payload", action, "install=" + pseudo + (" " + detail if detail else ""))

    def _audit_key(self) -> bytes:
        if self.audit_key:
            return hashlib.sha256(self.audit_key).digest()
        encoded = os.environ.get("CROWNAUTH_AUDIT_KEY", "").encode()
        # A deployment may rotate this key; a fixed source-code secret is forbidden.
        if not encoded:
            encoded = os.environ.get("CROWNAUTH_PAYLOAD_MASTER_KEY", "").encode()
        if not encoded:
            # No source-code secret: deterministic pseudonyms remain stable for
            # this authority key while deployments may provide a dedicated key.
            return hashlib.sha256(_raw_public(self.public)).digest()
        return hashlib.sha256(encoded).digest()

    def begin_enrollment(self, *, install_id: str, license_id: int | None = None, token: str | None = None, ttl: int = DEFAULT_CHALLENGE_SECONDS) -> dict[str, Any]:
        install_id = str(install_id or "").strip()
        if not install_id or len(install_id) > 128:
            raise EnrollmentError("invalid install id")
        lic = self._license(license_id, token)
        now = _now(self.clock); ttl = max(10, min(DEFAULT_CHALLENGE_SECONDS, int(ttl)))
        nonce = _b64(secrets.token_bytes(32))
        con = db.connect(); con.execute("INSERT INTO payload_challenges(nonce,install_id,purpose,claims_json,created_at,expires_at) VALUES(?,?,?,?,?,?)", (nonce, install_id, "enroll", json.dumps({"license_id": int(lic["id"])}, sort_keys=True), now, now + ttl)); con.commit(); con.close()
        return {"ok": True, "challenge": nonce, "expires_at": now + ttl, "license_id": int(lic["id"]), "server_key_id": hashlib.sha256(_raw_public(self.public)).hexdigest()[:16]}

    def complete_enrollment(self, *, install_id: str, challenge: str, signing_public_key: Any, encryption_public_key: Any, proof: str) -> dict[str, Any]:
        install_id = str(install_id or "").strip()
        try:
            sp = _ed_public(signing_public_key); ep = _x_public(encryption_public_key)
        except Exception as exc:
            raise EnrollmentError("invalid install keys") from exc
        con = db.connect(); row = con.execute("SELECT * FROM payload_challenges WHERE nonce=? AND purpose='enroll'", (challenge,)).fetchone()
        if not row or row["install_id"] != install_id or row["consumed_at"] or _now(self.clock) > int(row["expires_at"]):
            con.close(); raise EnrollmentError("challenge expired")
        claims = json.loads(row["claims_json"])
        body = {"install_id": install_id, "challenge": challenge, "license_id": int(claims["license_id"]), "signing_public_key": _b64(_raw_public(sp)), "encryption_public_key": _b64(_raw_public(ep))}
        if not verify_domain(sp, self.ENROLL_DOMAIN, body, proof):
            con.close(); raise EnrollmentError("invalid enrollment proof")
        lic = self._license(int(claims["license_id"]))
        now = _now(self.clock)
        con.execute("INSERT INTO payload_installations(install_id,license_id,signing_public_key,encryption_public_key,created_at,last_seen,revoked_at) VALUES(?,?,?,?,?,?,0) ON CONFLICT(install_id) DO UPDATE SET license_id=excluded.license_id,signing_public_key=excluded.signing_public_key,encryption_public_key=excluded.encryption_public_key,last_seen=excluded.last_seen,revoked_at=0", (install_id, int(lic["id"]), _raw_public(sp), _raw_public(ep), now, now))
        con.execute("UPDATE payload_challenges SET consumed_at=? WHERE nonce=?", (now, challenge)); con.commit(); con.close()
        self._audit("install.enrolled", install_id, "license=%d" % int(lic["id"]))
        return {"ok": True, "install_id": install_id, "license_id": int(lic["id"]), "server_key_id": hashlib.sha256(_raw_public(self.public)).hexdigest()[:16]}

    def challenge_authorization(self, *, install_id: str, lib_id: str, revision: str, payload_hash: str, nonce: str | None = None, ttl: int = DEFAULT_CHALLENGE_SECONDS) -> dict[str, Any]:
        self._installation(install_id)
        if not str(lib_id or "").strip() or not str(revision or "").strip():
            raise AuthorizationError("library and revision are required")
        if len(str(payload_hash)) != 64 or any(c not in "0123456789abcdef" for c in str(payload_hash).lower()): raise AuthorizationError("invalid payload hash")
        now = _now(self.clock); ttl = max(10, min(DEFAULT_CHALLENGE_SECONDS, int(ttl))); challenge_nonce = _b64(secrets.token_bytes(32))
        claims = {"lib_id": str(lib_id), "revision": str(revision), "payload_hash": str(payload_hash).lower(), "nonce": str(nonce or _b64(secrets.token_bytes(24)))}
        con = db.connect(); con.execute("INSERT INTO payload_challenges(nonce,install_id,purpose,claims_json,created_at,expires_at) VALUES(?,?,?,?,?,?)", (challenge_nonce, str(install_id), "authorize", json.dumps(claims, sort_keys=True), now, now + ttl)); con.commit(); con.close()
        return {"ok": True, "challenge": challenge_nonce, "expires_at": now + ttl, **claims}

    def _installation(self, install_id: str) -> sqlite3.Row:
        con = db.connect(); row = con.execute("SELECT * FROM payload_installations WHERE install_id=?", (str(install_id),)).fetchone(); con.close()
        if not row or int(row["revoked_at"] or 0): raise AuthorizationError("installation revoked")
        lic = self._license(int(row["license_id"]))
        return row

    def authorize(self, *, install_id: str, challenge: str, proof: str, nonce: str | None = None, ttl: int = 300) -> dict[str, Any]:
        row_install = self._installation(install_id); now = _now(self.clock)
        con = db.connect(); row = con.execute("SELECT * FROM payload_challenges WHERE nonce=? AND purpose='authorize'", (challenge,)).fetchone()
        if not row or row["install_id"] != str(install_id) or row["consumed_at"] or now > int(row["expires_at"]): con.close(); raise AuthorizationError("challenge expired")
        claims = json.loads(row["claims_json"]); requested_nonce = str(nonce or claims.get("nonce") or _b64(secrets.token_bytes(24)))
        body = {"install_id": str(install_id), "challenge": challenge, **claims, "nonce": requested_nonce}
        pub = Ed25519PublicKey.from_public_bytes(bytes(row_install["signing_public_key"]))
        if not verify_domain(pub, self.AUTH_DOMAIN, body, proof): con.close(); raise AuthorizationError("invalid authorization proof")
        lic = self._license(int(row_install["license_id"])); exp = int(lic.get("expires_at") or 0); ttl = max(30, min(900, int(ttl))); expires = now + ttl; expires = min(expires, exp) if exp else expires
        jti = secrets.token_hex(16)
        signed_claims = {"v": VERSION, "jti": jti, "license_id": int(lic["id"]), "install_id": str(install_id), "install_pseudonym": hmac.new(self._audit_key(), str(install_id).encode(), hashlib.sha256).hexdigest()[:24], "lib_id": claims["lib_id"], "revision": claims["revision"], "payload_hash": claims["payload_hash"], "nonce": requested_nonce, "iat": now, "exp": expires}
        token = "PAS1." + _b64(canonical(signed_claims)) + "." + sign_domain(self.private, self.AUTH_DOMAIN, signed_claims)
        con.execute("UPDATE payload_challenges SET consumed_at=? WHERE nonce=?", (now, challenge)); con.execute("INSERT INTO payload_authorizations VALUES(?,?,?,?,?,?,?,?,?,0)", (jti, str(install_id), int(lic["id"]), claims["lib_id"], claims["revision"], claims["payload_hash"], requested_nonce, now, expires)); con.commit(); con.close()
        self._audit("payload.authorized", install_id, "lib=%s revision=%s" % (claims["lib_id"], claims["revision"]))
        return {"ok": True, "authorization": token, "jti": jti, "expires_at": expires, "payload_hash": claims["payload_hash"]}

    def verify_authorization(self, token: str, *, install_id: str, lib_id: str, revision: str, payload_hash: str, nonce: str | None = None) -> Authorization:
        try:
            p = str(token).split("."); assert len(p) == 3 and p[0] == "PAS1"; claims = json.loads(_unb64(p[1])); assert verify_domain(self.public, self.AUTH_DOMAIN, claims, p[2])
        except Exception as exc: raise AuthorizationError("invalid authorization") from exc
        now = _now(self.clock)
        if claims.get("install_id") != str(install_id) or claims.get("lib_id") != str(lib_id) or claims.get("revision") != str(revision) or claims.get("payload_hash") != str(payload_hash).lower() or (nonce is not None and claims.get("nonce") != str(nonce)) or now > int(claims.get("exp", 0)):
            raise AuthorizationError("authorization binding mismatch")
        con = db.connect(); row = con.execute("SELECT * FROM payload_authorizations WHERE jti=?", (claims.get("jti"),)).fetchone(); con.close()
        if not row or row["revoked_at"] or self._installation(install_id)["license_id"] != claims.get("license_id"): raise AuthorizationError("authorization revoked")
        return Authorization(token=token, claims=claims)

    def wrap_content_key(self, authorization: str, *, install_id: str, content_key: bytes) -> dict[str, Any]:
        auth = self.verify_authorization(authorization, install_id=install_id, lib_id=str(self._auth_claim(authorization, "lib_id")), revision=str(self._auth_claim(authorization, "revision")), payload_hash=str(self._auth_claim(authorization, "payload_hash")))
        row = self._installation(install_id); recipient = X25519PublicKey.from_public_bytes(bytes(row["encryption_public_key"]))
        eph = X25519PrivateKey.generate(); shared = eph.exchange(recipient); key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_domain(self.WRAP_DOMAIN, canonical({"jti": auth.claims["jti"], "install_id": install_id}))).derive(shared); nonce = secrets.token_bytes(12); aad = canonical({"jti": auth.claims["jti"], "payload_hash": auth.claims["payload_hash"], "install_id": install_id}); wrapped = AESGCM(key).encrypt(nonce, bytes(content_key), aad)
        return {"v": VERSION, "alg": "X25519-HKDF-SHA256-AES-256-GCM", "ephemeral_public_key": _b64(_raw_public(eph.public_key())), "nonce": _b64(nonce), "ciphertext": _b64(wrapped), "jti": auth.claims["jti"], "payload_hash": auth.claims["payload_hash"]}

    @staticmethod
    def _auth_claim(token: str, name: str) -> Any:
        try: return json.loads(_unb64(str(token).split(".")[1]))[name]
        except Exception as exc: raise AuthorizationError("invalid authorization") from exc

    def issue_offline_lease(self, *, authorization: str, install_id: str, seconds: int = 3600) -> dict[str, Any]:
        claims = json.loads(_unb64(str(authorization).split(".")[1])); self.verify_authorization(authorization, install_id=install_id, lib_id=str(claims["lib_id"]), revision=str(claims["revision"]), payload_hash=str(claims["payload_hash"]))
        now = _now(self.clock); seconds = max(1, min(MAX_OFFLINE_LEASE_SECONDS, int(seconds)))
        lic = self._license(int(claims["license_id"]))
        license_exp = int(lic.get("expires_at") or 0)
        exp = now + seconds
        if license_exp:
            exp = min(exp, license_exp)
        lease = {"v": VERSION, "lease_id": secrets.token_hex(16), "license_id": claims["license_id"], "install_id": install_id, "lib_id": claims["lib_id"], "revision": claims["revision"], "payload_hash": claims["payload_hash"], "nonce": claims["nonce"], "iat": now, "exp": exp}
        signed = "POL1." + _b64(canonical(lease)) + "." + sign_domain(self.private, self.LEASE_DOMAIN, lease)
        con = db.connect(); con.execute("INSERT INTO payload_leases VALUES(?,?,?,?,?,?,?,0)", (lease["lease_id"], install_id, int(claims["license_id"]), claims["payload_hash"], claims["nonce"], now, exp)); con.commit(); con.close(); return {"ok": True, "lease": signed, "expires_at": exp}

    def verify_offline_lease(self, lease_token: str, *, install_id: str, payload_hash: str, lib_id: str, revision: str) -> dict[str, Any]:
        try:
            parts = str(lease_token).split("."); assert len(parts) == 3 and parts[0] == "POL1"
            claims = json.loads(_unb64(parts[1])); assert verify_domain(self.public, self.LEASE_DOMAIN, claims, parts[2])
        except Exception as exc:
            raise AuthorizationError("invalid offline lease") from exc
        if claims.get("install_id") != str(install_id) or claims.get("payload_hash") != str(payload_hash).lower() or claims.get("lib_id") != str(lib_id) or claims.get("revision") != str(revision):
            raise AuthorizationError("offline lease binding mismatch")
        if _now(self.clock) > int(claims.get("exp", 0)) or int(claims.get("exp", 0)) - int(claims.get("iat", 0)) > MAX_OFFLINE_LEASE_SECONDS:
            raise AuthorizationError("offline lease expired")
        con = db.connect(); row = con.execute("SELECT * FROM payload_leases WHERE lease_id=?", (claims.get("lease_id"),)).fetchone(); con.close()
        if not row or row["revoked_at"]:
            raise AuthorizationError("offline lease revoked")
        self._installation(install_id)
        return claims

    def publish_payload(self, payload: bytes, *, lib_id: str, revision: str, metadata: Mapping[str, Any] | None = None) -> dict[str, Any]:
        if not self.store:
            raise PayloadSecurityError("encrypted content store is not configured")
        meta = {"lib_id": str(lib_id), "revision": str(revision), **dict(metadata or {})}
        result = self.store.encrypt(payload, metadata=meta)
        result["metadata_signature"] = sign_domain(self.private, self.METADATA_DOMAIN, {"sha256": result["sha256"], "bytes": result["bytes"], "lib_id": str(lib_id), "revision": str(revision)})
        con = db.connect(); con.execute("INSERT INTO payload_objects(sha256,metadata_json,created_at,revoked_at) VALUES(?,?,?,0) ON CONFLICT(sha256) DO NOTHING", (result["sha256"], json.dumps(result, sort_keys=True), _now(self.clock))); con.commit(); con.close()
        return {k: v for k, v in result.items() if k not in {"wrapped_key"}}

    def payload_metadata(self, payload_hash: str) -> dict[str, Any]:
        con = db.connect(); row = con.execute("SELECT metadata_json,revoked_at FROM payload_objects WHERE sha256=?", (str(payload_hash).lower(),)).fetchone(); con.close()
        if not row or row["revoked_at"]:
            raise PayloadNotFound("payload not found")
        result = json.loads(row["metadata_json"])
        meta = result.get("metadata") or {}
        check = {"sha256": result.get("sha256"), "bytes": result.get("bytes"), "lib_id": meta.get("lib_id"), "revision": meta.get("revision")}
        if not verify_domain(self.public, self.METADATA_DOMAIN, check, result.get("metadata_signature", "")):
            raise PayloadSecurityError("payload metadata signature invalid")
        return result

    def content_key_for_authorization(self, authorization: str, *, install_id: str) -> dict[str, Any]:
        claims = json.loads(_unb64(str(authorization).split(".")[1]))
        self.verify_authorization(authorization, install_id=install_id, lib_id=str(claims["lib_id"]), revision=str(claims["revision"]), payload_hash=str(claims["payload_hash"]))
        if not self.store:
            raise PayloadSecurityError("encrypted content store is not configured")
        _, key = self.store.read(self.payload_metadata(str(claims["payload_hash"])))
        return self.wrap_content_key(authorization, install_id=install_id, content_key=key)

    def revoke(self, *, install_id: str | None = None, authorization_id: str | None = None, lease_id: str | None = None, license_id: int | None = None) -> int:
        con = db.connect(); clauses=[]; vals=[]
        for col,val in (("install_id",install_id),("jti",authorization_id),("lease_id",lease_id),("license_id",license_id)):
            if val is not None: clauses.append(col+"=?"); vals.append(val)
        if not clauses: raise ValueError("revocation selector required")
        total=0
        if install_id is not None: tables = ("payload_installations", "payload_authorizations", "payload_leases")
        elif authorization_id is not None: tables = ("payload_authorizations",)
        elif lease_id is not None: tables = ("payload_leases",)
        else: tables = ("payload_authorizations", "payload_leases", "payload_installations")
        for table in tables:
            key_clauses = clauses
            if table == "payload_installations" and authorization_id is not None: continue
            if table == "payload_leases" and authorization_id is not None: continue
            if table == "payload_authorizations" and lease_id is not None: continue
            try: cur=con.execute("UPDATE %s SET revoked_at=? WHERE %s" % (table, " AND ".join(key_clauses)), (_now(self.clock), *vals)); total += cur.rowcount
            except sqlite3.OperationalError: pass
        if license_id is not None:
            for table in ("payload_installations", "payload_authorizations", "payload_leases"):
                con.execute("UPDATE %s SET revoked_at=? WHERE license_id=?" % table, (_now(self.clock), license_id))
        con.commit(); con.close(); return total

    # Stable vocabulary for callers integrating the server slice.
    enroll_install = complete_enrollment
    create_install_challenge = begin_enrollment
    create_payload_challenge = challenge_authorization
    authorize_payload = authorize
    revoke_install = revoke
