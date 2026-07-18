#!/usr/bin/env python3
"""Always-on entrypoint (Fly / Docker / VPS). PORT + PUBLIC_HOST from env.

BUILD: harden_v1 (anti-frida/xposed, integrity, client attestation)
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from http.server import ThreadingHTTPServer

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from crownauth import db  # noqa: E402
from crownauth import owner_auth  # noqa: E402
from crownauth.crypto_v2 import load_or_create_keypair  # noqa: E402
import crownauth.server as smod  # noqa: E402


def main() -> None:
    port = int(os.environ.get("PORT") or 8787)
    pub = (os.environ.get("PUBLIC_HOST") or "").strip().lower()
    pub = pub.replace("https://", "").replace("http://", "").split("/")[0]

    # Free tier: restore DB+secrets from GitHub backup before init (if wipe happened)
    try:
        from crownauth.persist import restore_if_needed, schedule_backup

        ok_r, msg_r = restore_if_needed()
        print(f"persist restore: {ok_r} {msg_r}")
    except Exception as e:
        print(f"persist restore skip: {e}")

    db.init_db()
    if pub:
        db.set_setting("client_api_host", pub)
        db.set_setting("client_api_scheme", "https")
        db.set_setting("client_api_port", 0)
    db.set_setting("force_online", True)
    db.set_setting("hybrid_lease", True)
    db.set_setting("allow_offline_envelope", True)
    db.set_setting("enable_owner_ip_allowlist", False)
    db.set_setting("panel_password_enabled", True)
    db.set_setting("api_port", port)
    db.set_setting("api_bind", "0.0.0.0")
    # CRITICAL: free-tier restore can revive old min_vc → OTA chrome loop.
    # Keep forced OTA OFF on every boot.
    db.set_setting("ota_enabled", False)
    db.set_setting("force_update", False)
    db.set_setting("min_client_version_code", 0)
    db.set_setting("min_client_protocol", 0)
    db.set_setting("blocked_build_ids", [])
    db.set_setting("update_message", "")

    smod.PRIV, smod.PUB = load_or_create_keypair()
    once = owner_auth.bootstrap_if_needed()
    owner_auth.load_or_create_api_token()
    try:
        from crownauth.persist import schedule_backup

        schedule_backup()
    except Exception:
        pass

    host_show = db.get_setting("client_api_host") or f"0.0.0.0:{port}"
    print("=" * 56)
    print("  CrownAuth LIVE")
    print(f"  Owner:  https://{host_show}/app/owner/auth/login")
    print(f"  Seller: https://{host_show}/app/user/auth/login")
    print(f"  Health: https://{host_show}/v2/health")
    if once:
        print(f"  FIRST password: {once}  (also in secrets/OWNER_PASSWORD_ONCE.txt)")
    print("=" * 56)

    httpd = ThreadingHTTPServer(("0.0.0.0", port), smod.Handler)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
