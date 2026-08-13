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

    # Free tier: restore DB+secrets+libs from GitHub before init (if wipe happened)
    try:
        from crownauth.persist import restore_if_needed

        ok_r, msg_r = restore_if_needed()
        print(f"persist restore: {ok_r} {msg_r}")
    except Exception as e:
        print(f"persist restore skip: {e}")

    db.init_db()
    # Second pass: DB may have lib rows after init while DATA/libs is still empty.
    try:
        from crownauth.persist import heal_missing_libs

        ok_h, msg_h = heal_missing_libs()
        print(f"persist heal: {ok_h} {msg_h}")
    except Exception as e:
        print(f"persist heal skip: {e}")
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
    db.set_setting("update_apk_url", "")
    # Never lock buyers behind rate bans (testing / cold starts / shared IPs)
    db.set_setting("rate_limit_enabled", False)
    db.set_setting("max_failed_auth", 500)
    db.set_setting("ban_duration_sec", 60)
    try:
        n = db.rate_clear_all()
        print(f"rate_limit cleared: {n}")
    except Exception as e:
        print(f"rate_limit clear skip: {e}")

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
    print(f"  Ping:   https://{host_show}/v2/ping")
    if once:
        print(f"  FIRST password: {once}  (also in secrets/OWNER_PASSWORD_ONCE.txt)")
    print("=" * 56)

    # Internal tick keeps in-process caches warm AFTER boot. It does NOT stop
    # Render free-tier sleep — the whole dyno freezes when no EXTERNAL HTTP
    # arrives for ~15 min. Point UptimeRobot or cron-job.org at:
    #   GET/HEAD https://<PUBLIC_HOST>/v2/ping   every 5 min (cheapest)
    #   GET/HEAD https://<PUBLIC_HOST>/v2/health every 5 min (also fine)
    def _keepalive() -> None:
        import time
        import urllib.request

        ping = f"http://127.0.0.1:{port}/v2/ping"
        health = f"http://127.0.0.1:{port}/v2/health"
        while True:
            time.sleep(240)
            for url in (ping, health):
                try:
                    urllib.request.urlopen(url, timeout=15).read()
                    break
                except Exception:
                    continue

    import threading

    threading.Thread(target=_keepalive, daemon=True, name="agor-keepalive").start()

    httpd = ThreadingHTTPServer(("0.0.0.0", port), smod.Handler)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
