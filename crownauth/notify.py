"""Optional owner alerts (Discord webhook only). No Telegram."""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Optional

_last_send: dict[str, float] = {}
_MIN_GAP = 2.0


def _settings() -> dict[str, Any]:
    try:
        from crownauth import db

        return db.all_settings()
    except Exception:
        return {}


def _env(name: str) -> str:
    import os

    return (os.environ.get(name) or "").strip()


def discord_webhook(s: Optional[dict] = None) -> str:
    s = s or _settings()
    return (s.get("webhook_url") or s.get("discord_webhook") or _env("DISCORD_WEBHOOK") or "").strip()


def send(text: str, *, force: bool = False, kind: str = "info") -> tuple[bool, str]:
    """Send to Discord webhook if configured. Silent no-op otherwise."""
    s = _settings()
    if not force and not s.get("notify_enabled", False):
        return False, "notifications off"
    text = (text or "").strip()
    if not text:
        return False, "empty"
    if len(text) > 1900:
        text = text[:1890] + "…"

    now = time.time()
    if not force and now - _last_send.get(kind, 0) < _MIN_GAP:
        return True, "rate-limited (ok)"
    _last_send[kind] = now

    wh = discord_webhook(s)
    if not wh:
        return False, "no webhook configured"
    return _discord(wh, text)


def send_async(text: str, *, force: bool = False, kind: str = "info") -> None:
    def _run() -> None:
        try:
            send(text, force=force, kind=kind)
        except Exception:
            pass

    threading.Thread(target=_run, daemon=True).start()


def notify_if(flag: str, text: str, *, kind: str = "info") -> None:
    """Only fires if notify_enabled and optional flag are true + webhook set."""
    s = _settings()
    if not s.get("notify_enabled", False):
        return
    if flag and not s.get(flag, False):
        return
    send_async(text, kind=kind)


def _discord(webhook: str, text: str) -> tuple[bool, str]:
    try:
        body = json.dumps({"content": text[:1900]}).encode("utf-8")
        req = urllib.request.Request(
            webhook,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json", "User-Agent": "crownauth-notify"},
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            r.read()
        return True, "ok"
    except Exception as e:
        return False, str(e)[:120]


def test_ping() -> tuple[bool, str]:
    return send(
        f"WhiteCrown test · {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
        force=True,
        kind="test",
    )


# back-compat stubs (old panel/ops code)
def telegram_config(s: Optional[dict] = None) -> tuple[str, str]:
    return "", ""
