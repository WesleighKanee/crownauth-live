"""
Free owner alerts: Telegram Bot API + Discord webhook.

Telegram is completely free (BotFather). No paid API.
Discord is free (channel webhook).
"""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

_last_send: dict[str, float] = {}
_MIN_GAP = 2.0  # avoid Telegram flood on bulk mint


def _settings() -> dict[str, Any]:
    try:
        from crownauth import db

        return db.all_settings()
    except Exception:
        return {}


def _env(name: str) -> str:
    import os

    return (os.environ.get(name) or "").strip()


def telegram_config(s: Optional[dict] = None) -> tuple[str, str]:
    s = s or _settings()
    token = (s.get("telegram_bot_token") or _env("TELEGRAM_BOT_TOKEN") or "").strip()
    chat = str(s.get("telegram_chat_id") or _env("TELEGRAM_CHAT_ID") or "").strip()
    return token, chat


def discord_webhook(s: Optional[dict] = None) -> str:
    s = s or _settings()
    return (s.get("webhook_url") or s.get("discord_webhook") or _env("DISCORD_WEBHOOK") or "").strip()


def send(text: str, *, force: bool = False, kind: str = "info") -> tuple[bool, str]:
    """Send to Telegram and/or Discord if configured. Returns (any_ok, detail)."""
    s = _settings()
    if not force and not s.get("notify_enabled", True):
        return False, "notifications off"
    text = (text or "").strip()
    if not text:
        return False, "empty"
    if len(text) > 3500:
        text = text[:3490] + "…"

    now = time.time()
    key = kind
    if not force and now - _last_send.get(key, 0) < _MIN_GAP:
        return True, "rate-limited (ok)"
    _last_send[key] = now

    results: list[str] = []
    any_ok = False

    tok, chat = telegram_config(s)
    if tok and chat:
        ok, msg = _telegram(tok, chat, text)
        any_ok = any_ok or ok
        results.append(f"tg:{msg}")
    else:
        results.append("tg:not configured")

    wh = discord_webhook(s)
    if wh:
        ok, msg = _discord(wh, text)
        any_ok = any_ok or ok
        results.append(f"dc:{msg}")
    else:
        results.append("dc:not configured")

    return any_ok, "; ".join(results)


def send_async(text: str, *, force: bool = False, kind: str = "info") -> None:
    def _run() -> None:
        try:
            send(text, force=force, kind=kind)
        except Exception:
            pass

    threading.Thread(target=_run, daemon=True).start()


def notify_if(flag: str, text: str, *, kind: str = "info") -> None:
    s = _settings()
    if not s.get("notify_enabled", True):
        return
    if flag and not s.get(flag, True):
        return
    send_async(text, kind=kind)


def _telegram(token: str, chat_id: str, text: str) -> tuple[bool, str]:
    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        body = json.dumps(
            {
                "chat_id": chat_id,
                "text": text,
                "disable_web_page_preview": True,
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json", "User-Agent": "crownauth-notify"},
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode())
        if data.get("ok"):
            return True, "ok"
        return False, str(data.get("description") or data)[:120]
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode()[:160]
        except Exception:
            detail = str(e)
        return False, f"http {e.code} {detail}"
    except Exception as e:
        return False, str(e)[:120]


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
        "WhiteCrown · test alert\n"
        f"Time: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n"
        "If you see this, free Telegram/Discord notify works.",
        force=True,
        kind="test",
    )
