"""
Persist free-tier state across Render redeploys / disk wipes.

1) OWNER_PASSWORD → Render env (survives redeploy when env is set)
2) Full data dir (DB + secrets) → private GitHub repo (optional but enabled when token set)

Env:
  RENDER_API_KEY      - Render API key
  RENDER_SERVICE_ID   - e.g. srv-xxxxx
  GITHUB_TOKEN        - fine-grained or classic with repo contents:write
  GITHUB_BACKUP_REPO  - owner/name e.g. WesleighKanee/crownauth-live-data
  OWNER_PASSWORD      - applied on boot (kept in sync when password changes)
"""
from __future__ import annotations

import base64
import json
import os
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

_lock = threading.Lock()
_last_backup = 0.0
_MIN_BACKUP_GAP = 20.0  # seconds


def _env(name: str) -> str:
    return (os.environ.get(name) or "").strip()


def sync_owner_password_to_render(password: str) -> tuple[bool, str]:
    """Update OWNER_PASSWORD on Render so free redeploys keep the panel password."""
    api = _env("RENDER_API_KEY")
    sid = _env("RENDER_SERVICE_ID")
    if not api or not sid:
        return False, "RENDER_API_KEY / RENDER_SERVICE_ID not set"
    if len(password) < 10:
        return False, "password too short"
    try:
        # GET current env vars
        req = urllib.request.Request(
            f"https://api.render.com/v1/services/{sid}/env-vars",
            headers={"Authorization": f"Bearer {api}", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            cur = json.loads(r.read().decode())
        # Render returns list of {envVar:{key,value}} or plain list depending on version
        merged: dict[str, str] = {}
        if isinstance(cur, list):
            for item in cur:
                if isinstance(item, dict) and "envVar" in item:
                    ev = item["envVar"]
                    merged[str(ev.get("key"))] = str(ev.get("value") or "")
                elif isinstance(item, dict) and "key" in item:
                    merged[str(item["key"])] = str(item.get("value") or "")
        merged["OWNER_PASSWORD"] = password
        # keep essential keys
        for k, default in (
            ("PORT", "8787"),
            ("CROWNAUTH_DATA", "/tmp/crowndata"),
            ("PUBLIC_HOST", "crownauth-live.onrender.com"),
            ("PYTHONUNBUFFERED", "1"),
        ):
            merged.setdefault(k, default)
        body = json.dumps([{"key": k, "value": v} for k, v in merged.items()]).encode()
        req2 = urllib.request.Request(
            f"https://api.render.com/v1/services/{sid}/env-vars",
            data=body,
            method="PUT",
            headers={
                "Authorization": f"Bearer {api}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(req2, timeout=30) as r2:
            r2.read()
        return True, "password synced to Render env"
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode()
        except Exception:
            detail = str(e)
        return False, f"render sync failed: {e.code} {detail}"
    except Exception as e:
        return False, f"render sync failed: {e}"


def _data_root() -> Path:
    from crownauth import db
    from crownauth import crypto_v2 as c

    # secrets live next to db data root
    return Path(db.DATA)


def _tar_b64() -> str:
    import io
    import tarfile

    root = _data_root()
    root.mkdir(parents=True, exist_ok=True)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        # db
        db_path = Path(os.environ.get("CROWNAUTH_DB") or (root / "crownauth.db"))
        if db_path.exists():
            tar.add(db_path, arcname="crownauth.db")
        # wal/shm if present
        for suffix in ("-wal", "-shm"):
            p = Path(str(db_path) + suffix)
            if p.exists():
                tar.add(p, arcname="crownauth.db" + suffix)
        # secrets
        sec = root / "secrets"
        if not sec.exists():
            from crownauth import crypto_v2 as c

            sec = Path(c.SECRETS)
        if sec.exists():
            for f in sec.iterdir():
                if f.is_file():
                    tar.add(f, arcname=f"secrets/{f.name}")
    return base64.b64encode(buf.getvalue()).decode("ascii")


def _apply_tar_b64(b64: str) -> None:
    import io
    import tarfile

    raw = base64.b64decode(b64.encode("ascii"))
    root = _data_root()
    root.mkdir(parents=True, exist_ok=True)
    sec = root / "secrets"
    sec.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
        # Safe extract — no path traversal (tar slip)
        for m in tar.getmembers():
            name = (m.name or "").replace("\\", "/")
            if name.startswith("/") or ".." in name.split("/"):
                continue
            base = name.split("/", 1)[0]
            if base not in ("crownauth.db", "crownauth.db-wal", "crownauth.db-shm", "secrets") and not name.startswith(
                "secrets/"
            ):
                # allow flat db names at root
                if not name.startswith("crownauth.db"):
                    continue
            tar.extract(m, path=root)


def backup_now(force: bool = False, notify: bool = True) -> tuple[bool, str]:
    """Push data snapshot to private GitHub repo."""
    global _last_backup
    token = _env("GITHUB_TOKEN")
    repo = _env("GITHUB_BACKUP_REPO")  # owner/name
    if not token or not repo:
        msg = "GITHUB_TOKEN / GITHUB_BACKUP_REPO not set"
        if notify:
            try:
                from crownauth import notify as _n

                _n.notify_if("notify_on_backup_fail", f"⚠️ WhiteCrown backup skipped: {msg}", kind="backup_fail")
            except Exception:
                pass
        return False, msg
    # Never overwrite a good remote backup with an empty license DB (free-tier wipe trap)
    try:
        from crownauth import db as _db

        n_lic = int(_db.stats().get("licenses_total") or 0)
        if n_lic == 0 and not force:
            return False, "refused empty backup (0 licenses) — mint keys or force=True"
    except Exception:
        pass
    now = time.time()
    with _lock:
        if not force and (now - _last_backup) < _MIN_BACKUP_GAP:
            return True, "skipped (rate limit)"
        try:
            payload = {
                "message": f"auto backup {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
                "content": _tar_b64(),
                "branch": "main",
            }
            # get existing sha if any
            api = f"https://api.github.com/repos/{repo}/contents/crownauth-backup.tar.gz.b64"
            headers = {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "crownauth-backup",
            }
            sha = None
            try:
                req = urllib.request.Request(api, headers=headers)
                with urllib.request.urlopen(req, timeout=30) as r:
                    meta = json.loads(r.read().decode())
                    sha = meta.get("sha")
            except urllib.error.HTTPError as e:
                if e.code != 404:
                    raise
            if sha:
                payload["sha"] = sha
            # GitHub contents API expects content base64 of the file bytes, not raw string of b64
            # We store the b64 text as file content → encode the text as base64 for the API
            file_text = payload["content"]
            payload["content"] = base64.b64encode(file_text.encode("ascii")).decode("ascii")
            body = json.dumps(payload).encode()
            req2 = urllib.request.Request(api, data=body, method="PUT", headers={**headers, "Content-Type": "application/json"})
            with urllib.request.urlopen(req2, timeout=60) as r2:
                r2.read()
            _last_backup = time.time()
            if notify and force:
                try:
                    from crownauth import notify as _n

                    _n.notify_if(
                        "notify_on_backup",
                        f"✅ WhiteCrown backup ok\nRepo: {repo}\nUTC: {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())}",
                        kind="backup_ok",
                    )
                except Exception:
                    pass
            return True, "backup ok"
        except Exception as e:
            err = f"backup failed: {e}"
            if notify:
                try:
                    from crownauth import notify as _n

                    _n.notify_if("notify_on_backup_fail", f"⚠️ WhiteCrown {err}", kind="backup_fail")
                except Exception:
                    pass
            return False, err


def restore_if_needed() -> tuple[bool, str]:
    """On boot: if local DB missing/empty-ish, restore from GitHub backup."""
    token = _env("GITHUB_TOKEN")
    repo = _env("GITHUB_BACKUP_REPO")
    if not token or not repo:
        return False, "no backup config"
    from crownauth import db

    db_path = Path(db.DB_PATH)
    # restore if no db or tiny
    need = (not db_path.exists()) or db_path.stat().st_size < 2000
    if not need:
        from crownauth import crypto_v2 as c

        if not c.PRIV_PATH.exists():
            need = True
        else:
            # free-tier trap: empty schema DB after wipe (plans exist, 0 licenses)
            try:
                db.init_db()
                n = int(db.stats().get("licenses_total") or 0)
                if n == 0:
                    need = True  # pull last backup (may have keys)
            except Exception:
                pass
            if not need:
                return False, "local data present"
    try:
        api = f"https://api.github.com/repos/{repo}/contents/crownauth-backup.tar.gz.b64"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "crownauth-backup",
        }
        req = urllib.request.Request(api, headers=headers)
        with urllib.request.urlopen(req, timeout=60) as r:
            meta = json.loads(r.read().decode())
        content_b64 = meta.get("content", "").replace("\n", "")
        file_text = base64.b64decode(content_b64).decode("ascii")
        _apply_tar_b64(file_text)
        return True, "restored from GitHub backup"
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False, "no backup yet"
        return False, f"restore failed: {e.code}"
    except Exception as e:
        return False, f"restore failed: {e}"


def schedule_backup() -> None:
    """Fire-and-forget backup after mutations."""

    def _run() -> None:
        try:
            backup_now(force=False, notify=True)
        except Exception:
            pass

    threading.Thread(target=_run, daemon=True).start()


def restore_drill() -> dict:
    """
    Soft restore drill (does NOT wipe production DB):
    1) Force backup now
    2) Verify GitHub object exists and decodes
    Returns status dict for panel / scripts.
    """
    ok_b, msg_b = backup_now(force=True, notify=True)
    if not ok_b:
        return {"ok": False, "step": "backup", "message": msg_b}

    token = _env("GITHUB_TOKEN")
    repo = _env("GITHUB_BACKUP_REPO")
    try:
        api = f"https://api.github.com/repos/{repo}/contents/crownauth-backup.tar.gz.b64"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "crownauth-backup",
        }
        req = urllib.request.Request(api, headers=headers)
        with urllib.request.urlopen(req, timeout=60) as r:
            meta = json.loads(r.read().decode())
        content_b64 = meta.get("content", "").replace("\n", "")
        file_text = base64.b64decode(content_b64).decode("ascii")
        raw = base64.b64decode(file_text.encode("ascii"))
        size = len(raw)
        if size < 100:
            return {"ok": False, "step": "verify", "message": "backup blob too small"}
        try:
            from crownauth import notify as _n

            _n.notify_if(
                "notify_on_backup",
                f"🧪 Restore drill OK\nRepo: {repo}\nBlob bytes: {size}\nBackup step: {msg_b}",
                kind="drill",
            )
        except Exception:
            pass
        return {
            "ok": True,
            "step": "done",
            "message": f"backup + verify ok ({size} bytes compressed)",
            "backup": msg_b,
            "bytes": size,
            "sha": (meta.get("sha") or "")[:12],
        }
    except Exception as e:
        try:
            from crownauth import notify as _n

            _n.notify_if("notify_on_backup_fail", f"⚠️ Restore drill failed: {e}", kind="drill_fail")
        except Exception:
            pass
        return {"ok": False, "step": "verify", "message": str(e)}
