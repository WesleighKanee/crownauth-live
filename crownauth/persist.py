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
import hashlib
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


def _gh_headers(token: str, accept: str = "application/vnd.github+json") -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": accept,
        "User-Agent": "crownauth-backup",
    }


def _github_get_backup_text(token: str, repo: str) -> str:
    """Return the inner crownauth-backup.tar.gz.b64 text.

    Contents JSON drops `content` once the stored object is > ~1 MB.
    A snapshot that includes libs is always that large — use download_url / raw.
    """
    api = f"https://api.github.com/repos/{repo}/contents/crownauth-backup.tar.gz.b64"
    req = urllib.request.Request(api, headers=_gh_headers(token))
    with urllib.request.urlopen(req, timeout=60) as r:
        meta = json.loads(r.read().decode())
    content_b64 = (meta.get("content") or "").replace("\n", "")
    if content_b64:
        return base64.b64decode(content_b64).decode("ascii")
    dl = (meta.get("download_url") or "").strip()
    if dl:
        req2 = urllib.request.Request(
            dl,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/octet-stream",
                "User-Agent": "crownauth-backup",
            },
        )
        with urllib.request.urlopen(req2, timeout=180) as r2:
            return r2.read().decode("ascii")
    req3 = urllib.request.Request(api, headers=_gh_headers(token, "application/vnd.github.raw"))
    with urllib.request.urlopen(req3, timeout=180) as r3:
        return r3.read().decode("ascii")


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


# GitHub contents API hard-caps a file at 100 MB. We store inner-b64 text,
# then the API wraps that again (~4/3). Keep the stored blob under this.
_GH_BLOB_BUDGET = 70 * 1024 * 1024
# Uncompressed lib payload cap (already-compressed .so barely gzips).
_LIB_BUDGET = 50 * 1024 * 1024
_DB_NAMES = frozenset({"crownauth.db", "crownauth.db-wal", "crownauth.db-shm"})


def _lib_dir() -> Path:
    try:
        from crownauth import db as _db

        return _db.lib_data_dir()
    except Exception:
        d = _data_root() / "libs"
        d.mkdir(parents=True, exist_ok=True)
        return d


def _safe_arcname(name: str) -> Optional[str]:
    name = (name or "").replace("\\", "/").lstrip("/")
    while name.startswith("./"):
        name = name[2:]
    parts = [p for p in name.split("/") if p and p != "."]
    if not parts or any(p == ".." for p in parts):
        return None
    return "/".join(parts)


def _tar_b64(include_libs: bool = False) -> str:
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
        # uploaded mod binaries — without these a dyno recycle looks like "sync is broken"
        # Always include libs when possible. Sorted smallest-first so one huge .so
        # does not starve every smaller mod (SHADOW ~25 MB still fits under budget).
        if include_libs:
            ld = _lib_dir()
            used = 0
            if ld.exists():
                files = [
                    f
                    for f in ld.iterdir()
                    if f.is_file() and f.name and f.name not in {".", ".."}
                ]
                files.sort(key=lambda p: (p.stat().st_size, p.name.lower()))
                for f in files:
                    fname = Path(f.name).name
                    sz = f.stat().st_size
                    if used + sz > _LIB_BUDGET:
                        # skip this one; keep packing remaining smaller files
                        continue
                    tar.add(f, arcname=f"libs/{fname}")
                    used += sz
    return base64.b64encode(buf.getvalue()).decode("ascii")


def _write_under(dest: Path, root: Path, src) -> bool:
    """Write extractfile() bytes only if dest resolves inside root."""
    root_res = root.resolve()
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        dest.parent.resolve().relative_to(root_res)
        dest_res = dest.parent.resolve() / dest.name
        dest_res.relative_to(root_res)
    except (ValueError, OSError):
        return False
    if dest_res == root_res:
        return False
    dest_res.write_bytes(src.read())
    return True


def _apply_tar_b64(b64: str, libs_only: bool = False) -> dict:
    """Extract snapshot into DATA (db/secrets) and DATA/libs (mod binaries).

    Never switches dest_root under tar.extract() — that was a slip surface
    and could drop libs next to DATA instead of inside DATA/libs.
    Returns counts of files written. Refuses empty / tiny blobs.
    """
    import io
    import tarfile

    if not (b64 or "").strip() or len(b64) < 80:
        raise ValueError("empty backup blob")
    raw = base64.b64decode(b64.encode("ascii"))
    if len(raw) < 32:
        raise ValueError("empty backup blob")
    root = _data_root()
    root.mkdir(parents=True, exist_ok=True)
    (root / "secrets").mkdir(parents=True, exist_ok=True)
    lib_dir = _lib_dir()
    lib_dir.mkdir(parents=True, exist_ok=True)
    n_db = n_sec = n_libs = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
        for m in tar.getmembers():
            if not m.isfile():
                continue
            name = _safe_arcname(m.name)
            if not name:
                continue
            src = tar.extractfile(m)
            if src is None:
                continue
            base = name.split("/", 1)[0]
            if base == "libs":
                fname = Path(name).name
                if not fname or fname in {".", ".."}:
                    continue
                if _write_under(lib_dir / fname, lib_dir, src):
                    n_libs += 1
                continue
            if libs_only:
                continue
            if name in _DB_NAMES:
                if _write_under(root / name, root, src):
                    n_db += 1
                continue
            if base == "secrets":
                fname = Path(name).name
                if not fname or fname in {".", ".."}:
                    continue
                if _write_under(root / "secrets" / fname, root / "secrets", src):
                    n_sec += 1
    if libs_only:
        if n_libs == 0:
            raise ValueError("libs_only extract wrote 0 files")
    elif (n_db + n_sec + n_libs) == 0:
        raise ValueError("backup extract wrote 0 files")
    return {"db": n_db, "secrets": n_sec, "libs": n_libs}


def _lib_pack_stats() -> dict:
    """How many lib files exist on disk and total bytes (for backup diagnostics)."""
    ld = _lib_dir()
    n = 0
    total = 0
    names: list[str] = []
    if ld.exists():
        for f in ld.iterdir():
            if f.is_file() and f.name not in {".", ".."}:
                n += 1
                total += f.stat().st_size
                names.append(f.name)
    return {"n": n, "bytes": total, "names": sorted(names)}


def backup_now(force: bool = False, notify: bool = True) -> tuple[bool, str]:
    """Push data snapshot to private GitHub repo (DB + secrets + lib binaries)."""
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
    # Library binaries live in GitHub Release assets. Render's local copies are
    # disposable cache and intentionally do not gate control-plane backups.
    now = time.time()
    with _lock:
        if not force and (now - _last_backup) < _MIN_BACKUP_GAP:
            return True, "skipped (rate limit)"
        try:
            stats = _lib_pack_stats()
            include_libs = False
            blob = _tar_b64(False)
            api = f"https://api.github.com/repos/{repo}/contents/crownauth-backup.tar.gz.b64"
            headers = {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "crownauth-backup",
            }

            def _put(file_text: str) -> None:
                payload = {
                    "message": f"auto backup {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
                    "content": base64.b64encode(file_text.encode("ascii")).decode("ascii"),
                    "branch": "main",
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
                body = json.dumps(payload).encode()
                # large lib snapshots need a longer PUT timeout
                req2 = urllib.request.Request(
                    api, data=body, method="PUT", headers={**headers, "Content-Type": "application/json"}
                )
                with urllib.request.urlopen(req2, timeout=180) as r2:
                    r2.read()

            try:
                _put(blob)
            except urllib.error.HTTPError as e:
                # 413/422: contents API / file too large. Retry db+secrets only.
                if include_libs and e.code in (413, 422):
                    include_libs = False
                    blob = _tar_b64(False)
                    _put(blob)
                else:
                    raise
            _last_backup = time.time()
            if include_libs:
                msg = "backup ok (libs=%d, ~%d MB)" % (
                    int(stats.get("n") or 0),
                    int((stats.get("bytes") or 0) / (1024 * 1024)),
                )
            else:
                msg = "backup ok (library binaries on GitHub Releases CDN)"
                if notify:
                    try:
                        from crownauth import notify as _n

                        _n.notify_if(
                            "notify_on_backup_fail",
                            f"⚠️ WhiteCrown {msg}\nRepo: {repo}\nDisk libs: {stats.get('names')}",
                            kind="backup_fail",
                        )
                    except Exception:
                        pass
            if notify and force:
                try:
                    from crownauth import notify as _n

                    _n.notify_if(
                        "notify_on_backup",
                        f"✅ WhiteCrown {msg}\nRepo: {repo}\nUTC: {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())}",
                        kind="backup_ok",
                    )
                except Exception:
                    pass
            return True, msg
        except Exception as e:
            err = f"backup failed: {e}"
            if notify:
                try:
                    from crownauth import notify as _n

                    _n.notify_if("notify_on_backup_fail", f"⚠️ WhiteCrown {err}", kind="backup_fail")
                except Exception:
                    pass
            return False, err


def _libs_missing() -> bool:
    """True when the DB lists uploaded mods but the binary files are gone (dyno wipe)."""
    try:
        from crownauth import db as _db

        rows = _db.lib_list()
        if not rows:
            return False
        for r in rows:
            fp = _db.lib_data_path(r.get("name") or "")
            if not fp.is_file() or fp.stat().st_size <= 0:
                return True
        return False
    except Exception:
        return False


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
    libs_only = False
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
                if _libs_missing():
                    # DB is healthy — pull binaries only, do not roll back newer keys
                    need = True
                    libs_only = True
                else:
                    return False, "local data present"
    try:
        file_text = _github_get_backup_text(token, repo)
        counts = _apply_tar_b64(file_text, libs_only=libs_only)
        n_libs = int(counts.get("libs") or 0)
        if libs_only:
            return True, f"restored {n_libs} libs from GitHub backup"
        return True, f"restored from GitHub backup (db={counts.get('db', 0)} libs={n_libs})"
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False, "no backup yet"
        return False, f"restore failed: {e.code}"
    except Exception as e:
        return False, f"restore failed: {e}"


def heal_missing_libs() -> tuple[bool, str]:
    """After init_db: DB has lib rows but DATA/libs files are gone → GitHub libs_only.

    Call this on boot AFTER db.init_db() and BEFORE the HTTP server accepts traffic.
    restore_if_needed() may have already pulled a full snapshot; this is the
    second pass for the wipe case where the DB survived and binaries did not.
    """
    if not _libs_missing():
        return False, "libs present"
    token = _env("GITHUB_TOKEN")
    repo = _env("GITHUB_BACKUP_REPO")
    if not token or not repo:
        return False, "no backup config"
    try:
        file_text = _github_get_backup_text(token, repo)
        counts = _apply_tar_b64(file_text, libs_only=True)
        n = int(counts.get("libs") or 0)
        if _libs_missing():
            return False, f"heal extracted {n} lib files but some still missing"
        return True, f"healed {n} lib files from GitHub backup"
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False, "no backup yet"
        return False, f"heal failed: {e.code}"
    except Exception as e:
        return False, f"heal failed: {e}"


maybe_restore = restore_if_needed


def schedule_backup(force: bool = False) -> None:
    """Fire-and-forget backup after mutations.

    force=True: bypass 20s rate limit and empty-license / missing-lib guards.
    Required after lib delete/toggle so free-tier recycle cannot resurrect a
    removed or disabled mod from a stale GitHub snapshot.
    """

    def _run() -> None:
        try:
            backup_now(force=force, notify=True)
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
        file_text = _github_get_backup_text(token, repo)
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
            "sha": hashlib.sha256(raw).hexdigest()[:12],
        }
    except Exception as e:
        try:
            from crownauth import notify as _n

            _n.notify_if("notify_on_backup_fail", f"⚠️ Restore drill failed: {e}", kind="drill_fail")
        except Exception:
            pass
        return {"ok": False, "step": "verify", "message": str(e)}
