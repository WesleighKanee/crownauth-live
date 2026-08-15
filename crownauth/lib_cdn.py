"""Publish panel library binaries to the latest GitHub Release."""
from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
from typing import Any

DEFAULT_REPO = "WesleighKanee/crownauth-live"
DEFAULT_RELEASE_TAG = "library-cdn-v1"


def _token() -> str:
    return (os.environ.get("LIB_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN") or "").strip()


def repo_name() -> str:
    return (os.environ.get("LIB_GITHUB_REPO") or DEFAULT_REPO).strip()


def release_tag() -> str:
    return (os.environ.get("LIB_GITHUB_RELEASE_TAG") or DEFAULT_RELEASE_TAG).strip()


def configured() -> bool:
    return bool(_token() and repo_name())


def _request(url: str, *, method: str = "GET", data: bytes | None = None,
             content_type: str = "application/vnd.github+json") -> tuple[int, bytes]:
    token = _token()
    if not token:
        raise RuntimeError("LIB_GITHUB_TOKEN or GITHUB_TOKEN is not configured")
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "crownauth-library-cdn",
    }
    if data is not None:
        headers["Content-Type"] = content_type
        headers["Content-Length"] = str(len(data))
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=180) as response:
        return int(response.status), response.read()


def _json(url: str, *, method: str = "GET", body: dict[str, Any] | None = None) -> dict[str, Any]:
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
    _, raw = _request(url, method=method, data=data)
    return json.loads(raw.decode("utf-8")) if raw else {}


def _library_release() -> dict[str, Any]:
    tag = urllib.parse.quote(release_tag(), safe="")
    return _json(f"https://api.github.com/repos/{repo_name()}/releases/tags/{tag}")


def _asset_by_name(release: dict[str, Any], name: str) -> dict[str, Any] | None:
    for asset in release.get("assets") or []:
        if str(asset.get("name") or "") == name:
            return asset
    return None


def _rename_asset(asset_id: int, name: str) -> dict[str, Any]:
    return _json(
        f"https://api.github.com/repos/{repo_name()}/releases/assets/{int(asset_id)}",
        method="PATCH",
        body={"name": name},
    )


def _delete_asset(asset_id: int) -> None:
    _request(
        f"https://api.github.com/repos/{repo_name()}/releases/assets/{int(asset_id)}",
        method="DELETE",
    )


def publish(name: str, payload: bytes) -> dict[str, Any]:
    """Replace one asset with a near-atomic upload/rename/rollback swap."""
    if not configured():
        raise RuntimeError("GitHub library publishing is not configured")
    if not name or "/" in name or "\\" in name:
        raise ValueError("invalid asset name")
    if not payload:
        raise ValueError("empty asset")

    release = _library_release()
    upload_base = str(release.get("upload_url") or "").split("{", 1)[0]
    if not upload_base:
        raise RuntimeError("latest GitHub Release has no upload URL")

    old = _asset_by_name(release, name)
    stamp = f"{int(time.time())}-{os.getpid()}"
    temp_name = f".{name}.uploading-{stamp}"
    upload_url = upload_base + "?" + urllib.parse.urlencode({"name": temp_name})
    _, raw = _request(upload_url, method="POST", data=payload, content_type="application/octet-stream")
    fresh = json.loads(raw.decode("utf-8"))
    fresh_id = int(fresh.get("id") or 0)
    if not fresh_id:
        raise RuntimeError("GitHub did not return a release asset id")

    backup_name = ""
    try:
        if old:
            backup_name = f".{name}.backup-{stamp}"
            _rename_asset(int(old["id"]), backup_name)
        final = _rename_asset(fresh_id, name)
        if old:
            _delete_asset(int(old["id"]))
    except Exception:
        try:
            _delete_asset(fresh_id)
        except Exception:
            pass
        if old and backup_name:
            try:
                _rename_asset(int(old["id"]), name)
            except Exception:
                pass
        raise

    return {
        "ok": True,
        "repo": repo_name(),
        "release": release.get("tag_name") or "latest",
        "asset_id": int(final.get("id") or fresh_id),
        "size": int(final.get("size") or len(payload)),
        "url": f"https://github.com/{repo_name()}/releases/download/{urllib.parse.quote(release_tag())}/{urllib.parse.quote(name)}",
    }


def remove(name: str) -> bool:
    if not configured():
        return False
    release = _library_release()
    asset = _asset_by_name(release, name)
    if not asset:
        return False
    _delete_asset(int(asset["id"]))
    return True
