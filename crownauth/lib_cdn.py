"""Publish panel library binaries to the latest GitHub Release."""
from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
import hashlib
import re
from pathlib import Path
from typing import Any

DEFAULT_REPO = "WesleighKanee/crownauth-live"
DEFAULT_RELEASE_TAG = "library-cdn-v1"
_CONTENT_NAME = re.compile(r"^experience-(?:login|library)-[0-9a-f]{16}-[1-9][0-9]*\.(?:jpg|gif)$")


def _require_content_name(name: str) -> str:
    if not isinstance(name, str) or not _CONTENT_NAME.fullmatch(name):
        raise ValueError("invalid immutable name")
    return name


def content_address(data: bytes, *, slot: str, edge: int, fmt: str) -> tuple[str, str]:
    """Return immutable CDN name and full digest for exact bytes."""
    digest = hashlib.sha256(bytes(data)).hexdigest()
    safe_slot = str(slot).lower()
    safe_fmt = str(fmt).lower()
    if safe_slot not in ("login", "library") or safe_fmt not in ("jpg", "gif"):
        raise ValueError("invalid content-addressed asset")
    if isinstance(edge, bool) or not isinstance(edge, int) or edge <= 0:
        raise ValueError("invalid content-addressed asset")
    return f"experience-{safe_slot}-{digest[:16]}-{edge}.{safe_fmt}", digest


class LocalContentCDN:
    """Small immutable CDN adapter used by staging/tests and local installs."""
    def __init__(self, root: str | os.PathLike[str]):
        self.root = Path(root); self.root.mkdir(parents=True, exist_ok=True)

    def put(self, name: str, data: bytes) -> str:
        if not name or Path(name).name != name or name.startswith("."):
            raise ValueError("invalid immutable name")
        path = self.root / name
        payload = bytes(data)
        if path.exists():
            if path.read_bytes() != payload: raise ValueError("immutable object collision")
        else:
            tmp = path.with_suffix(path.suffix + ".part")
            tmp.write_bytes(payload)
            tmp.replace(path)
        return name

    def put_many(self, objects: Any) -> list[str]:
        """Stage multiple immutable objects with best-effort compensation."""
        objects = list(objects or ())
        created: list[str] = []
        try:
            for name, payload in objects or ():
                existed = False
                try:
                    existed = self.get(name) == bytes(payload)
                except Exception:
                    pass
                self.put(name, payload)
                if not existed:
                    created.append(name)
            return [str(name) for name, _ in objects or ()]
        except Exception:
            self.discard_many(created)
            raise

    def get(self, name: str) -> bytes:
        return (self.root / Path(name).name).read_bytes()

    def exists(self, name: str) -> bool:
        if not name or Path(name).name != name:
            raise ValueError("invalid immutable name")
        return (self.root / name).is_file()

    def public_url(self, name: str) -> str:
        _require_content_name(name)
        # Local URLs are intentionally only valid for staging/dev.  They are
        # not emitted by production manifests.
        return "/v2/experience/assets/" + urllib.parse.quote(name, safe=".-_")

    def remove(self, name: str) -> bool:
        # Immutable objects are never removed as part of a live swap.
        return False

    def discard(self, name: str) -> bool:
        """Delete an unreferenced object during a failed staged transaction."""
        if not name or Path(name).name != name:
            return False
        path = self.root / name
        try:
            path.unlink()
            return True
        except FileNotFoundError:
            return False

    def discard_many(self, names: Any) -> int:
        removed = 0
        for name in names or ():
            try:
                removed += int(bool(self.discard(name)))
            except Exception:
                continue
        return removed


class GitHubContentCDN:
    """Production immutable object adapter.

    LocalContentCDN is intentionally explicit staging-only storage; production
    callers must select this adapter (or another object-store implementation)
    rather than silently writing to an ephemeral container filesystem.
    """
    def __init__(self) -> None:
        # Names in this adapter are immutable.  This set is deliberately
        # process-local and is only used to compensate objects uploaded by
        # this adapter instance; an existing release asset is never deleted
        # as compensation for a later failure.
        self._created: set[str] = set()

    def put(self, name: str, data: bytes) -> str:
        result = publish(name, bytes(data))
        if isinstance(result, dict) and result.get("created"):
            self._created.add(name)
        return name

    def put_many(self, objects: Any) -> list[str]:
        objects = list(objects or ())
        created: list[str] = []
        try:
            for name, payload in objects or ():
                was_created = name in self._created
                self.put(name, payload)
                if not was_created and name in self._created:
                    created.append(name)
            return [str(name) for name, _ in objects or ()]
        except Exception:
            self.discard_many(created)
            raise

    def exists(self, name: str) -> bool:
        _require_content_name(name)
        return _asset_by_name(_library_release(), name) is not None

    def public_url(self, name: str) -> str:
        _require_content_name(name)
        return f"https://github.com/{repo_name()}/releases/download/{urllib.parse.quote(release_tag())}/{urllib.parse.quote(name)}"

    def discard(self, name: str) -> bool:
        # This is used only for objects staged by a failed transaction.  The
        # caller tracks pre-existing objects separately and never asks us to
        # remove those immutable live objects.
        if name not in self._created:
            return False
        try:
            result = remove(name)
        finally:
            self._created.discard(name)
        return result

    def discard_many(self, names: Any) -> int:
        removed = 0
        for name in names or ():
            try:
                removed += int(bool(self.discard(name)))
            except Exception:
                continue
        return removed


def experience_cdn(*, staging: bool = False) -> Any:
    """Select a CDN with an explicit environment boundary."""
    root = os.environ.get("EXPERIENCE_CDN_DIR")
    env = str(os.environ.get("APP_ENV") or os.environ.get("ENVIRONMENT") or "").lower()
    if staging or env in {"test", "staging", "development"}:
        if not root:
            raise RuntimeError("EXPERIENCE_CDN_DIR is required for staging CDN")
        return LocalContentCDN(root)
    if not configured():
        raise RuntimeError("production experience CDN is not configured")
    return GitHubContentCDN()


def publish_immutable(cdn: Any, data: bytes, *, slot: str, edge: int, fmt: str) -> dict[str, Any]:
    name, digest = content_address(data, slot=slot, edge=edge, fmt=fmt)
    put = getattr(cdn, "put", None)
    if not callable(put): raise TypeError("cdn adapter must implement put")
    put(name, bytes(data))
    public = getattr(cdn, "public_url", None)
    if not callable(public):
        raise RuntimeError("CDN adapter cannot provide a public asset URL")
    url = str(public(name) or "")
    if not (url.startswith("https://") or url.startswith("/v2/experience/assets/")):
        raise RuntimeError("CDN returned a non-public asset URL")
    return {"name": name, "sha256": digest, "bytes": len(data), "url": url}


def _token() -> str:
    return (os.environ.get("LIB_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN") or "").strip()


def repo_name() -> str:
    return (os.environ.get("LIB_GITHUB_REPO") or DEFAULT_REPO).strip()


def release_tag() -> str:
    return (os.environ.get("LIB_GITHUB_RELEASE_TAG") or DEFAULT_RELEASE_TAG).strip()


def configured() -> bool:
    return bool(_token() and repo_name())


def experience_asset_url(name: str) -> str:
    """Return the URL clients can actually fetch for an experience object.

    Production never points at the panel's ephemeral filesystem.  A missing
    public CDN configuration is an error rather than a relative URL that
    would silently produce broken manifests.
    """
    if not name or Path(name).name != name or name.startswith("."):
        raise ValueError("invalid immutable name")
    env = str(os.environ.get("APP_ENV") or os.environ.get("ENVIRONMENT") or "").lower()
    if env in {"prod", "production"}:
        base = (os.environ.get("EXPERIENCE_CDN_PUBLIC_BASE_URL") or "").strip().rstrip("/")
        if base:
            if not base.startswith("https://"):
                raise RuntimeError("production experience CDN must use HTTPS")
            return base + "/" + urllib.parse.quote(name, safe=".-_")
        if not configured():
            raise RuntimeError("production experience CDN is not configured")
        return f"https://github.com/{repo_name()}/releases/download/{urllib.parse.quote(release_tag())}/{urllib.parse.quote(name)}"
    return "/v2/experience/assets/" + urllib.parse.quote(name, safe=".-_")


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
    """Publish one immutable asset.

    Release assets are content addressed and therefore must never be replaced
    in place.  A retry of the exact content-addressed object is idempotent;
    every other same-name collision is rejected before an upload starts.
    """
    if not configured():
        raise RuntimeError("GitHub library publishing is not configured")
    if not name or "/" in name or "\\" in name or name.startswith("."):
        raise ValueError("invalid asset name")
    if not payload:
        raise ValueError("empty asset")

    release = _library_release()
    upload_base = str(release.get("upload_url") or "").split("{", 1)[0]
    if not upload_base:
        raise RuntimeError("latest GitHub Release has no upload URL")

    old = _asset_by_name(release, name)
    digest = hashlib.sha256(payload).hexdigest()
    # Experience objects use names generated by content_address().  Matching
    # the embedded prefix proves a retry is for the same bytes while still
    # avoiding a download of the existing release asset.
    m = re.match(r"^experience-(?:login|library)-([0-9a-f]{16})-[1-9][0-9]*\.(?:jpg|gif)$", name)
    if m and not digest.startswith(m.group(1)):
        raise ValueError("asset name does not match content")
    if old:
        if m and digest.startswith(m.group(1)):
            return {
                "ok": True, "created": False, "idempotent": True,
                "repo": repo_name(), "release": release.get("tag_name") or "latest",
                "asset_id": int(old.get("id") or 0),
                "size": int(old.get("size") or len(payload)),
                "url": f"https://github.com/{repo_name()}/releases/download/{urllib.parse.quote(release_tag())}/{urllib.parse.quote(name)}",
            }
        raise ValueError("immutable release asset already exists")
    stamp = f"{int(time.time())}-{os.getpid()}"
    temp_name = f".{name}.uploading-{stamp}"
    upload_url = upload_base + "?" + urllib.parse.urlencode({"name": temp_name})
    _, raw = _request(upload_url, method="POST", data=payload, content_type="application/octet-stream")
    fresh = json.loads(raw.decode("utf-8"))
    fresh_id = int(fresh.get("id") or 0)
    if not fresh_id:
        raise RuntimeError("GitHub did not return a release asset id")

    try:
        final = _rename_asset(fresh_id, name)
    except Exception:
        # Only the newly uploaded object is eligible for compensation.  Never
        # look up/delete by final name: a concurrent publisher may have made
        # that name live after our upload began.
        try:
            _delete_asset(fresh_id)
        except Exception:
            pass
        raise

    return {
        "ok": True, "created": True,
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


def cover_url(card: str, fmt: str = "jpg") -> str:
    """Public GitHub CDN URL for a cover asset: <CARD>.cover.<jpg|gif>"""
    return (
        f"https://github.com/{repo_name()}/releases/download/"
        f"{urllib.parse.quote(release_tag())}/{urllib.parse.quote(card + '.cover.' + (fmt or 'jpg'))}"
    )
