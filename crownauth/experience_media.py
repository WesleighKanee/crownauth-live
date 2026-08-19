"""Bounded owner artwork validation and deterministic client renditions."""
from __future__ import annotations

import io
import math
import time
import struct
import threading
import zlib
from dataclasses import dataclass
from typing import Any

from PIL import Image, ImageFile, ImageOps, UnidentifiedImageError

Image.MAX_IMAGE_PIXELS = 67_108_864
ImageFile.LOAD_TRUNCATED_IMAGES = False

MAX_STATIC_BYTES = 40 * 1024 * 1024
MAX_GIF_BYTES = 60 * 1024 * 1024
MAX_EDGE = 8192
MAX_PIXELS = 67_108_864
MAX_FRAMES = 180
MAX_GIF_DURATION_MS = 20_000
MAX_GIF_OUTPUT_BYTES = 15 * 1024 * 1024
# Aggregate budget is intentionally lower than the per-frame limit because the
# encoder needs bounded retained RGBA frames for the normalized output.
MAX_GIF_TOTAL_PIXELS = 33_554_432
MAX_DECODE_SECONDS = 8.0
MAX_CONCURRENT_DECODES = 2
_DECODE_SLOTS = threading.BoundedSemaphore(MAX_CONCURRENT_DECODES)


class MediaError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message); self.code, self.message = code, message


@dataclass(frozen=True)
class Rendition:
    data: bytes
    sha256: str
    width: int
    height: int
    format: str


@dataclass(frozen=True)
class ValidatedMedia:
    source_format: str
    width: int
    height: int
    frame_count: int
    duration_ms: int
    renditions: tuple[Rendition, ...]


def _png_exact_end(data: bytes) -> bool:
    """Parse PNG chunks and require IEND to be the final byte."""
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return False
    pos = 8; seen_ihdr = False
    try:
        while pos + 12 <= len(data):
            length = struct.unpack(">I", data[pos:pos + 4])[0]
            typ = data[pos + 4:pos + 8]
            end = pos + 12 + length
            if end > len(data) or len(typ) != 4 or not all((65 <= b <= 90) or (97 <= b <= 122) for b in typ):
                return False
            payload = data[pos + 8:pos + 8 + length]
            crc = struct.unpack(">I", data[pos + 8 + length:end])[0]
            if (zlib.crc32(typ + payload) & 0xffffffff) != crc:
                return False
            if typ == b"IHDR":
                if seen_ihdr or length != 13: return False
                seen_ihdr = True
            if typ == b"IEND":
                return seen_ihdr and length == 0 and end == len(data)
            pos = end
        return False
    except (IndexError, struct.error, zlib.error):
        return False


def _gif_exact_end(data: bytes) -> bool:
    """Walk GIF blocks so a trailing/polyglot payload cannot be hidden after ;."""
    if len(data) < 13 or data[:6] not in (b"GIF87a", b"GIF89a"):
        return False
    pos = 6
    try:
        width, height, packed = struct.unpack_from("<HHB", data, pos); pos += 7
        if width <= 0 or height <= 0: return False
        if packed & 0x80:
            pos += 3 * (1 << ((packed & 7) + 1))
        if pos > len(data): return False
        while pos < len(data):
            marker = data[pos]; pos += 1
            if marker == 0x3b:
                return pos == len(data)
            if marker == 0x21:
                if pos >= len(data): return False
                label = data[pos]; pos += 1
                if label == 0xf9:
                    if pos >= len(data) or data[pos] != 4: return False
                    pos += 1 + 4
                    if pos >= len(data) or data[pos] != 0: return False
                    pos += 1
                elif label == 0x01:
                    if pos >= len(data) or data[pos] != 12: return False
                    pos += 13
                    while True:
                        if pos >= len(data): return False
                        n = data[pos]; pos += 1
                        if n == 0: break
                        pos += n
                else:
                    while True:
                        if pos >= len(data): return False
                        n = data[pos]; pos += 1
                        if n == 0: break
                        pos += n
                if pos > len(data): return False
            elif marker == 0x2c:
                if pos + 9 > len(data): return False
                left, top, w, h, packed = struct.unpack_from("<HHHHB", data, pos); pos += 9
                if w <= 0 or h <= 0: return False
                if packed & 0x80:
                    pos += 3 * (1 << ((packed & 7) + 1))
                if pos >= len(data): return False
                pos += 1  # LZW minimum code size
                while True:
                    if pos >= len(data): return False
                    n = data[pos]; pos += 1
                    if n == 0: break
                    pos += n
                if pos > len(data): return False
            else:
                return False
        return False
    except (IndexError, struct.error):
        return False


def _format(im: Image.Image, data: bytes) -> str:
    fmt = (im.format or "").upper()
    if fmt not in {"JPEG", "PNG", "WEBP", "GIF"}:
        raise MediaError("unsupported_format", "only JPEG, PNG, WebP and GIF are accepted")
    if fmt == "WEBP" and bool(getattr(im, "n_frames", 1) > 1):
        raise MediaError("animated_webp", "animated WebP is not supported")
    magic = data[:16]
    if fmt == "JPEG" and not magic.startswith(b"\xff\xd8"):
        raise MediaError("bad_magic", "invalid JPEG")
    if fmt == "PNG" and not magic.startswith(b"\x89PNG\r\n\x1a\n"):
        raise MediaError("bad_magic", "invalid PNG")
    if fmt == "GIF" and not magic.startswith((b"GIF87a", b"GIF89a")):
        raise MediaError("bad_magic", "invalid GIF")
    if fmt == "WEBP" and not (magic.startswith(b"RIFF") and data[8:12] == b"WEBP"):
        raise MediaError("bad_magic", "invalid WebP")
    # Reject polyglot/trailing payloads.  PIL intentionally tolerates some
    # trailing bytes, but an owner upload must be exactly one image container.
    if fmt == "PNG":
        if not _png_exact_end(data):
            raise MediaError("trailing_data", "PNG has trailing data")
    elif fmt == "GIF":
        if not _gif_exact_end(data):
            raise MediaError("trailing_data", "GIF has trailing data")
    elif fmt == "JPEG":
        # In entropy-coded JPEG data FF D9 is the EOI marker (unlike FF 00
        # stuffing), so requiring the sole EOI at EOF rejects appended
        # markers, whitespace, and embedded second-file polyglots.
        if data.find(b"\xff\xd9") != len(data) - 2:
            raise MediaError("trailing_data", "JPEG has trailing data")
    elif fmt == "WEBP":
        if len(data) < 12 or struct.unpack_from("<I", data, 4)[0] + 8 != len(data):
            raise MediaError("trailing_data", "WebP has trailing data")
    return "gif" if fmt == "GIF" else "jpg"


def _check_size(im: Image.Image) -> None:
    w, h = map(int, im.size)
    if w < 128 or h < 128 or w > MAX_EDGE or h > MAX_EDGE or w * h > MAX_PIXELS:
        raise MediaError("dimensions", "image dimensions or pixel budget exceeded")


def _rendition(im: Image.Image, edge: int) -> Rendition:
    w, h = im.size
    scale = min(1.0, edge / max(w, h))
    size = (max(1, round(w * scale)), max(1, round(h * scale)))
    work = im.convert("RGB")
    if size != work.size:
        work = work.resize(size, Image.Resampling.LANCZOS)
    out = io.BytesIO(); work.save(out, format="JPEG", quality=88, optimize=True)
    raw = out.getvalue(); return Rendition(raw, __import__('hashlib').sha256(raw).hexdigest(), size[0], size[1], "jpg")


def _validate_and_render(data: bytes, *, slot: str = "login", accept_static_fallback: bool = False) -> ValidatedMedia:
    if slot not in ("login", "library"): raise MediaError("slot", "slot must be login or library")
    if not isinstance(data, (bytes, bytearray)) or not data: raise MediaError("empty", "upload is empty")
    raw = bytes(data)
    # GIF has a larger transport cap, all static inputs share the lower cap.
    if len(raw) > MAX_GIF_BYTES: raise MediaError("too_large", "upload exceeds byte limit")
    started = time.monotonic()
    try:
        im = Image.open(io.BytesIO(raw))
        fmt = _format(im, raw); _check_size(im); im.verify()
        # verify() closes/invalidates the decoder; reopen for complete frame walk.
        im = Image.open(io.BytesIO(raw))
        if fmt != "gif":
            im = ImageOps.exif_transpose(im)
        _check_size(im)
        frame_count = int(getattr(im, "n_frames", 1) or 1)
        if fmt != "gif" and len(raw) > MAX_STATIC_BYTES: raise MediaError("too_large", "static upload exceeds 40 MiB")
        if fmt == "gif" and frame_count > MAX_FRAMES: raise MediaError("frames", "GIF has too many frames")
    except MediaError: raise
    except (UnidentifiedImageError, OSError, ValueError, SyntaxError) as exc:
        raise MediaError("invalid_media", "media could not be decoded") from exc
    if fmt == "gif":
        frames: list[Image.Image] = []; delays: list[int] = []
        total = 0
        try:
            total_pixels = 0
            for n in range(frame_count):
                if time.monotonic() - started > MAX_DECODE_SECONDS:
                    raise MediaError("timeout", "GIF decode exceeded time budget")
                im.seek(n); frame = im.convert("RGBA"); frame.load()
                _check_size(frame); frames.append(frame.copy())
                total_pixels += int(frame.width) * int(frame.height)
                if total_pixels > MAX_GIF_TOTAL_PIXELS:
                    raise MediaError("pixels", "GIF aggregate pixel budget exceeded")
                delay = max(33, int(im.info.get("duration") or 0)); delays.append(delay); total += delay
                if total > MAX_GIF_DURATION_MS: raise MediaError("duration", "GIF loop exceeds 20 seconds")
        except MediaError: raise
        except Exception as exc: raise MediaError("truncated", "GIF frame decode failed") from exc
        # Render max edge 1440, retaining normalized frame timing.
        out_frames = []
        for frame in frames:
            scale = min(1.0, 1440 / max(frame.size)); size = (max(1, round(frame.width*scale)), max(1, round(frame.height*scale)))
            out_frames.append(frame.resize(size, Image.Resampling.LANCZOS) if scale < 1 else frame)
        out = io.BytesIO(); out_frames[0].save(out, format="GIF", save_all=True, append_images=out_frames[1:], duration=delays, loop=0, optimize=False, disposal=2)
        payload = out.getvalue()
        if len(payload) > MAX_GIF_OUTPUT_BYTES:
            if not accept_static_fallback: raise MediaError("gif_output_limit", "safe GIF rendition exceeds 15 MiB")
            renditions = (_rendition(frames[0], 1440),)
        else:
            renditions = (Rendition(payload, __import__('hashlib').sha256(payload).hexdigest(), out_frames[0].width, out_frames[0].height, "gif"),)
        return ValidatedMedia("gif", im.width, im.height, frame_count, total, renditions)
    edges = [edge for edge in (1920, 2560, 3840) if max(im.size) >= edge]
    if not edges: edges = [max(im.size)]
    try: im.load()
    except Exception as exc: raise MediaError("truncated", "image decode failed") from exc
    return ValidatedMedia(fmt, im.width, im.height, 1, 0, tuple(_rendition(im, e) for e in edges))


def validate_and_render(data: bytes, *, slot: str = "login", accept_static_fallback: bool = False) -> ValidatedMedia:
    """Decode with a process-wide concurrency bound to cap retained memory."""
    if not isinstance(data, (bytes, bytearray)) or not data:
        raise MediaError("empty", "upload is empty")
    raw = bytes(data)
    if len(raw) > MAX_GIF_BYTES:
        raise MediaError("too_large", "upload exceeds byte limit")
    # Reject oversized static payloads before Pillow allocates decoder state.
    if len(raw) > MAX_STATIC_BYTES and not raw.startswith((b"GIF87a", b"GIF89a")):
        raise MediaError("too_large", "static upload exceeds 40 MiB")
    if not _DECODE_SLOTS.acquire(timeout=1.0):
        raise MediaError("busy", "media decode capacity is temporarily exhausted")
    try:
        return _validate_and_render(raw, slot=slot, accept_static_fallback=accept_static_fallback)
    finally:
        _DECODE_SLOTS.release()
