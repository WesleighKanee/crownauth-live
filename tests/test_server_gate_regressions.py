import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
 sys.path.insert(0, str(PROJECT_ROOT))
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from PIL import Image

from crownauth import db, experience, experience_media, server


class ServerGateRegressionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.patch = mock.patch.multiple(db, DATA=root, DB_PATH=root / "db.sqlite")
        self.patch.start()
        db.init_db()

    def tearDown(self):
        self.patch.stop()
        self.tmp.cleanup()

    def test_bootstrap_revision_does_not_collide_with_first_publish(self):
        payload, etag, revision = experience.get_manifest()
        self.assertIsNone(payload)
        self.assertEqual((etag, revision), ('"rev-0"', 0))
        fallback = experience.verify_envelope(experience.sign_payload(experience.fallback_manifest()))
        self.assertEqual(fallback["revision"], 0)
        out = experience.publish(expected_revision=0)
        self.assertEqual(out["revision"], 1)
        self.assertNotEqual(out["etag"], etag)

    def test_label_rename_is_atomic_and_idempotent(self):
        body_hash = "a" * 64
        out = experience.rename_label("AURASIA", "Aurora", expected_revision=0,
                                      idempotency_key="rename-1", request_hash=body_hash)
        self.assertEqual(out["revision"], 1)
        replay = experience.rename_label("AURASIA", "Different", expected_revision=0,
                                         idempotency_key="rename-1", request_hash=body_hash)
        self.assertEqual(replay, out)
        with self.assertRaises(experience.ConflictError) as ctx:
            experience.rename_label("AURASIA", "Nope", expected_revision=1,
                                    idempotency_key="rename-1", request_hash="b" * 64)
        self.assertEqual(ctx.exception.code, "idempotency_conflict")
        self.assertEqual(db.library_labels()[0]["display_name"], "Aurora")

    def test_forwarded_headers_are_ignored_from_untrusted_peer(self):
        h = server.Handler.__new__(server.Handler)
        h.client_address = ("127.0.0.1", 1)
        h.headers = {"X-Forwarded-For": "203.0.113.9", "CF-Connecting-IP": "198.51.100.4"}
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("TRUSTED_PROXY_CIDRS", None)
            self.assertEqual(h._ip(), "127.0.0.1")
        with mock.patch.dict(os.environ, {"TRUSTED_PROXY_CIDRS": "127.0.0.1/32"}):
            self.assertEqual(h._ip(), "198.51.100.4")

    def test_exif_orientation_is_normalized_before_rendition(self):
        out = io.BytesIO()
        im = Image.new("RGB", (128, 256), "red")
        exif = im.getexif(); exif[274] = 6
        im.save(out, "JPEG", exif=exif)
        media = experience_media.validate_and_render(out.getvalue())
        self.assertEqual((media.renditions[0].width, media.renditions[0].height), (256, 128))


if __name__ == "__main__":
    unittest.main()

