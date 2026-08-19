import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from crownauth import db, server


class LegacyLibraryCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.patch = mock.patch.multiple(db, DATA=root, DB_PATH=root / "db.sqlite")
        self.patch.start()
        db.init_db()
        db.lib_save("ASHESZ.so", b"legacy", version="1")
        self.http = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()
        self.url = "http://127.0.0.1:%d/v2/libs" % self.http.server_address[1]

    def tearDown(self):
        self.http.shutdown()
        self.http.server_close()
        self.patch.stop()
        self.tmp.cleanup()

    def test_default_feed_remains_available_for_legacy_clients(self):
        with urllib.request.urlopen(self.url) as response:
            payload = json.loads(response.read())
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["libs"][0]["name"], "ASHESZ.so")

    def test_explicit_post_migration_cutoff_disables_feed(self):
        db.set_setting("legacy_libs_cutoff", True)
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(self.url)
        self.assertEqual(ctx.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
