import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
 sys.path.insert(0, str(PROJECT_ROOT))
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from crownauth import db, experience


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); root = Path(self.tmp.name)
        self.p = mock.patch.multiple(db, DATA=root, DB_PATH=root / 'db.sqlite')
        self.p.start(); db.init_db()

    def tearDown(self): self.p.stop(); self.tmp.cleanup()

    def test_deterministic_signature_and_tamper_rejected(self):
        result = experience.publish(expected_revision=0)
        self.assertTrue(result['manifest']); self.assertEqual(result['etag'], '"rev-1"')
        payload = experience.verify_envelope(result['manifest'])
        self.assertEqual(payload['revision'], 1)
        self.assertEqual(experience.sign_payload(payload), result['manifest'])
        tampered = ('A' if result['manifest'][0] != 'A' else 'B') + result['manifest'][1:]
        with self.assertRaises(experience.ExperienceError): experience.verify_envelope(tampered)

    def test_stale_revision_and_idempotency(self):
        body = '{"x":1}'
        one = experience.publish(expected_revision=0, idempotency_key='a', request_hash='h')
        self.assertEqual(one, experience.publish(expected_revision=0, idempotency_key='a', request_hash='h'))
        with self.assertRaises(experience.ConflictError): experience.publish(expected_revision=0)
        with self.assertRaises(experience.ConflictError): experience.publish(expected_revision=1, idempotency_key='a', request_hash='different')

    def test_unknown_settings_rejected(self):
        with self.assertRaises(experience.ExperienceError): experience.update_draft({'theme': {'preset': 'NOPE'}}, expected_revision=0)


if __name__ == '__main__': unittest.main()

