import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
 sys.path.insert(0, str(PROJECT_ROOT))
import tempfile, unittest
from pathlib import Path
from unittest import mock
from crownauth import db
from crownauth import server
from crownauth.crypto_v2 import mint_license_token, token_fingerprint

class LicenseTimeTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory(); root=Path(self.t.name); self.p=mock.patch.multiple(db,DATA=root,DB_PATH=root/'db.sqlite'); self.p.start(); db.init_db(); db.set_setting('require_challenge',False); db.set_setting('generic_errors',False)
  self.token=mint_license_token(); db.create_license(self.token,token_fingerprint(self.token),duration_seconds=3600,tier='vip')
 def tearDown(self): self.p.stop(); self.t.cleanup()
 def test_login_and_heartbeat_expose_authoritative_fields(self):
  login=server.client_auth({'token':self.token,'hwid':'device','phase':'login'},'127.0.0.1'); self.assertTrue(login['ok']); self.assertIn('server_time',login); self.assertIn('license_expires_at',login)
  hb=server.client_heartbeat({'session':login['session'],'hwid':'device'},'127.0.0.1'); self.assertTrue(hb['ok']); self.assertEqual(hb['license_expires_at'],login['license_expires_at']); self.assertEqual(hb['tier'],'vip'); self.assertEqual(hb['license_status'],'active'); self.assertIn('server_time',hb)
 def test_lifetime_is_zero(self):
  tok=mint_license_token(); db.create_license(tok,token_fingerprint(tok),duration_seconds=0); out=server.client_auth({'token':tok,'hwid':'life','phase':'login'},'127.0.0.1'); self.assertEqual(out['license_expires_at'],0)

if __name__=='__main__': unittest.main()

