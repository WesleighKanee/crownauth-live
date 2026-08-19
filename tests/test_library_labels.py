import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
 sys.path.insert(0, str(PROJECT_ROOT))
import json, tempfile, threading, unittest, urllib.request
from pathlib import Path
from unittest import mock
from crownauth import db, server

class LabelTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory(); root=Path(self.t.name); self.p=mock.patch.multiple(db,DATA=root,DB_PATH=root/'db.sqlite'); self.p.start(); db.init_db(); db.lib_save('ASHESZ.so',b'binary',version='1')
  self.http=server.ThreadingHTTPServer(('127.0.0.1',0),server.Handler); threading.Thread(target=self.http.serve_forever,daemon=True).start(); self.url='http://127.0.0.1:%d/v2/libs'%self.http.server_address[1]
 def tearDown(self): self.http.shutdown(); self.http.server_close(); self.p.stop(); self.t.cleanup()
 def test_rename_changes_only_display_metadata(self):
  before=db.lib_get('ASHESZ.so'); db.set_library_label('ASHESZ','Ashesz Reborn'); after=db.lib_get('ASHESZ.so'); self.assertEqual(before['name'],after['name']); self.assertEqual(before['md5'],after['md5']); self.assertEqual(before['sha256'],after['sha256'])
  with urllib.request.urlopen(self.url) as r: item=json.loads(r.read())['libs'][0]
  self.assertEqual(item['name'],'ASHESZ.so'); self.assertEqual(item['card'],'ASHESZ'); self.assertEqual(item['display_name'],'Ashesz Reborn'); self.assertEqual(item['sha256'],after['sha256'])
 def test_embedded_defaults_exist(self): self.assertEqual(db.set_library_label('AURASIA','Aurora')['display_name'],'Aurora')

if __name__=='__main__': unittest.main()

