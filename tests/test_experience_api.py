import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
 sys.path.insert(0, str(PROJECT_ROOT))
import json, tempfile, threading, unittest, urllib.request
from pathlib import Path
from unittest import mock
from crownauth import db, server

class ApiTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory(); root=Path(self.t.name); self.p=mock.patch.multiple(db,DATA=root,DB_PATH=root/'db.sqlite'); self.p.start(); db.init_db()
  self.http=server.ThreadingHTTPServer(('127.0.0.1',0),server.Handler); self.th=threading.Thread(target=self.http.serve_forever,daemon=True); self.th.start(); self.url='http://127.0.0.1:%d/v2/experience/manifest'%self.http.server_address[1]
 def tearDown(self): self.http.shutdown(); self.http.server_close(); self.p.stop(); self.t.cleanup()
 def test_get_conditional_and_head(self):
  with urllib.request.urlopen(self.url) as r: self.assertEqual(r.status,200); etag=r.headers['ETag']; body=json.loads(r.read())
  self.assertTrue(body['ok']); self.assertIn('.',body['manifest'])
  req=urllib.request.Request(self.url,headers={'If-None-Match':etag})
  with self.assertRaises(urllib.error.HTTPError) as ctx: urllib.request.urlopen(req)
  self.assertEqual(ctx.exception.code,304)
  req=urllib.request.Request(self.url,method='HEAD')
  with urllib.request.urlopen(req) as r: self.assertEqual(r.status,200); self.assertEqual(r.headers['ETag'],etag)

if __name__=='__main__': unittest.main()

