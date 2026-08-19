import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
 sys.path.insert(0, str(PROJECT_ROOT))
import io, json, tempfile, threading, unittest, urllib.error, urllib.request
from pathlib import Path
from unittest import mock
from PIL import Image
from crownauth import db, server, owner_auth

class OwnerApiTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory(); root=Path(self.t.name); self.p=mock.patch.multiple(db,DATA=root,DB_PATH=root/'db.sqlite'); self.p.start(); db.init_db(); db.set_setting('enable_owner_ip_allowlist',True); db.set_setting('quiet_logs',False)
  self.http=server.ThreadingHTTPServer(('127.0.0.1',0),server.Handler); threading.Thread(target=self.http.serve_forever,daemon=True).start(); self.base='http://127.0.0.1:%d'%self.http.server_address[1]; self.h={'X-Owner-Key':owner_auth.load_or_create_api_token()}
 def tearDown(self): self.http.shutdown(); self.http.server_close(); self.p.stop(); self.t.cleanup()
 def req(self,path,method='GET',data=None,headers=None):
  h=dict(self.h); h.update(headers or {}); req=urllib.request.Request(self.base+path,data=data,method=method,headers=h)
  with urllib.request.urlopen(req) as r: return r.status,json.loads(r.read() or b'{}')
 def test_auth_draft_upload_publish_and_idempotency(self):
  code,draft=self.req('/api/experience/draft'); self.assertEqual(code,200); self.assertEqual(draft['manifest_revision'],0)
  b=io.BytesIO(); Image.new('RGB',(128,128),'red').save(b,'JPEG'); code,out=self.req('/api/experience/assets?slot=login&expected_revision=0','POST',b.getvalue(),{'Content-Type':'application/octet-stream','X-Expected-Revision':'0'}); self.assertEqual(code,200); self.assertTrue(out['ok'])
  code,out=self.req('/api/experience/publish','POST',b'{}',{'Content-Type':'application/json','Idempotency-Key':'one'}); self.assertEqual(out['revision'],1)
  code,out2=self.req('/api/experience/publish','POST',b'{}',{'Content-Type':'application/json','Idempotency-Key':'one'}); self.assertEqual(out2,out)
 def test_upload_requires_owner(self):
  req=urllib.request.Request(self.base+'/api/experience/assets?slot=login&expected_revision=0',data=b'bad',method='POST',headers={'Content-Type':'application/octet-stream','X-Expected-Revision':'0'})
  with self.assertRaises(urllib.error.HTTPError) as e: urllib.request.urlopen(req)
  self.assertEqual(e.exception.code,401)

 def test_stale_upload_returns_409_and_does_not_change_draft(self):
  # A real HTTP request must reject stale Theme Director coordinates before
  # media/CDN work and before the draft's selected asset is changed.
  code,before=self.req('/api/experience/draft')
  self.assertEqual(before['manifest_revision'],0)
  image=io.BytesIO(); Image.new('RGB',(128,128),'blue').save(image,'JPEG')
  code,published=self.req('/api/experience/publish','POST',b'{}',{'Content-Type':'application/json'})
  self.assertEqual(code,200); self.assertEqual(published['revision'],1)
  req=urllib.request.Request(self.base+'/api/experience/assets?slot=login&expected_revision=0',data=image.getvalue(),method='POST',headers={**self.h,'Content-Type':'application/octet-stream','X-Expected-Revision':'0'})
  with self.assertRaises(urllib.error.HTTPError) as error:
   urllib.request.urlopen(req)
  self.assertEqual(error.exception.code,409)
  body=json.loads(error.exception.read())
  self.assertEqual(body['error']['code'],'stale_revision')
  _,after=self.req('/api/experience/draft')
  self.assertIsNone(after['draft'].get('login_asset_id'))

 def test_upload_accepts_header_only_revision(self):
  image=io.BytesIO(); Image.new('RGB',(128,128),'green').save(image,'JPEG')
  code,out=self.req('/api/experience/assets?slot=login','POST',image.getvalue(),{'Content-Type':'application/octet-stream','X-Expected-Revision':'0'})
  self.assertEqual(code,200); self.assertTrue(out['ok'])

if __name__=='__main__': unittest.main()

