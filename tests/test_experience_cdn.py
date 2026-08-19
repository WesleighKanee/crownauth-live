import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
 sys.path.insert(0, str(PROJECT_ROOT))
import hashlib, tempfile, unittest
from pathlib import Path
from crownauth.lib_cdn import LocalContentCDN, content_address, publish_immutable

class CdnTests(unittest.TestCase):
 def test_content_address_and_retry(self):
  with tempfile.TemporaryDirectory() as d:
   c=LocalContentCDN(d); data=b'abc'; out=publish_immutable(c,data,slot='login',edge=1920,fmt='jpg')
   self.assertEqual(out['sha256'],hashlib.sha256(data).hexdigest()); self.assertEqual(c.get(out['name']),data)
   self.assertEqual(publish_immutable(c,data,slot='login',edge=1920,fmt='jpg'),out)
   with self.assertRaises(ValueError): c.put(out['name'],b'other')
 def test_remove_never_mutates_live(self):
  name,_=content_address(b'x',slot='library',edge=1440,fmt='gif'); self.assertTrue(name.endswith('.gif'))
  with tempfile.TemporaryDirectory() as d:
   c=LocalContentCDN(d); c.put(name,b'x'); self.assertFalse(c.remove(name)); self.assertEqual(c.get(name),b'x')

if __name__=='__main__': unittest.main()

