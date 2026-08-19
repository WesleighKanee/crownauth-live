import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
 sys.path.insert(0, str(PROJECT_ROOT))
import io
import unittest
from PIL import Image
from crownauth.experience_media import MediaError, validate_and_render


def image(fmt='JPEG', size=(256, 256)):
    out=io.BytesIO(); Image.new('RGB', size, '#223344').save(out, fmt); return out.getvalue()


class MediaTests(unittest.TestCase):
    def test_static_rendition_and_hash(self):
        m=validate_and_render(image(size=(2048, 1024)))
        self.assertEqual(m.source_format, 'jpg'); self.assertTrue(m.renditions)
        for r in m.renditions:
            import hashlib
            self.assertEqual(r.sha256, hashlib.sha256(r.data).hexdigest())
            self.assertLessEqual(max(r.width,r.height),3840)

    def test_gif_bounds_and_animation(self):
        out=io.BytesIO(); frames=[Image.new('RGBA',(128,128),c) for c in ('red','blue')]
        frames[0].save(out,'GIF',save_all=True,append_images=frames[1:],duration=[1,1],loop=0)
        m=validate_and_render(out.getvalue(),slot='library')
        self.assertEqual(m.source_format,'gif'); self.assertEqual(m.frame_count,2); self.assertGreaterEqual(m.duration_ms,66)

    def test_bad_and_too_small_rejected(self):
        with self.assertRaises(MediaError): validate_and_render(b'not an image')
        with self.assertRaises(MediaError): validate_and_render(image(size=(32,32)))


if __name__=='__main__': unittest.main()

