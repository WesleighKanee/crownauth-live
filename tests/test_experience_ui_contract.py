import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
 sys.path.insert(0, str(PROJECT_ROOT))
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "crownauth" / "static" / "index.html").read_text(encoding="utf-8", errors="replace")
PANEL_JS = (ROOT / "crownauth" / "static" / "js" / "panel.js").read_text(encoding="utf-8", errors="replace")


class ExperienceUiContractTests(unittest.TestCase):
    """Executable static/DOM contracts for the owner Theme Director gate."""

    def test_experience_has_own_navigation_and_view(self):
        self.assertRegex(HTML, r'data-view="experience"[^>]*>Experience')
        self.assertIn('id="view-experience"', HTML)
        self.assertIn('id="view-libs"', HTML)
        self.assertIn('experience: ["Experience"', PANEL_JS)

    def test_preview_modes_and_accessible_focal_pickers(self):
        for mode in ("desktop", "16:9", "20:9", "tablet"):
            self.assertIn(f'data-preview-mode="{mode}"', HTML)
        self.assertEqual(HTML.count('data-focal-picker="Login"'), 1)
        self.assertEqual(HTML.count('data-focal-picker="Library"'), 1)
        self.assertIn('role="application"', HTML)
        self.assertIn('aria-label="Login focal point', HTML)
        self.assertIn('aria-label="Library focal point', HTML)
        self.assertIn("pointerdown", HTML)

    def test_upload_uses_server_rendition_and_revision(self):
        self.assertIn("/api/experience/assets?slot=", HTML)
        self.assertIn("expected_revision=", HTML)
        self.assertIn("X-Expected-Revision", HTML)
        self.assertIn("setServerPreview", HTML)
        self.assertIn("server rendition loaded into preview", HTML)
        self.assertIn("URL.revokeObjectURL", HTML)
        self.assertNotIn("preview.src = URL.createObjectURL(file)", HTML)

    def test_publish_and_conflicts_are_explicit(self):
        self.assertIn("window.confirm(\"Publish this draft", HTML)
        self.assertIn("Conflict (409)", HTML)
        self.assertIn("refreshAfterConflict", HTML)
        self.assertRegex(HTML, r'expected_revision:\s*exp\.revision')

    def test_cloud_ids_are_seeded_and_response_is_accessible(self):
        for sid in ("AURASIA", "AUREXIA", "AURYNXIA", "AUVEXIA"):
            self.assertIn(sid, HTML)
        self.assertIn('role="alert"', HTML)
        self.assertIn('role="status"', HTML)
        self.assertIn('aria-live="polite"', HTML)
        self.assertIn('class ExperienceRequestError', HTML)


if __name__ == "__main__":
    unittest.main()

