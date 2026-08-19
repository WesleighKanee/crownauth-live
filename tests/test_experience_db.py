import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
 sys.path.insert(0, str(PROJECT_ROOT))
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from crownauth import db


class ExperienceMigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.patch = mock.patch.multiple(db, DATA=root, DB_PATH=root / "test.db")
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.tmp.cleanup()

    def test_fresh_and_repeat_migration_is_idempotent(self):
        db.init_db()
        con = db.connect()
        for name in db.experience_tables():
            self.assertIsNotNone(con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone())
        self.assertEqual(4, con.execute("SELECT count(*) FROM library_labels").fetchone()[0])
        con.execute("INSERT INTO experience_assets(slot,sha256,format,width,height,bytes,cdn_name,created_at) VALUES('login','x','jpg',1,1,1,'x',1)")
        con.commit(); con.close()
        db.init_db(); db.init_db()
        con = db.connect()
        self.assertEqual(1, con.execute("SELECT count(*) FROM experience_assets WHERE sha256='x'").fetchone()[0])
        self.assertEqual(1, con.execute("SELECT count(*) FROM experience_state").fetchone()[0])
        con.close()

    def test_migrates_current_copy_without_loss(self):
        con = sqlite3.connect(str(db.DB_PATH))
        con.executescript("CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT NOT NULL); CREATE TABLE libs(name TEXT PRIMARY KEY,version TEXT DEFAULT '',size INTEGER NOT NULL DEFAULT 0,md5 TEXT DEFAULT '',enabled INTEGER NOT NULL DEFAULT 1,note TEXT DEFAULT '',created_at INTEGER NOT NULL DEFAULT 0,has_cover INTEGER NOT NULL DEFAULT 0);")
        con.execute("INSERT INTO settings VALUES('keep','\"yes\"')")
        con.execute("INSERT INTO libs(name,version) VALUES('ASHESZ','1')")
        con.commit(); con.close()
        db.init_db()
        con = db.connect()
        self.assertEqual('"yes"', con.execute("SELECT value FROM settings WHERE key='keep'").fetchone()[0])
        self.assertEqual('1', con.execute("SELECT version FROM libs WHERE name='ASHESZ'").fetchone()[0])
        con.close()


if __name__ == '__main__':
    unittest.main()

