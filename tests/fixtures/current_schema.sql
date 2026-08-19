-- Minimal representative pre-experience schema used by migration tests.
CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE libs(name TEXT PRIMARY KEY, version TEXT DEFAULT '', size INTEGER NOT NULL DEFAULT 0,
                  md5 TEXT DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1,
                  note TEXT DEFAULT '', created_at INTEGER NOT NULL DEFAULT 0,
                  has_cover INTEGER NOT NULL DEFAULT 0);
