#!/usr/bin/env python3
"""Run free-tier backup + verify drill from CLI (optional).

Usage (from owner_panel, with env set like Render):
  set GITHUB_TOKEN=...
  set GITHUB_BACKUP_REPO=owner/crownauth-live-data
  python tools/restore_drill.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))

from crownauth.persist import restore_drill  # noqa: E402


def main() -> int:
    result = restore_drill()
    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
