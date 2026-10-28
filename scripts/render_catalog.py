"""Regenerate the bypass catalog table in README.md from tests/test_bypass_catalog.py.

Usage: python scripts/render_catalog.py [--check]
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from tests.test_bypass_catalog import BEGIN, END, render_table  # noqa: E402


def main() -> int:
    readme_path = ROOT / "README.md"
    readme = readme_path.read_text(encoding="utf-8")
    start = readme.index(BEGIN) + len(BEGIN)
    stop = readme.index(END)
    updated = readme[:start] + "\n" + render_table() + "\n" + readme[stop:]
    if "--check" in sys.argv[1:]:
        if updated != readme:
            print("README.md catalog is stale", file=sys.stderr)
            return 1
        return 0
    readme_path.write_text(updated, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
