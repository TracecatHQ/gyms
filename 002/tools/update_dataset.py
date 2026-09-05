#!/usr/bin/env python3
"""Compile Gym 002's audited BOTSv3 specification into benchmark artifacts."""

from __future__ import annotations

import sys
from pathlib import Path


GYM_ROOT = Path(__file__).resolve().parents[1]
REPO_SRC = GYM_ROOT.parent / "src"
for source in (str(GYM_ROOT), str(REPO_SRC)):
    if source not in sys.path:
        sys.path.insert(0, source)

from tools.botsv3.cli import main  # noqa: E402


if __name__ == "__main__":
    defaults = [
        "--archive",
        str(GYM_ROOT / "assets/botsv3-20260904T130332Z-1-001.zip"),
        "--specs",
        str(GYM_ROOT / "benchmark/evals/cases.source.json"),
        "--output-root",
        str(GYM_ROOT),
    ]
    raise SystemExit(main([*defaults, *sys.argv[1:]]))
