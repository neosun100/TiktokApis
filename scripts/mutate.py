"""Mutation check: prove a test goes red when a guarded line is reverted.

    uv run python scripts/mutate.py FILE 'original snippet' 'mutated snippet' [pytest args...]

Exit 0 when the mutant is killed (tests fail), 1 when it survives, 2 when the
snippet was not found (the mutation never landed — that is not a pass).
__pycache__ is purged before *and after*: a same-length edit restored within
the same second keeps the mutant's .pyc valid (mtime+size check) and
poisons every later run.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def purge():
    for cache in ROOT.rglob("__pycache__"):
        if ".venv" not in cache.parts:
            shutil.rmtree(cache, ignore_errors=True)


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    path, original, mutated, *pytest_args = argv
    target = ROOT / path
    source = target.read_text(encoding="utf-8")
    if source.count(original) != 1:
        print(f"MISSING: snippet occurs {source.count(original)} times in {path}", file=sys.stderr)
        return 2
    target.write_text(source.replace(original, mutated, 1), encoding="utf-8")
    purge()
    try:
        result = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", *pytest_args],
                                cwd=ROOT, capture_output=True, text=True)
    finally:
        target.write_text(source, encoding="utf-8")
        purge()
    summary = (result.stdout.strip().splitlines() or ["?"])[-1]
    killed = result.returncode != 0
    print(f"{'KILLED' if killed else 'SURVIVED'}: {summary}")
    return 0 if killed else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
