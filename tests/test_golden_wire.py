"""Characterisation: the request shape of every public method is frozen.

Any refactor that changes a URL (query order included), header order, or
body of a recorded method turns this red.  If the change is intended (e.g.
new capture evidence), regenerate with `uv run python -m tests.golden_harness`
and review the diff of tests/golden/wire.json like code.
"""

import json

import pytest

from tests.golden_harness import GOLDEN, record

EXPECTED = json.loads(GOLDEN.read_text(encoding="utf-8"))
ACTUAL = record()


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_wire_unchanged(name):
    assert ACTUAL.get(name) == EXPECTED[name]


def test_no_method_added_or_removed_silently():
    assert sorted(ACTUAL) == sorted(EXPECTED)


def test_coverage_floor():
    recorded = [name for name, value in EXPECTED.items() if "url" in value]
    assert len(recorded) >= 99
