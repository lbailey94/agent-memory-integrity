# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Pins the measured scorecard for Recallspection / ExactMemory.

Runs only with AGMI_RECALLSPECTION_REPO pointing at a checkout of
exactmemory.recallspection at the pinned commit, since the core is not
published on PyPI. The read path is the core's own `load` followed by
`get_with_status` on every record.

The two rows differ in one thing, where the anchor lives, and the tests pin
that they differ on T9 and on nothing else.
"""

import os

import pytest

if not os.environ.get("AGMI_RECALLSPECTION_REPO"):
    pytest.skip("AGMI_RECALLSPECTION_REPO not set", allow_module_level=True)

from agmi.adapters.recallspection import (  # noqa: E402
    CORE_VERSION, PIN, RecallspectionAdapter, RecallspectionAnchoredAdapter,
    installed_commit,
)
from agmi.attacks.at_rest import AT_REST_ATTACKS_WITH_SNAPSHOT  # noqa: E402

RECORD_EDITS = ("tamper", "truncate", "delete_middle", "reorder", "forge",
                "cross_replay", "rollback_replay", "metadata_tamper")


def _run(cls):
    return {r.attack: r for r in (c().run(cls()) for c in AT_REST_ATTACKS_WITH_SNAPSHOT)}


def test_the_checkout_is_the_pinned_one():
    assert installed_commit() == PIN
    assert RecallspectionAdapter().measured_on().endswith(PIN[:7])
    assert CORE_VERSION == "3.2.0"


def test_a_clean_store_is_served_whole_and_the_contexts_are_separate():
    a = RecallspectionAdapter()
    a.setup()
    try:
        a.seed(5)
        a.seed_other(5)
        assert a.verify() is True
        assert "5 records served ok" in (a.verify_detail or "")
        first = [r.fields["key"] for r in a.read_all_raw()]
        other = [r.fields["key"] for r in a.read_other_raw()]
        assert all(k.startswith("agmi-seed-") for k in first)
        assert all(k.startswith("agmi-other-") for k in other)
        # No value is shared, so a donor landing in the first context can only
        # have come from the second.
        assert not ({a.payload_of(r) for r in a.read_all_raw()}
                    & {a.payload_of(r) for r in a.read_other_raw()})
        assert a.owner_of(a.read_all_raw()[0]) != a.owner_of(a.read_other_raw()[0])
    finally:
        a.teardown()


def test_every_record_edit_is_refused_by_the_container_mac():
    results = _run(RecallspectionAdapter)
    for name in RECORD_EDITS:
        r = results[name]
        assert r.guard is None, f"{name}: {r.guard}"
        assert r.error is None, f"{name}: {r.error}"
        assert r.detected is True, f"{name} moved; re-measure"
        assert "Container MAC failed" in (r.detail or ""), f"{name}: {r.detail}"


def test_the_default_anchor_leaves_a_whole_store_rollback_accepted():
    # The product's default puts anchor.json beside memory.db, so an attacker
    # with disk write rolls the anchor back too and nothing is left off-store
    # to notice. The maintainer asked for this row to be published.
    r = _run(RecallspectionAdapter)["snapshot_rollback"]
    assert r.guard is None and r.error is None
    assert r.detected is False
    assert r.status == "VULNERABLE"


def test_an_off_store_anchor_catches_the_rollback_and_says_so_differently():
    r = _run(RecallspectionAnchoredAdapter)["snapshot_rollback"]
    assert r.guard is None and r.error is None
    assert r.detected is True
    # A different exception type from the record edits, which is the point of
    # the row: T9 is caught by the anchor, not by the container MAC.
    assert "RollbackError" in (r.detail or "")
    assert "Container MAC failed" not in (r.detail or "")


def test_the_two_configurations_differ_on_t9_and_nothing_else():
    default = _run(RecallspectionAdapter)
    anchored = _run(RecallspectionAnchoredAdapter)
    assert set(default) == set(anchored)
    differ = [name for name in default
              if default[name].detected != anchored[name].detected]
    assert differ == ["snapshot_rollback"], differ
