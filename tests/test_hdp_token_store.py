# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Pins the measured scorecard for the HDP token-by-reference store.

Runs only with AGMI_HDP_REPO pointing at a checkout of Helixar-AI/HDP at the
pinned commit, built, with Node 22 on PATH. The read path is the library's
own resolveToken followed by verifyToken, in a fresh process per read.

Two rows, one variable: whether the recipient holds the content-addressed
reference or the UUID. The tests pin both the verdicts and the stage each
refusal happens at, because that stage is the difference between the rows.
"""

import os

import pytest

if not os.environ.get("AGMI_HDP_REPO"):
    pytest.skip("AGMI_HDP_REPO not set", allow_module_level=True)

from agmi.adapters.hdp_token_store import (  # noqa: E402
    PIN, HdpTokenStoreAdapter, HdpTokenStoreUuidAdapter,
)
from agmi.attacks.at_rest import AT_REST_ATTACKS_WITH_SNAPSHOT  # noqa: E402

REFUSED = ("tamper", "reorder", "forge", "cross_replay", "rollback_replay", "metadata_tamper")
SERVED = ("truncate", "delete_middle", "snapshot_rollback")


def _run(cls):
    return {r.attack: r for r in (c().run(cls()) for c in AT_REST_ATTACKS_WITH_SNAPSHOT)}


def test_the_checkout_and_the_runtime_are_the_pinned_ones():
    a = HdpTokenStoreAdapter()
    assert PIN in a.measured_on()
    assert "Node 22" in a.measured_on()


def test_a_clean_store_resolves_and_verifies_in_both_configurations():
    for cls in (HdpTokenStoreAdapter, HdpTokenStoreUuidAdapter):
        a = cls()
        a.setup()
        try:
            a.seed(5)
            a.seed_other(5)
            assert a.verify() is True, cls.name
            assert "verified 5 tokens" in (a.verify_detail or ""), cls.name
            # The two contexts never share a value, so a donor landing in the
            # first context can only have come from the second.
            assert not ({a.payload_of(r) for r in a.read_all_raw()}
                        & {a.payload_of(r) for r in a.read_other_raw()})
            assert a.owner_of(a.read_all_raw()[0]) != a.owner_of(a.read_other_raw()[0])
        finally:
            a.teardown()


def test_both_rows_refuse_the_same_six_edits_and_serve_the_same_three():
    for cls in (HdpTokenStoreAdapter, HdpTokenStoreUuidAdapter):
        results = _run(cls)
        for name in REFUSED:
            r = results[name]
            assert r.guard is None and r.error is None, f"{cls.name} {name}: {r.guard or r.error}"
            assert r.detected is True, f"{cls.name} {name} moved; re-measure"
        for name in SERVED:
            r = results[name]
            assert r.guard is None and r.error is None, f"{cls.name} {name}: {r.guard or r.error}"
            assert r.detected is False, f"{cls.name} {name} moved; re-measure"


def test_a_token_removed_from_the_store_leaves_no_trace_in_either_row():
    # The completeness limit the draft names in 10.4, measured at store level:
    # nothing on the read path knows how many tokens there should be.
    for cls in (HdpTokenStoreAdapter, HdpTokenStoreUuidAdapter):
        a = cls()
        a.setup()
        try:
            a.seed(5)
            a.delete_raw(2)
            assert len(a.read_all_raw()) == 4
            assert a.verify() is True, cls.name
        finally:
            a.teardown()


def test_the_content_reference_refuses_at_resolve_and_the_uuid_at_verify():
    # 8.2: the content reference is checked on read, the UUID binds only the
    # token's id. Same edit, same verdict, a different layer catching it.
    content = _run(HdpTokenStoreAdapter)["tamper"]
    uuid = _run(HdpTokenStoreUuidAdapter)["tamper"]
    assert "content reference digest mismatch" in (content.detail or "")
    assert "resolve:" in (content.detail or "")
    assert "verifyToken failed" in (uuid.detail or "")
    assert "verify:" in (uuid.detail or "")
