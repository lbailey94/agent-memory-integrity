# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""T10, erasure resurrection: the tool erases a record through its own
API, the attacker restores a copy of the store taken before that erasure,
and the tool reads.

Self-validation: the reference store catches it because its witness moved
to the post-erasure head; a store whose only out-of-reach state is a
high-water mark would not, since erasure does not raise it. An adapter
without the erasure hook reads not evaluable, never a pass."""

import pytest

from agmi.adapters.reference_atrest import ReferenceAtRestAdapter
from agmi.attacks.at_rest import (
    ALL_AT_REST_ATTACKS, AT_REST_ATTACKS_WITH_ERASE, AT_REST_ATTACKS_WITH_SNAPSHOT,
    EraseResurrectAttack,
)
from agmi.attacks.guard import GuardFailed


def test_the_ten_are_the_nine_plus_t10():
    assert AT_REST_ATTACKS_WITH_ERASE[:-1] == AT_REST_ATTACKS_WITH_SNAPSHOT
    assert AT_REST_ATTACKS_WITH_ERASE[-1] is EraseResurrectAttack
    assert AT_REST_ATTACKS_WITH_ERASE[:8] == ALL_AT_REST_ATTACKS


def test_reference_store_rejects_the_returned_record():
    a = ReferenceAtRestAdapter()
    r = EraseResurrectAttack().run(a)
    assert r.error is None and r.guard is None, (r.error, r.guard)
    assert r.detected
    assert "erased is back" in (a.verify_detail or "")


def test_reference_store_accepts_its_own_erasure():
    """The tool's own erasure must leave a store the tool still trusts;
    otherwise T10 would be measuring a broken erase, not a resurrection."""
    a = ReferenceAtRestAdapter()
    a.setup()
    try:
        a.seed(5)
        erased = a.erase_genuine()
        assert len(erased) == 1
        assert len(a.read_all_raw()) == 4
        assert a.verify(), a.verify_detail
    finally:
        a.teardown()


def test_adapter_without_erase_hook_is_not_evaluable():
    class Bare(ReferenceAtRestAdapter):
        supports_erase = False
    r = EraseResurrectAttack().run(Bare())
    assert r.error is not None and "erasure" in r.error
    assert r.status == "n/a"


def test_adapter_without_snapshot_is_not_evaluable():
    class Bare(ReferenceAtRestAdapter):
        supports_snapshot = False
    r = EraseResurrectAttack().run(Bare())
    assert r.status == "n/a"


def test_guard_refuses_an_erasure_that_did_not_land():
    """Control C3: if the tool's erase removes nothing, the cell is an
    ERROR, never a verdict."""
    class NoOp(ReferenceAtRestAdapter):
        def erase_genuine(self):
            return ["ctx-A:4"]  # claims an erasure it did not perform
    r = EraseResurrectAttack().run(NoOp())
    assert r.guard is not None and "did not remove" in r.guard, r.guard
    assert r.status == "ERROR"


def test_guard_refuses_an_erasure_that_names_nothing():
    class Nothing(ReferenceAtRestAdapter):
        def erase_genuine(self):
            return []
    r = EraseResurrectAttack().run(Nothing())
    assert r.guard is not None and "erased nothing" in r.guard


@pytest.mark.parametrize("modname, attr, expect", [
    ("agmi.adapters.langgraph_sqlite", "LangGraphSqliteAdapter", False),
    ("agmi.adapters.openai_agents_session", "OpenAIAgentsSessionAdapter", False),
    ("agmi.adapters.llamaindex_memory", "LlamaIndexMemoryAdapter", False),
    ("agmi.adapters.mem0_at_rest", "Mem0AtRestAdapter", False),
])
def test_measured_rows(modname, attr, expect):
    mod = pytest.importorskip(modname)
    cls = getattr(mod, attr)
    try:
        a = cls()
        r = EraseResurrectAttack().run(a)
    except ImportError:
        pytest.skip(f"{modname} dependency not installed")
    if r.error and ("No module" in r.error or "import" in r.error.lower()
                    or "is not set" in r.error or "not installed" in r.error):
        pytest.skip(r.error)
    assert r.error is None and r.guard is None, (r.error, r.guard)
    assert r.detected is expect, a.verify_detail


def test_guard_failed_is_the_control_type():
    assert issubclass(GuardFailed, Exception)
