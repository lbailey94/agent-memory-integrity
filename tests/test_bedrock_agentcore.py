# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""The AWS Bedrock AgentCore Memory event-plane row.

Two layers. The stub tests run everywhere, including CI with no AWS account:
they drive the adapter against an in-process double of the two AgentCore
clients that implements exactly the operations the service exposes
(CreateEvent, ListEvents, DeleteEvent, and no update of any kind), so the
adapter's own logic, its guard hooks and its not-applicable reasons are
pinned without spending anything.

The live test runs only with AGMI_BEDROCK=1 and real credentials, and pins
the measured row against the service itself.
"""

import datetime as dt
import os
import uuid

import pytest

from agmi.adapters.bedrock_agentcore import (  # noqa: E402
    NO_METADATA, NO_REORDER, NO_SNAPSHOT, NO_UPDATE, SESSION,
    BedrockAgentCoreEventsAdapter,
)
from agmi.attacks.at_rest import AT_REST_ATTACKS_WITH_SNAPSHOT  # noqa: E402

#: The edits the event plane can actually make, and the ones its API cannot.
APPLY = {"truncate", "delete_middle", "forge"}
NOT_APPLICABLE = {"tamper", "reorder", "cross_replay", "rollback_replay",
                  "metadata_tamper", "snapshot_rollback"}


class _FakeData:
    """The AgentCore data plane, as much of it as this row uses."""

    def __init__(self):
        self.events: list[dict] = []

    def create_event(self, memoryId, actorId, sessionId, eventTimestamp, payload):  # noqa: N803
        event = {"memoryId": memoryId, "actorId": actorId, "sessionId": sessionId,
                 "eventTimestamp": eventTimestamp, "payload": payload,
                 "branch": None, "eventId": uuid.uuid4().hex}
        self.events.append(event)
        return {"event": event}

    def list_events(self, memoryId, actorId, sessionId, maxResults=100, nextToken=None):  # noqa: N803
        return {"events": [e for e in self.events
                           if e["actorId"] == actorId and e["sessionId"] == sessionId]}

    def delete_event(self, memoryId, actorId, sessionId, eventId):  # noqa: N803
        before = len(self.events)
        self.events = [e for e in self.events if e["eventId"] != eventId]
        if len(self.events) == before:
            raise RuntimeError(f"no event {eventId}")
        return {}


class _FakeControl:
    def create_memory(self, **kwargs):
        return {"memory": {"id": "mem-fake"}}

    def get_memory(self, memoryId):  # noqa: N803
        return {"memory": {"status": "ACTIVE"}}

    def delete_memory(self, memoryId):  # noqa: N803
        return {}


def _stub_adapter(shared: _FakeData | None = None) -> BedrockAgentCoreEventsAdapter:
    adapter = BedrockAgentCoreEventsAdapter(region="stub", memory_id="mem-fake")
    control, data = _FakeControl(), (shared or _FakeData())

    def _clients():
        # reload() drops the clients, as it does against the real service;
        # here the doubles come back instead of new boto3 clients.
        adapter._control, adapter._data = control, data
        return control, data

    adapter._clients = _clients  # type: ignore[assignment]
    adapter._clients()
    adapter.settle_seconds = 5.0
    return adapter


def test_the_clean_store_is_served_whole_and_actors_are_separate():
    a = _stub_adapter()
    a.setup()
    try:
        a.seed(5)
        a.seed_other(5)
        assert a.verify() is True
        texts = [r.fields["text"] for r in a.read_all_raw()]
        assert len(texts) == 5 and all(t.startswith("agmi-seed-") for t in texts)
        assert all(r.fields["text"].startswith("agmi-other-") for r in a.read_other_raw())
        assert [r.fields["eventTimestamp"] for r in a.read_all_raw()] == sorted(
            r.fields["eventTimestamp"] for r in a.read_all_raw())
    finally:
        a.teardown()


def test_the_api_refuses_every_edit_that_would_rewrite_an_event():
    a = _stub_adapter()
    a.setup()
    try:
        a.seed(5)
        a.seed_other(5)
        existing = a.read_all_raw()[2]
        with pytest.raises(RuntimeError, match="no UpdateEvent"):
            a.write_raw(a.mutate_payload(existing))
        with pytest.raises(RuntimeError, match="no UpdateEvent"):
            a.replay_onto(2, a.read_other_raw()[1])
        # A move to another position is a different refusal from a rewrite.
        moved = a.read_all_raw()[1]
        moved.seq = 3
        with pytest.raises(RuntimeError, match="ordered by eventTimestamp"):
            a.write_raw(moved)
        with pytest.raises(RuntimeError, match="fixed at"):
            a.write_meta(2, {"actorId": "someone-else"})
        assert [r.fields["text"] for r in a.read_all_raw()] == [
            f"agmi-seed-{i}: the limit is {50 + i}" for i in range(5)]
    finally:
        a.teardown()


def test_delete_and_forge_land_and_the_read_path_serves_the_result():
    a = _stub_adapter()
    a.setup()
    try:
        a.seed(5)
        a.delete_raw(2)
        after_delete = [r.fields["text"] for r in a.read_all_raw()]
        assert len(after_delete) == 4 and "agmi-seed-2" not in " ".join(after_delete)
        a.write_raw(a.forge_record(a.read_all_raw()[-1]))
        served = [r.fields["text"] for r in a.read_all_raw()]
        assert len(served) == 5 and served[-1].startswith("agmi-seed-forged")
        assert a.verify() is True
        assert "served 5 events" in (a.verify_detail or "")
    finally:
        a.teardown()


def test_the_nine_edits_split_into_three_measured_and_six_not_applicable():
    shared = _FakeData()
    results = {}
    for cls in AT_REST_ATTACKS_WITH_SNAPSHOT:
        adapter = _stub_adapter(shared)
        r = cls().run(adapter)
        results[r.attack] = r
    assert set(results) == APPLY | NOT_APPLICABLE
    for name in APPLY:
        r = results[name]
        assert r.guard is None, f"{name}: {r.guard}"
        assert r.error is None, f"{name}: {r.error}"
        assert r.detected is False, f"{name}: the service reported the edit"
    for name in NOT_APPLICABLE:
        r = results[name]
        assert r.status == "n/a", f"{name}: expected n/a, got {r.status}"
    # Each refused edit names its own reason, not a catch-all.
    assert results["tamper"].error == NO_UPDATE
    assert results["cross_replay"].error == NO_UPDATE
    assert results["rollback_replay"].error == NO_UPDATE
    assert results["reorder"].error == NO_REORDER
    assert results["metadata_tamper"].error == NO_METADATA
    assert results["snapshot_rollback"].error == NO_SNAPSHOT


def test_a_forged_event_can_be_planted_between_two_genuine_ones():
    a = _stub_adapter()
    a.setup()
    try:
        a.seed(5)
        genuine = a.read_all_raw()
        between = dt.datetime.fromisoformat(genuine[1].fields["eventTimestamp"]) + dt.timedelta(
            milliseconds=1)
        a._create_event(a._actor, "agmi-seed-planted: the limit is 999", between)
        served = [r.fields["text"] for r in a.read_all_raw()]
        assert served[2].startswith("agmi-seed-planted")
        assert len(served) == 6 and a.verify() is True
    finally:
        a.teardown()


@pytest.mark.skipif(os.environ.get("AGMI_BEDROCK") != "1",
                    reason="AGMI_BEDROCK is not 1 (the live row bills a few cents per run)")
def test_live_service_matches_the_published_row():
    results = {}
    for cls in AT_REST_ATTACKS_WITH_SNAPSHOT:
        r = cls().run(BedrockAgentCoreEventsAdapter())
        results[r.attack] = r
    for name in APPLY:
        r = results[name]
        assert r.guard is None, f"{name}: {r.guard}"
        assert r.error is None, f"{name}: {r.error}"
        assert r.detected is False, f"{name} moved at AgentCore; re-measure"
    for name in NOT_APPLICABLE:
        assert results[name].status == "n/a", f"{name}: expected n/a, got {results[name].status}"


@pytest.mark.skipif(os.environ.get("AGMI_BEDROCK") != "1", reason="AGMI_BEDROCK is not 1")
def test_live_service_keeps_each_actor_separate():
    a = BedrockAgentCoreEventsAdapter()
    a.setup()
    try:
        a.seed(5)
        a.seed_other(5)
        assert all(r.fields["actorId"] == a._actor for r in a.read_all_raw())
        assert all(r.fields["sessionId"] == SESSION for r in a.read_all_raw())
        assert "agmi-other-" not in " ".join(r.fields["text"] for r in a.read_all_raw())
    finally:
        a.teardown()
