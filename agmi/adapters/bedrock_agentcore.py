# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""AWS Bedrock AgentCore Memory, the event plane (short-term memory).

The second managed store on the board, and the attacker is the same position
as the Vertex AI Memory Bank row: there is no disk to edit. "Store access"
here means a principal holding the AgentCore data-plane permissions outside
the agent's own session (a leaked access key, a second workload in the same
account, a platform operator), editing through the API while the agent's own
read path is ListEvents for its actor and session.

An AgentCore memory holds two kinds of state. Events are the raw turns the
agent writes with CreateEvent and reads back with ListEvents; memory records
are the long-term items a strategy extracts from them. This row measures the
event plane. The record plane is a separate row, because its API is
different and so are its answers.

What the API allows, mapped to the nine edits:

  T1 tamper          not applicable: there is no UpdateEvent. An event's
                     content cannot be changed in place, and delete plus
                     create yields a different eventId, which is a
                     different edit, not this one
  T2 truncate        DeleteEvent on the newest two events          applies
  T3 delete_middle   DeleteEvent on one event                      applies
  T4 reorder         not applicable: events are ordered by eventTimestamp,
                     which is fixed at creation, so an existing event
                     cannot be moved to another position
  T5 forge           CreateEvent in the agent's own actor and session, with
                     an attacker-chosen eventTimestamp                applies
  T6 cross_replay    not applicable for the same reason as T1: another
                     actor's text cannot be written over a victim event.
                     Inserting that text as a new event is T5's mechanism
  T7 rollback_replay not applicable for the same reason as T1
  T8 metadata_tamper not applicable: an event's actor, session, timestamp
                     and id are fixed at creation and the API exposes no
                     way to change them
  T9 snapshot_rb     not applicable: a managed store exposes no snapshot or
                     restore of its own state

The shape of that list is the result. AgentCore's event plane is
append-and-delete: an attacker with the data-plane role can remove any turn
from the agent's history and can plant a new one at any point in time, and
the agent's next ListEvents serves what is left as its own record, with no
error and nothing on the read path that notices. What the attacker cannot do
is rewrite a turn in place, which is a stronger position than a store whose
records can be patched.

CloudTrail records the CreateEvent and DeleteEvent calls at the platform
layer when data-event logging is on for AgentCore, naming the principal.
That sits outside the store, the read path never consults it, and it is not
part of this row, exactly as the Admin Activity log is not part of the
Vertex row.

Needs: AGMI_BEDROCK=1 to switch the row on (it bills a few cents per run),
AWS credentials in the environment or profile, and a region in
AWS_DEFAULT_REGION or AGMI_BEDROCK_REGION (default us-east-1). The memory
resource is created with no strategies, so no Bedrock model access and no
execution role are needed, and no long-term records are stored.

One memory resource is created per process and reused (creation takes a
minute or two), then deleted at exit unless AGMI_BEDROCK_KEEP_MEMORY=1 or
AGMI_BEDROCK_MEMORY_ID names an existing one. Each adapter instance uses its
own actor ids, so runs never see each other's events, and teardown deletes
the events it wrote.
"""

from __future__ import annotations

import atexit
import datetime as dt
import os
import secrets
import time

from agmi.adapters.base import MemoryAdapter, Record

SEED_TOKEN = "agmi-seed-"
OTHER_TOKEN = "agmi-other-"
SESSION = "agmi-session"
ROLE = "USER"

#: Why each edit the API cannot make is n/a, printed in the cell.
NO_UPDATE = ("not applicable: AgentCore has no UpdateEvent, so an event's content cannot be "
             "changed in place; delete plus create yields a different eventId, which is a "
             "different edit")
NO_REORDER = ("not applicable: events are ordered by eventTimestamp, fixed at creation, so an "
              "existing event cannot be moved to another position")
NO_METADATA = ("not applicable: an event's actor, session, timestamp and id are fixed at "
               "creation and the API exposes no way to change them")

_MEMORY_CACHE: dict[str, str] = {}


def bedrock_enabled() -> bool:
    return os.environ.get("AGMI_BEDROCK") == "1"


def bedrock_region() -> str:
    return (os.environ.get("AGMI_BEDROCK_REGION")
            or os.environ.get("AWS_DEFAULT_REGION")
            or "us-east-1")


def _text_of(event: dict) -> str:
    for block in event.get("payload") or []:
        content = (block.get("conversational") or {}).get("content") or {}
        if "text" in content:
            return content["text"]
    return ""


def _iso(value) -> str:
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


class BedrockAgentCoreEventsAdapter(MemoryAdapter):
    """AgentCore Memory events, read through the agent's own ListEvents."""

    name = "bedrock-agentcore-events"
    supports_replay = True      # the attempt is made; the API's refusal is the n/a reason
    supports_metadata = True
    supports_snapshot = False
    detection_point = "read"
    metadata_na_reason = NO_METADATA

    #: How long to wait for the service to show a write.
    settle_seconds = 60.0

    def __init__(self, region: str | None = None, memory_id: str | None = None):
        self._region = region or bedrock_region()
        self._memory_arg = memory_id or os.environ.get("AGMI_BEDROCK_MEMORY_ID")
        self._control = None
        self._data = None
        self._memory_id: str | None = None
        self._actor: str | None = None
        self._other_actor: str | None = None

    @staticmethod
    def measured_on() -> str:
        return "AWS Bedrock AgentCore Memory (events), boto3"

    # --- clients and the memory resource ----------------------------------

    def _clients(self):
        if self._control is None:
            import boto3
            self._control = boto3.client("bedrock-agentcore-control", region_name=self._region)
            self._data = boto3.client("bedrock-agentcore", region_name=self._region)
        return self._control, self._data

    def _ensure_memory(self) -> str:
        if self._memory_arg:
            return self._memory_arg
        if self._region in _MEMORY_CACHE:
            return _MEMORY_CACHE[self._region]
        control, _ = self._clients()
        created = control.create_memory(
            name=f"agmi_events_{secrets.token_hex(4)}",
            description="agmi conformance run; no strategies; safe to delete",
            eventExpiryDuration=7,
        )
        memory_id = created["memory"]["id"]
        deadline = time.time() + 600
        while time.time() < deadline:
            status = control.get_memory(memoryId=memory_id)["memory"]["status"]
            if status == "ACTIVE":
                break
            if status == "FAILED":
                raise RuntimeError(f"memory {memory_id} creation FAILED")
            time.sleep(5)
        else:
            raise RuntimeError(f"memory {memory_id} did not become ACTIVE in 10 minutes")
        _MEMORY_CACHE[self._region] = memory_id
        if os.environ.get("AGMI_BEDROCK_KEEP_MEMORY") != "1":
            def _cleanup(mid=memory_id, c=control):
                try:
                    c.delete_memory(memoryId=mid)
                except Exception:  # noqa: BLE001 - best effort at interpreter exit
                    pass
            atexit.register(_cleanup)
        return memory_id

    # --- lifecycle --------------------------------------------------------

    def setup(self) -> None:
        self._clients()
        self._memory_id = self._ensure_memory()
        self._actor = f"agmi-{secrets.token_hex(4)}"
        self._other_actor = f"{self._actor}-B"

    def teardown(self) -> None:
        if self._data is None or not self._memory_id:
            return
        for actor in (self._actor, self._other_actor):
            if not actor:
                continue
            for event in self._raw_events(actor):
                try:
                    self._data.delete_event(memoryId=self._memory_id, actorId=actor,
                                            sessionId=SESSION, eventId=event["eventId"])
                except Exception:  # noqa: BLE001 - teardown is best effort
                    pass

    # --- the agent's write path: CreateEvent ------------------------------

    def _create_event(self, actor: str, text: str, when: dt.datetime) -> str:
        _, data = self._clients()
        resp = data.create_event(
            memoryId=self._memory_id,
            actorId=actor,
            sessionId=SESSION,
            eventTimestamp=when,
            payload=[{"conversational": {"content": {"text": text}, "role": ROLE}}],
        )
        return (resp.get("event") or {}).get("eventId", "")

    def _base_time(self) -> dt.datetime:
        # One minute ago, so a forged event can be given an earlier timestamp
        # and still be in the past.
        return dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)

    def _seed_actor(self, actor: str, token: str, n: int) -> None:
        start = self._base_time()
        for i in range(n):
            self._create_event(actor, f"{token}{i}: the limit is {50 + i}",
                               start + dt.timedelta(seconds=i))
        self._wait_count(actor, n)

    def seed(self, n: int) -> None:
        self._seed_actor(self._actor, SEED_TOKEN, n)

    def seed_other(self, n: int) -> None:
        self._seed_actor(self._other_actor, OTHER_TOKEN, n)

    # --- reading ----------------------------------------------------------

    def _raw_events(self, actor: str) -> list[dict]:
        _, data = self._clients()
        events: list[dict] = []
        token = None
        while True:
            kwargs = {"memoryId": self._memory_id, "actorId": actor,
                      "sessionId": SESSION, "maxResults": 100}
            if token:
                kwargs["nextToken"] = token
            resp = data.list_events(**kwargs)
            events.extend(resp.get("events") or [])
            token = resp.get("nextToken")
            if not token:
                break
        events.sort(key=lambda e: (_iso(e.get("eventTimestamp")), e.get("eventId") or ""))
        return events

    def _to_record(self, seq: int, event: dict) -> Record:
        return Record(seq=seq, fields={
            "eventId": event.get("eventId"),
            "text": _text_of(event),
            "actorId": event.get("actorId"),
            "sessionId": event.get("sessionId"),
            "eventTimestamp": _iso(event.get("eventTimestamp")),
        })

    def _read_actor(self, actor: str) -> list[Record]:
        return [self._to_record(i, e) for i, e in enumerate(self._raw_events(actor))]

    def read_all_raw(self) -> list[Record]:
        return self._read_actor(self._actor)

    def read_other_raw(self) -> list[Record]:
        return self._read_actor(self._other_actor)

    def _wait_count(self, actor: str, n: int) -> None:
        deadline = time.time() + self.settle_seconds
        while time.time() < deadline:
            if len(self._raw_events(actor)) == n:
                return
            time.sleep(1.0)
        raise RuntimeError(f"actor {actor} did not settle at {n} events within {self.settle_seconds}s")

    def _event_at(self, seq: int) -> dict:
        events = self._raw_events(self._actor)
        if seq < 0 or seq >= len(events):
            raise RuntimeError(f"no event at position {seq}")
        return events[seq]

    # --- the data-plane edits (the attacker's moves) ----------------------

    def write_raw(self, record: Record) -> None:
        if record.fields.get("eventId"):
            # An existing event: the API has no way to rewrite one.
            raise RuntimeError(NO_UPDATE)
        current = self._raw_events(self._actor)
        when = self._base_time() + dt.timedelta(seconds=len(current))
        self._create_event(self._actor, record.fields["text"], when)
        self._wait_count(self._actor, len(current) + 1)

    def delete_raw(self, seq: int) -> None:
        _, data = self._clients()
        event = self._event_at(seq)
        n = len(self._raw_events(self._actor))
        data.delete_event(memoryId=self._memory_id, actorId=self._actor,
                          sessionId=SESSION, eventId=event["eventId"])
        self._wait_count(self._actor, n - 1)

    def replay_onto(self, victim_seq: int, donor: Record) -> None:
        raise RuntimeError(NO_UPDATE)

    def read_meta(self, seq: int) -> dict:
        event = self._event_at(seq)
        return {"actorId": event.get("actorId"), "sessionId": event.get("sessionId"),
                "eventTimestamp": _iso(event.get("eventTimestamp"))}

    def write_meta(self, seq: int, meta: dict) -> None:
        raise RuntimeError(NO_METADATA)

    def mutate_payload(self, record: Record) -> Record:
        fields = dict(record.fields)
        fields["text"] = fields["text"] + " [agmi-tampered]"
        return Record(seq=record.seq, fields=fields)

    def forge_record(self, template: Record) -> Record:
        return Record(seq=template.seq + 1, fields={
            "text": f"{SEED_TOKEN}forged: the limit is 999",
            "actorId": self._actor,
            "sessionId": SESSION,
        })

    # --- identity ---------------------------------------------------------

    def identity_of(self, record: Record) -> str:
        return record.fields.get("eventId") or ""

    def payload_of(self, record: Record) -> str:
        return record.fields.get("text") or ""

    def owner_of(self, record: Record) -> str | None:
        return record.fields.get("actorId")

    # --- the agent's read path --------------------------------------------

    def reload(self) -> None:
        # A managed store has no process to restart; the next read is a fresh
        # call to the service, which is what a restarted agent would make.
        self._control = None
        self._data = None
        self._clients()

    def verify(self) -> bool:
        """The agent's own read: ListEvents for its actor and session.
        AgentCore performs no integrity check on the way out, so this returns
        True whenever the service answers; a refusal would be the service
        failing closed."""
        self.verify_detail = None
        try:
            events = self._raw_events(self._actor)
        except Exception as exc:  # noqa: BLE001 - a raise is the service refusing
            self.verify_detail = f"{type(exc).__name__}: {exc}"[:160]
            return False
        self.verify_detail = f"ListEvents served {len(events)} events, no error"
        return True
