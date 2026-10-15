# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Template adapter. Copy this file, rename it, and work through the TODOs.

Read docs/adding-a-row.md first; it has the five questions to answer before
any of this makes sense.

The docstring of your adapter is not decoration. It is where the row's
attacker model lives, and it is what a reader checks the cells against. Say
what the store is, what one record is, where the attacker stands, what the
read path is, and what is pinned. Where something is n/a, say why in the
store's own terms.

This file is not a row. It is skipped by the runner and by the tests.
"""

from __future__ import annotations

from agmi.adapters.base import MemoryAdapter, Record


class TemplateAdapter(MemoryAdapter):
    """TODO: one line on what this store is and how it is read back."""

    #: Scorecard label. Lower case, hyphenated, and specific enough that a
    #: second configuration of the same store gets its own obvious name:
    #: "yourstore-default" and "yourstore+anchor" rather than "yourstore-2".
    name = "yourstore"

    #: Which of the optional attack families this store can express. Setting
    #: one to False is a claim that the edit cannot apply here, and the cell
    #: will say n/a, so it needs the reason in the docstring.
    supports_replay = True      # T6 cross-context replay, T7 rollback replay
    supports_metadata = True    # T8 metadata tamper
    supports_snapshot = True    # T9 whole-store rollback

    #: "read" if the store notices before serving memory to the agent,
    #: "audit" if it only notices in a separate pass the operator runs.
    #: Be honest here. An audit-only store is a legitimate design and the
    #: scorecard shows it as such; claiming "read" for a check that runs
    #: later is the one thing that makes a row worthless.
    detection_point = "read"

    @staticmethod
    def measured_on() -> str:
        """Version and commit, exactly as the row will print it."""
        raise NotImplementedError("TODO: e.g. 'yourstore 1.2.3 at abc1234'")

    # --- lifecycle ----------------------------------------------------------

    def setup(self) -> None:
        """Fresh, empty store. A temp directory or a fresh database."""
        raise NotImplementedError

    def teardown(self) -> None:
        """Remove whatever setup() made. Must not raise if already gone."""
        raise NotImplementedError

    # --- the agent's write path ---------------------------------------------

    def seed(self, n: int) -> None:
        """Write n records through the store's own public API.

        Never write them to the raw store directly. Signatures, digests and
        chains have to be genuine, or every later refusal is just the store
        rejecting something the adapter built wrong.

        Give each record a distinct value. If two records can carry the same
        text, a crossed or replayed record cannot be distinguished from a
        coincidence and the landed check will refuse to score T6.
        """
        raise NotImplementedError

    def seed_other(self, n: int) -> None:
        """A second context: another user, session, tenant or namespace.

        Its values must not overlap with seed()'s. If seed() writes "the
        limit is 50", this writes "the quota is 70". T6 moves a record from
        here into the first context and the check has to be able to tell.
        """
        raise NotImplementedError

    def append_genuine(self) -> None:
        """One more genuine record, written through the API as seed() does.

        Used by T9: snapshot, append this, roll back, and see whether the
        store notices that the newest genuine record has vanished.
        """
        raise NotImplementedError

    # --- reading the raw store ----------------------------------------------

    def read_all_raw(self) -> list[Record]:
        """Every record as it sits in the store, in the order written.

        `Record.seq` is the position. `Record.fields` is the store's own
        shape for that record.

        Keep adapter bookkeeping out of `fields`. The guard fingerprints the
        whole dict, so a position index or a cached path in there makes an
        unrelated record look changed the moment anything is deleted.
        """
        raise NotImplementedError

    def read_other_raw(self) -> list[Record]:
        """The same, for the second context."""
        raise NotImplementedError

    # --- the attacker's edits -----------------------------------------------

    def write_raw(self, record: Record) -> None:
        """Write a record back to the raw store, beneath the store's API.

        This is the attacker, so bypass every validation the store would
        normally apply. If the store writes the same record in two places,
        write both: an attacker rewriting the store rewrites what is there.

        Address the slot by `record.seq` rather than by a key inside the
        record, so T4 reordering is a real swap rather than a no-op.
        """
        raise NotImplementedError

    def delete_raw(self, seq: int) -> None:
        """Remove the record at that position.

        Raise IndexError if there is nothing there. Returning quietly turns a
        failed attack into an apparent pass.
        """
        raise NotImplementedError

    def mutate_payload(self, record: Record) -> Record:
        """Return a copy with its content changed, nothing else touched.

        Deep-copy first. Mutating the record in place corrupts the before
        snapshot the guard compares against.
        """
        raise NotImplementedError

    def forge_record(self, template: Record) -> Record:
        """A new record the store never wrote, shaped like a real one.

        Give it whatever an attacker could compute without a key. A digest is
        computable; a signature is not. Forging the parts the attacker could
        not produce would understate the store.
        """
        raise NotImplementedError

    def replay_onto(self, victim_seq: int, donor: Record) -> None:
        """Put a genuine record from the other context into this position.

        The donor is untouched and correctly signed. The question is whether
        the store notices it is in the wrong place.
        """
        raise NotImplementedError

    # --- metadata (T8) -------------------------------------------------------

    def read_meta(self, seq: int) -> dict:
        """The record's metadata: owner, source, timestamps, flags."""
        raise NotImplementedError

    def write_meta(self, seq: int, meta: dict) -> None:
        """Write metadata back verbatim.

        Write exactly what you are handed. Branching on the contents, or
        rejecting a value because it looks like an attack, means the adapter
        is doing the store's job and the cell measures the adapter.
        """
        raise NotImplementedError

    # --- identity, payload, owner -------------------------------------------

    def identity_of(self, record: Record) -> str:
        """Stable identity: primary key, filename, hash, sequence number."""
        raise NotImplementedError

    def payload_of(self, record: Record) -> str:
        """The content an agent would act on, as text."""
        raise NotImplementedError

    def owner_of(self, record: Record) -> str | None:
        """Which context this record belongs to, derived from where it sits.

        Use the storage location: the file it was read from, the table, the
        namespace. Never a field inside the record. An attacker who can write
        records can write that field, and then a moved record claims to
        belong exactly where it was put.

        Return None only if the store genuinely has no notion of context,
        which makes T6 n/a and needs saying in the docstring.
        """
        raise NotImplementedError

    # --- whole-store rollback (T9) ------------------------------------------

    def snapshot_store(self):
        """An opaque copy of the entire store. `self._copy_store(path)` helps."""
        raise NotImplementedError

    def restore_store(self, token) -> None:
        """Put the store back to that copy. `self._restore_store(token, path)`.

        This is a rollback to a genuine earlier state, not tampering. Every
        byte is something the store itself wrote. That is what makes T9 hard:
        there is nothing malformed to find.
        """
        raise NotImplementedError

    # --- the read path -------------------------------------------------------

    def reload(self) -> None:
        """Simulate a restart: drop caches, reopen, start a fresh process.

        A store that only holds its chain in memory looks perfect until this
        runs, so this is where a lot of rows are decided.
        """
        raise NotImplementedError

    def verify(self) -> bool:
        """What the store itself says when the agent reads its memory.

        True means it served the memory without complaint. False means it
        refused, raised or reported a problem.

        Set `self.verify_detail` to the store's own words: the exception
        type and message, or the failing check. That string goes in the cell
        and is what lets a reader tell a deliberate refusal from a crash.

        Never check the data yourself. If the store hands back a tampered
        record and says nothing, this returns True and the cell is accepted.
        That is the measurement.
        """
        self.verify_detail = None
        raise NotImplementedError
