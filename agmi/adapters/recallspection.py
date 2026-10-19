# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Recallspection / ExactMemory, an exact-memory layer for agents.

Submitted for measurement by its maintainer, Eliam Raell. The measured unit
is the standalone core, `exactmemory.recallspection`, which the product repo
consumes.

The store on disk is three files. `memory.db` is a 32-byte HMAC over a
zlib-compressed JSON container holding every record, each record carrying its
own HMAC tag as well. `transparency.log` is a hash chain, one entry per save,
holding the counter, the high-water version and the digest of the container.
An anchor holds the same high-water mark again, and where that anchor lives
is the whole question this row answers.

The attacker reads and writes the store. He holds neither the container key
nor the record keys, so he cannot forge either MAC; what he can do is edit,
delete, reorder, forge and replay entries inside the container, and put the
whole directory back to an earlier copy of itself.

Two rows, differing in one thing:

  recallspection-exact          the default the product ships: the anchor is
                                a file beside memory.db on the same disk, so
                                an attacker with disk write rolls the anchor
                                back along with everything else
  recallspection-exact+anchor   the anchor lives off the store, on a separate
                                volume or a remote service, where this
                                attacker cannot reach it

The maintainer predicted the two differ on T9 and only on T9, and asked for
the default row to be published rather than the anchored one alone.

Read path: a fresh `ExactMemory`, `load(path, keys)`, then
`get_with_status(key)` for every record, which is what the agent's own read
does. `load` raises `TamperError` with "Container MAC failed" when the
container has been edited, and `RollbackError` with "Log rollback vs remote
anchor" when the anchor has seen a later version than the store carries.
Those are two different exception types and the row keeps them apart: T9
being caught by a different check from T1 to T8 is the point of the row.

Needs AGMI_RECALLSPECTION_REPO pointing at a checkout of the core, since it
is not published on PyPI. Pinned to commit c62ef7a, core version 3.2.0.
Python 3.10 or later, standard library only.

One thing worth stating for anyone reading both repos: at the commits the
maintainer pinned, the product vendors its own copy of the core at version
3.0.1 while the standalone core is 3.2.0, and a container written by one
raises `FormatVersionError` in the other. This row measures the standalone
core, which is the unit he named.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

from agmi.adapters.base import MemoryAdapter, Record

PIN = "c62ef7ada64928418a7e5d3251a6b65d005599b6"
CORE_VERSION = "3.2.0"
CTX, OTHER = "a", "b"
STORE_FILE = "memory.db"
LOG_FILE = "transparency.log"
ANCHOR_FILE = "anchor.json"
SEED_TOKEN = "agmi-seed-"
OTHER_TOKEN = "agmi-other-"

#: The same keys serve both contexts, so a record replayed across them is
#: genuine at record level and only the context binding can catch it.
KEYS = {
    "k1": b"agmi-record-key-32-bytes-long-01",
    "container": b"agmi-container-key-32-bytes-0001",
}


def recallspection_repo() -> str | None:
    """The configured checkout of the core, or None when the row is off."""
    path = os.environ.get("AGMI_RECALLSPECTION_REPO")
    return os.path.abspath(os.path.expanduser(path)) if path else None


def _import_core():
    repo = recallspection_repo()
    if not repo:
        raise RuntimeError("AGMI_RECALLSPECTION_REPO is not set")
    if repo not in sys.path:
        sys.path.insert(0, repo)
    import exactmemory_recallspection as core
    return core


def installed_commit() -> str:
    repo = recallspection_repo()
    proc = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"],
                          capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        raise RuntimeError(f"not a git checkout: {proc.stderr.strip()[-200:]}")
    return proc.stdout.strip()


class _FileAnchor:
    """The product's FileAnchor, reimplemented against the core's interface.

    Monotonic: a later save raises the mark, an earlier one is ignored. Where
    the file sits is what separates the two rows.
    """

    def __init__(self, path: Path):
        self.path = Path(path)

    def anchor(self, chain_hash: str, max_version: int, container_hash: str) -> None:
        current = self.get_latest()
        if current and max_version <= current.get("max_version", 0):
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"max_version": max_version,
                                         "chain_hash": chain_hash,
                                         "container_hash": container_hash},
                                        sort_keys=True), encoding="utf-8")

    def get_latest(self):
        if not self.path.exists():
            return None
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001 - an unreadable anchor is no anchor
            return None

    def verify(self, chain_hash: str) -> bool:
        current = self.get_latest()
        return current is not None and current.get("chain_hash") == chain_hash


class RecallspectionAdapter(MemoryAdapter):
    """ExactMemory with the anchor on the same disk as the store."""

    name = "recallspection-exact"
    supports_replay = True
    supports_metadata = True
    supports_snapshot = True
    detection_point = "read"

    #: False puts the anchor beside memory.db, where this attacker reaches it.
    anchor_off_store = False

    def __init__(self):
        self._core = _import_core()
        found = installed_commit()
        if found != PIN:
            raise RuntimeError(f"checkout at {found[:7]}, pinned {PIN[:7]}; re-measure before re-pinning")
        if self._core.ExactMemory.VERSION != CORE_VERSION:
            raise RuntimeError(f"core {self._core.ExactMemory.VERSION}, pinned {CORE_VERSION}")
        self._root: Path | None = None

    @staticmethod
    def measured_on() -> str:
        return f"exactmemory.recallspection {CORE_VERSION} at {PIN[:7]}"

    # --- layout ------------------------------------------------------------

    def _dir(self, ctx: str) -> Path:
        return self._root / f"store-{ctx}"

    def _store(self, ctx: str) -> Path:
        return self._dir(ctx) / STORE_FILE

    def _log(self, ctx: str) -> Path:
        return self._dir(ctx) / LOG_FILE

    def _anchor_path(self, ctx: str) -> Path:
        if self.anchor_off_store:
            return self._root / "anchors" / f"{ctx}-{ANCHOR_FILE}"
        return self._dir(ctx) / ANCHOR_FILE

    def _memory(self, ctx: str):
        return self._core.ExactMemory(
            keys=dict(KEYS), container_key_id="container",
            log_path=str(self._log(ctx)),
            remote_anchor=_FileAnchor(self._anchor_path(ctx)),
        )

    def setup(self) -> None:
        self._root = Path(tempfile.mkdtemp(prefix="agmi-recallspection-"))
        for ctx in (CTX, OTHER):
            self._dir(ctx).mkdir(parents=True)

    def teardown(self) -> None:
        if self._root:
            shutil.rmtree(self._root, ignore_errors=True)
        self._root = None

    # --- the agent's write path --------------------------------------------

    def _value(self, token: str, i: int) -> str:
        # The two contexts never share a value, so a donor's content landing
        # in the first context can only have come from the second.
        return (f"the limit is {50 + i}" if token == SEED_TOKEN
                else f"the quota is {90 + i}")

    def _seed_ctx(self, ctx: str, token: str, n: int) -> None:
        memory = self._memory(ctx)
        if self._store(ctx).exists():
            memory.load(str(self._store(ctx)), dict(KEYS))
        for i in range(n):
            status = memory.put(f"{token}{i}", self._value(token, i),
                                key_id="k1", source="system")
            if status != "ok":
                raise RuntimeError(f"put returned {status!r} for {token}{i}")
        memory.save(str(self._store(ctx)))

    def seed(self, n: int) -> None:
        self._seed_ctx(CTX, SEED_TOKEN, n)

    def seed_other(self, n: int) -> None:
        self._seed_ctx(OTHER, OTHER_TOKEN, n)

    # --- raw access, beneath the API ---------------------------------------

    def _read_container(self, ctx: str) -> tuple[bytes, dict]:
        blob = self._store(ctx).read_bytes()
        return blob[:32], json.loads(zlib.decompress(blob[32:]))

    def _write_container(self, ctx: str, mac: bytes, container: dict) -> None:
        raw = json.dumps(container, sort_keys=True, separators=(",", ":")).encode()
        # The original MAC is kept: this attacker cannot forge a new one.
        self._store(ctx).write_bytes(mac + zlib.compress(raw, 6))

    def _records(self, ctx: str) -> list[Record]:
        _mac, container = self._read_container(ctx)
        return [Record(seq=i, fields={"ctx": ctx, "key": key, "rec": rec, "tag": tag_hex})
                for i, (key, rec, tag_hex) in enumerate(container["entries"])]

    def read_all_raw(self) -> list[Record]:
        return self._records(CTX)

    def read_other_raw(self) -> list[Record]:
        return self._records(OTHER)

    def _entry_of(self, record: Record) -> list:
        return [record.fields["key"], record.fields["rec"], record.fields["tag"]]

    def write_raw(self, record: Record) -> None:
        mac, container = self._read_container(CTX)
        entries = container["entries"]
        if record.seq < len(entries):
            entries[record.seq] = self._entry_of(record)
        else:
            entries.append(self._entry_of(record))
        self._write_container(CTX, mac, container)

    def delete_raw(self, seq: int) -> None:
        mac, container = self._read_container(CTX)
        entries = container["entries"]
        if seq < 0 or seq >= len(entries):
            raise IndexError(f"no entry at position {seq}")
        del entries[seq]
        self._write_container(CTX, mac, container)

    def replay_onto(self, victim_seq: int, donor: Record) -> None:
        mac, container = self._read_container(CTX)
        entries = container["entries"]
        victim_key = entries[victim_seq][0]
        donor_rec = dict(donor.fields["rec"])
        # The victim's slot keeps its own key; the donor's content and its
        # genuine record tag come across from the other context.
        donor_rec["key"] = victim_key
        entries[victim_seq] = [victim_key, donor_rec, donor.fields["tag"]]
        self._write_container(CTX, mac, container)

    def mutate_payload(self, record: Record) -> Record:
        fields = {**record.fields, "rec": dict(record.fields["rec"])}
        fields["rec"]["value"] = f"{fields['rec']['value']} [agmi-tampered]"
        return Record(seq=record.seq, fields=fields)

    def forge_record(self, template: Record) -> Record:
        rec = dict(template.fields["rec"])
        rec.update({"key": f"{SEED_TOKEN}forged", "value": "the limit is 999",
                    "nonce": secrets.token_hex(16)})
        return Record(seq=template.seq + 1,
                      fields={"ctx": CTX, "key": rec["key"], "rec": rec,
                              "tag": secrets.token_hex(32)})

    # --- metadata -----------------------------------------------------------

    def read_meta(self, seq: int) -> dict:
        rec = self._records(CTX)[seq].fields["rec"]
        return {k: v for k, v in rec.items() if k not in ("key", "value")}

    def write_meta(self, seq: int, meta: dict) -> None:
        record = self._records(CTX)[seq]
        rec = {"key": record.fields["rec"]["key"],
               "value": record.fields["rec"]["value"], **meta}
        record.fields["rec"] = rec
        self.write_raw(record)

    # --- identity -----------------------------------------------------------

    def identity_of(self, record: Record) -> str:
        return record.fields["key"]

    def payload_of(self, record: Record) -> str:
        return record.fields["rec"].get("value")

    def owner_of(self, record: Record) -> str | None:
        # The context is the store directory the record was read from, not
        # anything the record claims about itself.
        return str(self._dir(record.fields["ctx"]).resolve())

    # --- T9 -----------------------------------------------------------------

    def snapshot_store(self):
        return self._copy_store(self._dir(CTX))

    def restore_store(self, token) -> None:
        self._restore_store(token, self._dir(CTX))
        shutil.rmtree(Path(token).parent, ignore_errors=True)

    def append_genuine(self) -> None:
        n = len(self._records(CTX))
        memory = self._memory(CTX)
        memory.load(str(self._store(CTX)), dict(KEYS))
        if memory.put(f"{SEED_TOKEN}{n}", self._value(SEED_TOKEN, n),
                      key_id="k1", source="system") != "ok":
            raise RuntimeError("the genuine append was rejected")
        memory.save(str(self._store(CTX)))

    # --- T10: the core's own erasure, if it offers one -----------------------
    supports_erase = True

    def erase_genuine(self) -> list[str]:
        """Erase the newest record through ExactMemory's own API. The core
        is measured at a pinned commit; if that revision exposes no erasure
        operation the cell reads not evaluable with that reason, since
        deleting the record from the container by hand would be an attacker
        edit, not the tool's erasure."""
        n = len(self._records(CTX))
        memory = self._memory(CTX)
        memory.load(str(self._store(CTX)), dict(KEYS))
        erase = next((getattr(memory, m) for m in ("delete", "remove", "forget", "erase")
                      if callable(getattr(memory, m, None))), None)
        if erase is None:
            raise RuntimeError("ExactMemory at the pinned revision exposes no erasure operation "
                               "(no delete, remove, forget or erase method)")
        key = f"{SEED_TOKEN}{n - 1}"
        result = erase(key)
        if result not in (None, True, "ok"):
            raise RuntimeError(f"ExactMemory refused to erase {key!r}: {result!r}")
        memory.save(str(self._store(CTX)))
        return [key]

    # --- the agent's read path ----------------------------------------------

    def reload(self) -> None:
        # Every read builds a fresh ExactMemory and loads from disk, which is
        # what a restarted agent does.
        return None

    def verify(self) -> bool:
        """Load the store the way the agent does, then read every record."""
        self.verify_detail = None
        memory = self._memory(CTX)
        try:
            memory.load(str(self._store(CTX)), dict(KEYS))
        except self._core.ExactMemoryError as exc:
            self.verify_detail = f"{type(exc).__name__}: {exc}"[:200]
            return False
        bad = []
        for key in list(memory.store):
            _value, status = memory.get_with_status(key)
            if status != "ok":
                bad.append(f"{key}: {status}")
        if bad:
            self.verify_detail = "read path reported " + ", ".join(sorted(bad)[:3])
            return False
        self.verify_detail = f"load succeeded, {len(memory.store)} records served ok"
        return True


class RecallspectionAnchoredAdapter(RecallspectionAdapter):
    """ExactMemory with the anchor off the store, where this attacker cannot
    reach it. The configuration the maintainer recommends for deployment."""

    name = "recallspection-exact+anchor"
    anchor_off_store = True
