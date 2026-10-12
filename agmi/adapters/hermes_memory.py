# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Hermes Agent: the agent's curated memory, MEMORY.md under its profile home.

Hermes Agent (PyPI `hermes-agent`, Nous Research) keeps the memory the model
carries between sessions as plain Markdown in the profile's home directory:
`memories/MEMORY.md`, entries joined by a line holding only `§`. The agent
writes it through its memory tool (`MemoryStore.add`), and reads it once at
startup: `load_from_disk()` parses the file, freezes a snapshot, and
`format_for_system_prompt("memory")` renders that snapshot as the MEMORY
block of the system prompt. Nothing re-reads the file mid-session, which is
why the read path measured here is the one the model actually sees.

Hermes makes no integrity claim for the file. It does scan every entry at
load time for prompt-injection and exfiltration patterns and replaces a
match in the snapshot with a `[BLOCKED: ...]` placeholder, keeping the raw
text in live state so the operator can still see and delete it. That is a
content filter: it judges what an entry says, never who changed it or
whether it is the entry the agent wrote. This row is in the group that
makes no claim, like the LangGraph checkpointers and OpenClaw.

Write path: `MemoryStore.add("memory", text)`, the function behind the
agent's memory tool, which scans the content, re-reads the file under a
lock and writes it back atomically.

Read path: a fresh Python process per read, which is a restart. The process
sets HERMES_HOME, builds a `MemoryStore`, calls `load_from_disk()` and
returns `format_for_system_prompt("memory")`, the block the model sees. A
read that raises, or one whose block carries a `[BLOCKED:` placeholder, is
Hermes refusing on the read path and scores "rejected"; a block that serves
the edited file is "accepted".

Second context for T6: a second Hermes profile, its own home directory with
its own `memories/MEMORY.md`. T6 copies one of that profile's genuine
entries over an entry in the first profile's file. T9 restores the first
profile's whole memories directory from a copy taken before one more
genuine entry was written through `add`.

T8 is not applicable: an entry is plain text with no owner, source or
timestamp field to change.

One Hermes behaviour shapes T7. `load_from_disk` de-duplicates entries with
`dict.fromkeys`, so when an older entry is copied over the newest, the two
copies collapse and the newest entry simply disappears from the system
prompt, with no warning and no error.

Hermes runs in a virtualenv of its own, named by AGMI_HERMES_PYTHON
(`pip install hermes-agent==0.19.0`), so its dependencies never meet agmi's;
the adapter refuses any other version.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from agmi.adapters.base import MemoryAdapter, Record

PIN = "0.19.0"
MEASURED_ON = f"hermes-agent {PIN} (PyPI)"
CTX, OTHER = "a", "b"
MEMORY_DIR = "memories"
MEMORY_FILE = "MEMORY.md"
ENTRY_DELIMITER = "\n§\n"

HELPER = r"""
import json, sys
ops = json.loads(sys.stdin.read())
out = []
from tools.memory_tool import MemoryStore
for op in ops:
    try:
        store = MemoryStore()
        store.load_from_disk()
        if op["op"] == "read":
            out.append({"ok": True,
                        "block": store.format_for_system_prompt("memory"),
                        "entries": list(store.memory_entries)})
        elif op["op"] == "add":
            r = store.add("memory", op["content"])
            out.append({"ok": bool(r.get("success")), "error": r.get("error")})
        else:
            out.append({"ok": False, "error": "unknown op"})
    except Exception as e:
        out.append({"ok": False, "error": "%s: %s" % (type(e).__name__, e)})
sys.stdout.write(json.dumps(out))
"""

VERSION_PROBE = (
    "import json;from importlib.metadata import version;"
    "print(json.dumps(version('hermes-agent')))"
)


def hermes_python() -> str:
    """The interpreter of the virtualenv Hermes is installed in."""
    path = os.environ.get("AGMI_HERMES_PYTHON")
    if not path:
        raise RuntimeError("AGMI_HERMES_PYTHON is not set (the python of a venv with hermes-agent installed)")
    # expanduser only: realpath would follow the venv's symlink to the base
    # interpreter and lose the venv, and with it hermes-agent.
    return os.path.abspath(os.path.expanduser(path))


def installed_version() -> str:
    proc = subprocess.run([hermes_python(), "-c", VERSION_PROBE],
                          capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        raise RuntimeError(f"hermes-agent not importable in that venv: {proc.stderr.strip()[-300:]}")
    return json.loads(proc.stdout.strip())


def _entry(ctx: str, i: int) -> str:
    return f"agmi-{ctx}-{i}: the limit is {40 + i}"


class HermesMemoryAdapter(MemoryAdapter):
    """Hermes MEMORY.md, read through the system-prompt snapshot."""

    name = "hermes-memory-md"
    supports_replay = True
    supports_metadata = False
    metadata_na_reason = ("not applicable: a Hermes memory entry is plain text with no owner, source or "
                          "timestamp field to change")
    supports_snapshot = True
    detection_point = "read"

    def __init__(self):
        self._root: str | None = None
        self._python = hermes_python()
        found = installed_version()
        if found != PIN:
            raise RuntimeError(f"hermes-agent {found} installed, pinned {PIN}; re-measure before re-pinning")
        self._helper: str | None = None

    @staticmethod
    def measured_on() -> str:
        return MEASURED_ON

    # --- lifecycle ---------------------------------------------------------

    def _home(self, ctx: str) -> Path:
        return Path(self._root) / f"hermes-home-{ctx}"

    def _dir(self, ctx: str) -> Path:
        return self._home(ctx) / MEMORY_DIR

    def _path(self, ctx: str) -> Path:
        return self._dir(ctx) / MEMORY_FILE

    def setup(self) -> None:
        self._root = tempfile.mkdtemp(prefix="agmi-hermes-")
        for ctx in (CTX, OTHER):
            self._dir(ctx).mkdir(parents=True)
            self._path(ctx).write_text("", encoding="utf-8")
        self._helper = str(Path(self._root) / "agmi-hermes-run.py")
        Path(self._helper).write_text(HELPER, encoding="utf-8")

    def teardown(self) -> None:
        if self._root:
            shutil.rmtree(self._root, ignore_errors=True)
        self._root = None

    # --- running Hermes in its own interpreter ------------------------------

    def _run(self, ctx: str, ops: list[dict]) -> list[dict]:
        env = dict(os.environ, HERMES_HOME=str(self._home(ctx)))
        env.pop("PYTHONPATH", None)
        proc = subprocess.run([self._python, self._helper], input=json.dumps(ops),
                              capture_output=True, text=True, timeout=300,
                              env=env, cwd=self._root)
        if proc.returncode != 0:
            raise RuntimeError(f"hermes python exited {proc.returncode}: {proc.stderr.strip()[-400:]}")
        return json.loads(proc.stdout)

    # --- the agent's write path: MemoryStore.add ----------------------------

    def _seed_ctx(self, ctx: str, n: int) -> None:
        results = self._run(ctx, [{"op": "add", "content": _entry(ctx, i)} for i in range(n)])
        for i, r in enumerate(results):
            if not r.get("ok"):
                raise RuntimeError(f"Hermes refused the seed entry {i}: {r.get('error')}")

    def seed(self, n: int) -> None:
        self._seed_ctx(CTX, n)

    def seed_other(self, n: int) -> None:
        self._seed_ctx(OTHER, n)

    # --- raw access, bypassing Hermes --------------------------------------

    def _entries(self, ctx: str) -> list[str]:
        raw = self._path(ctx).read_text(encoding="utf-8")
        if not raw.strip():
            return []
        return [e.strip() for e in raw.split(ENTRY_DELIMITER) if e.strip()]

    def _write_entries(self, ctx: str, entries: list[str]) -> None:
        self._path(ctx).write_text(ENTRY_DELIMITER.join(entries), encoding="utf-8")

    def _read_ctx(self, ctx: str) -> list[Record]:
        return [Record(seq=i, fields={"ctx": ctx, "entry": e})
                for i, e in enumerate(self._entries(ctx))]

    def read_all_raw(self) -> list[Record]:
        return self._read_ctx(CTX)

    def read_other_raw(self) -> list[Record]:
        return self._read_ctx(OTHER)

    def write_raw(self, record: Record) -> None:
        entries = self._entries(CTX)
        if record.seq < len(entries):
            entries[record.seq] = record.fields["entry"]
        else:
            entries.append(record.fields["entry"])
        self._write_entries(CTX, entries)

    def delete_raw(self, seq: int) -> None:
        entries = self._entries(CTX)
        del entries[seq]
        self._write_entries(CTX, entries)

    def replay_onto(self, victim_seq: int, donor: Record) -> None:
        entries = self._entries(CTX)
        entries[victim_seq] = donor.fields["entry"]
        self._write_entries(CTX, entries)

    def mutate_payload(self, record: Record) -> Record:
        record.fields["entry"] = record.fields["entry"] + " [TAMPERED]"
        return record

    def forge_record(self, template: Record) -> Record:
        return Record(seq=template.seq + 1,
                      fields={"ctx": CTX, "entry": "agmi-forged: the limit is 999"})

    # --- guard hooks (control C3) -----------------------------------------

    def identity_of(self, record):
        return f"{record.fields['ctx']}:{record.seq}"

    def payload_of(self, record):
        return record.fields["entry"]

    def owner_of(self, record):
        return record.fields["ctx"]

    # --- T9: the profile's whole memories directory rolls back --------------

    def snapshot_store(self):
        return self._copy_store(self._dir(CTX))

    def restore_store(self, token) -> None:
        self._restore_store(token, self._dir(CTX))
        shutil.rmtree(Path(token).parent, ignore_errors=True)

    def append_genuine(self) -> None:
        n = len(self._entries(CTX))
        results = self._run(CTX, [{"op": "add", "content": _entry(CTX, n)}])
        if not results[0].get("ok"):
            raise RuntimeError(f"Hermes refused the genuine append: {results[0].get('error')}")

    # --- the read path ------------------------------------------------------

    def read_served(self, ctx: str = CTX) -> str | None:
        """The MEMORY block Hermes puts in the system prompt, or None if it refused."""
        out = self._run(ctx, [{"op": "read"}])[0]
        if not out.get("ok"):
            return None
        return out.get("block") or ""

    def reload(self) -> None:
        # Every read is a fresh process, which is a restart.
        return None

    def verify(self) -> bool:
        self.verify_detail = None
        out = self._run(CTX, [{"op": "read"}])[0]
        if not out.get("ok"):
            self.verify_detail = out.get("error")
            return False
        block = out.get("block") or ""
        if "[BLOCKED:" in block:
            self.verify_detail = "an entry was replaced by a [BLOCKED: ...] placeholder at load"
            return False
        served = out.get("entries") or []
        on_disk = self._entries(CTX)
        same = "the edited file as written" if served == on_disk else "content that differs from the file"
        self.verify_detail = (f"the system prompt block carried {len(served)} entries, {same}, no error")
        return True
