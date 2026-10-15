# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Surgical DevOps G7 authorization-store adapter.

Measured target: ``bonushora/surgical-dev-ops`` at commit
``f267cf38b0ac321b6361602973b4d34b5c043e1c`` with Node 24.18.0.

Legitimate records are claims written with the real SDO claim API.  Integrity
verification is the real current-authority read API, including its expected
``physicalWorkspaceIdentity``.  Only the JSON envelopes inside G7 are exposed
to AGMI's raw attack hooks.  SDO's signing identity and monotonic witness are
siblings of G7 and are never modified by T1--T8.

For T9, ``snapshot_store`` copies only G7.  ``append_genuine`` uses the claim
API, advancing both G7 and the independent witness.  Restoring the snapshot
replaces only G7, deliberately leaving that newer witness in place.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from agmi.adapters.base import MemoryAdapter, Record

EXPECTED_SDO_COMMIT = "f267cf38b0ac321b6361602973b4d34b5c043e1c"
EXPECTED_NODE_VERSION = "v24.18.0"
EXPECTED_SDO_VERSION = "2.6.0-rc.6"
BRIDGE = Path(__file__).resolve().parents[1] / "bridges" / "surgical_devops_bridge.js"


@dataclass
class _LocatedRecord(Record):
    """Raw record together with the concrete G7 file it was read from."""

    storage_path: Path


def surgical_devops_repo() -> str | None:
    """Configured SDO checkout, or ``None`` when the optional row is off."""
    return os.environ.get("AGMI_SDO_REPO") or None


def _tree_digest(path: Path) -> str:
    digest = hashlib.sha256()
    if not path.exists():
        return "missing"
    paths = [path] if path.is_file() else sorted(p for p in path.rglob("*") if p.is_file())
    for item in paths:
        digest.update(str(item.relative_to(path.parent)).encode())
        digest.update(b"\0")
        digest.update(item.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


class SurgicalDevOpsAdapter(MemoryAdapter):
    name = "surgical-devops-g7"
    detection_point = "read"
    supports_replay = True
    supports_metadata = True
    supports_snapshot = True

    def __init__(self, sdo_repo: str | None = None):
        configured = sdo_repo or surgical_devops_repo()
        if not configured:
            raise RuntimeError("AGMI_SDO_REPO is not set")
        self.sdo_repo = str(Path(configured).resolve(strict=True))
        self._root: Path | None = None
        self._primary_root: Path | None = None
        self._other_root: Path | None = None
        self._primary_workspace: Path | None = None
        self._other_workspace: Path | None = None
        self._primary_identity: str | None = None
        self._other_identity: str | None = None
        self._primary_fingerprints: list[str] = []
        self._other_fingerprints: list[str] = []
        self._next_primary = 0
        self._snapshot_tokens: list[Path] = []
        self.pin = self._bridge("probe")

    def measured_on(self) -> str:
        return (f"surgical-dev-ops {EXPECTED_SDO_VERSION} at "
                f"{EXPECTED_SDO_COMMIT[:7]}, Node {EXPECTED_NODE_VERSION.removeprefix('v')}")

    def _bridge(self, action: str, **payload):
        request = {"action": action, "sdoRepo": self.sdo_repo, **payload}
        env = os.environ.copy()
        env["NODE_TEST_CONTEXT"] = "agmi-surgical-devops"
        result = subprocess.run(
            ["node", str(BRIDGE)], input=json.dumps(request), text=True,
            capture_output=True, env=env, timeout=20, check=False,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            raise RuntimeError(f"Surgical DevOps bridge failed: {detail}")
        try:
            response = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Surgical DevOps bridge returned invalid JSON: {result.stdout!r}") from exc
        if response.get("ok") is not True:
            raise RuntimeError(f"Surgical DevOps bridge rejected {action}")
        return response["result"]

    @staticmethod
    def _state_root(context_root: Path) -> Path:
        return context_root / "g7"

    @staticmethod
    def _workspace(context_root: Path) -> Path:
        return context_root / "workspace"

    def setup(self) -> None:
        self._root = Path(tempfile.mkdtemp(prefix="agmi-sdo-g7-"))
        primary = self._root / "primary"
        other = self._root / "other"
        self._primary_root = self._state_root(primary)
        self._other_root = self._state_root(other)
        self._primary_workspace = self._workspace(primary)
        self._other_workspace = self._workspace(other)
        for directory in (self._primary_root, self._other_root,
                          self._primary_workspace, self._other_workspace):
            directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        self._primary_identity = self._bridge(
            "observe", workspaceRoot=str(self._primary_workspace)
        )["physicalWorkspaceIdentity"]
        self._other_identity = self._bridge(
            "observe", workspaceRoot=str(self._other_workspace)
        )["physicalWorkspaceIdentity"]
        self._primary_fingerprints = []
        self._other_fingerprints = []
        self._next_primary = 0
        self._snapshot_tokens = []
        self.verify_detail = None

    def teardown(self) -> None:
        if self._root:
            shutil.rmtree(self._root, ignore_errors=True)
        for token in self._snapshot_tokens:
            shutil.rmtree(token, ignore_errors=True)
        self._root = None
        self._snapshot_tokens = []

    def _seed_context(self, *, state_root: Path, workspace: Path,
                      context_label: str, count: int, start_index: int) -> list[str]:
        records = self._bridge(
            "seed", stateRoot=str(state_root), workspaceRoot=str(workspace),
            contextLabel=context_label, count=count, startIndex=start_index,
        )
        return [item["claim"]["authorizationFingerprint"] for item in records]

    def seed(self, n: int) -> None:
        # Pre-seed both genuine contexts through SDO.  CrossContextReplayAttack
        # calls seed_other() later; it becomes an idempotent assertion, so the
        # T6 attack step itself changes only primary G7.
        self._primary_fingerprints = self._seed_context(
            state_root=self._primary_root, workspace=self._primary_workspace,
            context_label="primary", count=n, start_index=0,
        )
        self._other_fingerprints = self._seed_context(
            state_root=self._other_root, workspace=self._other_workspace,
            context_label="other", count=n, start_index=0,
        )
        self._next_primary = n

    def _ordered_paths(self, state_root: Path, known: list[str]) -> list[Path]:
        by_name = {p.stem: p for p in state_root.glob("*.json") if p.is_file()}
        ordered = [by_name.pop(fingerprint) for fingerprint in known if fingerprint in by_name]
        ordered.extend(by_name[name] for name in sorted(by_name))
        return ordered

    def _records(self, state_root: Path, known: list[str]) -> list[Record]:
        records = []
        for seq, target in enumerate(self._ordered_paths(state_root, known)):
            envelope_bytes = target.read_bytes()
            records.append(_LocatedRecord(seq=seq, fields={
                "filename": target.name,
                "envelope": json.loads(envelope_bytes),
                "envelopeBytes": envelope_bytes,
            }, storage_path=target.resolve(strict=True)))
        return records

    def read_all_raw(self) -> list[Record]:
        return self._records(self._primary_root, self._primary_fingerprints)

    def read_other_raw(self) -> list[Record]:
        return self._records(self._other_root, self._other_fingerprints)

    def _path_at(self, seq: int) -> Path | None:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise TypeError("G7 position must be an integer")
        paths = self._ordered_paths(self._primary_root, self._primary_fingerprints)
        return paths[seq] if 0 <= seq < len(paths) else None

    def write_raw(self, record: Record) -> None:
        target = self._path_at(record.seq)
        if target is None:
            filename = record.fields.get("filename")
            if not isinstance(filename, str) or not filename.endswith(".json"):
                raise RuntimeError("forged G7 record has no safe JSON filename")
            target = self._primary_root / filename
        target.write_text(
            json.dumps(record.fields["envelope"], indent=2) + "\n", encoding="utf-8"
        )
        target.chmod(0o600)

    def delete_raw(self, seq: int) -> None:
        """Delete one G7 record by position, rejecting every invalid position."""
        target = self._path_at(seq)
        if target is None:
            raise IndexError(f"G7 position out of range: {seq}")
        target.unlink()

    def reload(self) -> None:
        # Every bridge invocation starts a fresh Node process and re-requires
        # SDO, so verify() below is already a process-style reopen.
        return None

    def verify(self) -> bool:
        self.verify_detail = None
        result = self._bridge(
            "verify", stateRoot=str(self._primary_root),
            authorizationFingerprints=self._primary_fingerprints,
            physicalWorkspaceIdentity=self._primary_identity,
        )
        if not result["intact"]:
            self.verify_detail = result["detail"]
            return False
        return True

    def mutate_payload(self, record: Record) -> Record:
        record.fields["envelope"]["payload"]["target"] += ".tampered"
        return record

    def forge_record(self, template: Record) -> Record:
        forged = Record(seq=template.seq + 1, fields=copy.deepcopy(template.fields))
        forged.fields["filename"] = hashlib.sha256(b"agmi-sdo-forged-slot").hexdigest() + ".json"
        forged.fields["envelope"]["payload"]["target"] += ".forged"
        return forged

    def seed_other(self, n: int) -> None:
        if len(self._other_fingerprints) != n:
            raise RuntimeError("second SDO context was not pre-seeded exactly")

    def replay_onto(self, victim_seq: int, donor: Record) -> None:
        target = self._path_at(victim_seq)
        if target is None:
            raise RuntimeError("no G7 victim at that position")
        # Copy the genuine donor envelope byte-for-byte.  The target filename
        # is the victim slot identity; no signed field is rewritten to make the
        # donor appear to belong to the primary fixture.
        target.write_bytes(donor.fields["envelopeBytes"])
        target.chmod(0o600)

    def identity_of(self, record: Record) -> str:
        return record.fields["filename"]

    def payload_of(self, record: Record) -> str:
        payload = record.fields["envelope"]["payload"]
        return json.dumps({
            "operationId": payload["operationId"],
            "target": payload["target"],
            "beforeSha256": payload["beforeSha256"],
            "replacementSha256": payload["replacementSha256"],
        }, sort_keys=True)

    def owner_of(self, record: Record) -> str | None:
        # C3 asks which context owns the slot, not which context the replayed
        # envelope claims.  Derive that context from the verified G7 location
        # the record was actually read from; never accept an identity stamped
        # into the record at read time.
        location = getattr(record, "storage_path", None)
        if not isinstance(location, Path):
            raise RuntimeError("G7 record has no verifiable storage location")
        if location.is_symlink() or not location.is_file():
            raise RuntimeError("G7 record storage location is missing or unsafe")
        resolved = location.resolve(strict=True)
        filename = record.fields.get("filename")
        if not isinstance(filename, str) or resolved.name != filename:
            raise RuntimeError("G7 record filename does not match its storage location")
        envelope_bytes = record.fields.get("envelopeBytes")
        if not isinstance(envelope_bytes, bytes) or resolved.read_bytes() != envelope_bytes:
            raise RuntimeError("G7 record bytes do not match its storage location")
        roots = {
            self._primary_root.resolve(strict=True),
            self._other_root.resolve(strict=True),
        }
        if resolved.parent not in roots:
            raise RuntimeError("G7 record storage location is outside a measured context")
        return str(resolved.parent)

    def read_meta(self, seq: int) -> dict:
        record = self.read_all_raw()[seq]
        return copy.deepcopy({
            key: value for key, value in record.fields["envelope"].items()
            if key != "payload"
        })

    def write_meta(self, seq: int, meta: dict) -> None:
        """Persist exactly ``meta`` as envelope metadata, preserving content."""
        if not isinstance(meta, dict):
            raise TypeError("G7 metadata must be a dictionary")
        record = self.read_all_raw()[seq]
        payload = record.fields["envelope"]["payload"]
        if "physicalWorkspaceIdentity" in meta:
            payload["physicalWorkspaceIdentity"] = meta["physicalWorkspaceIdentity"]
        record.fields["envelope"] = copy.deepcopy(meta)
        record.fields["envelope"]["payload"] = payload
        self.write_raw(record)

    def snapshot_store(self) -> object:
        token = Path(tempfile.mkdtemp(prefix="agmi-sdo-g7-snapshot-")) / "g7"
        shutil.copytree(self._primary_root, token)
        self._snapshot_tokens.append(token.parent)
        return str(token)

    def restore_store(self, token: object) -> None:
        source = Path(str(token))
        shutil.rmtree(self._primary_root)
        shutil.copytree(source, self._primary_root)

    def append_genuine(self) -> None:
        fingerprints = self._seed_context(
            state_root=self._primary_root, workspace=self._primary_workspace,
            context_label="primary", count=1, start_index=self._next_primary,
        )
        self._primary_fingerprints.extend(fingerprints)
        self._next_primary += 1

    def artifact_fingerprints(self) -> dict[str, str]:
        """Test evidence that identifies G7 and every off-store artifact."""
        context = Path(str(self._primary_root) + ".sdo-store-integrity-context.json")
        parent = self._primary_root.parent
        return {
            "g7": _tree_digest(self._primary_root),
            "context": _tree_digest(context),
            "identity": _tree_digest(parent / ".natural-development-store-integrity-identity"),
            "witness": _tree_digest(parent / ".natural-development-store-integrity-witness"),
        }
