# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""HDP, the token-by-reference store of draft-helixar-hdp-agentic-delegation-03.

Measured at the invitation of the draft's author, Siri (Helixar), who asked
for the reference implementation to be run through the method and for the
results to be posted to the IETF RATS list before anything was published.

The store is a `TokenStore`: `put`, `get` and `delete`, keyed by a reference.
A record is one stored token, holding the whole delegation chain to that
point. `storeToken` writes each token under two references at once, a version
4 UUID taken from the token's own header and a sha256 content digest, which
section 8.2 of -03 treats as two different things:

  content reference   the digest is recomputed on read and compared, so a
                      substituted token is refused before it is returned
  UUID reference      no such check on content. The UUID binds the token's
                      id and nothing else, so a differently-signed token
                      carrying the same token_id resolves; 8.2 calls this a
                      substitution point and steers implementers away from
                      it wherever the resolving party does not control the
                      store. This row's attacker holds no signing key, so
                      what reaches the read path here is caught by the
                      signature rather than by the reference

Storing each token under both references is the reference implementation's
default, not something the protocol requires.

Two rows, one variable: which reference the recipient holds. Everything else
is identical, same store, same attacker, same read path.

Read path: `resolveToken(store, reference)` followed by `verifyToken` with
the public key, which is what a recipient does before relying on the token.
A record is refused if either raises or if verification comes back invalid.

Attacker: holds the store and rewrites entries beneath the `TokenStore` API,
as a backing database, a mounted volume or process memory would allow, so
the write-once check in `put` is not in the way. No key.

One result on the UUID row needs stating rather than scoring, and the draft
says so itself. A UUID reference is write-once and names the first snapshot
stored; a later extension lives only under its own content digest. So a
recipient resolving by UUID sees the earliest snapshot by design, and a
rollback of the whole store cannot be distinguished from normal operation.
That cell is not a failure, it is a property, and 8.2 is explicit about it.

Needs AGMI_HDP_REPO pointing at a checkout of Helixar-AI/HDP with
`npm install` and a build run, and Node 22. Pinned to b753ba9, v0.2.2.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from agmi.adapters.base import MemoryAdapter, Record

PIN = "b753ba9"
HDP_VERSION = "0.2.2"
NODE_MAJOR = 22
CTX, OTHER = "a", "b"
BRIDGE = Path(__file__).resolve().parents[1] / "bridges" / "hdp_bridge.mjs"


def hdp_repo() -> str | None:
    path = os.environ.get("AGMI_HDP_REPO")
    return os.path.abspath(os.path.expanduser(path)) if path else None


class HdpTokenStoreAdapter(MemoryAdapter):
    """HDP tokens read back by their content-addressed reference."""

    name = "hdp-token-content-ref"
    supports_replay = True
    supports_metadata = True
    supports_snapshot = True
    detection_point = "read"

    #: Which reference the recipient holds; the only difference between rows.
    by_content_reference = True

    def __init__(self):
        repo = hdp_repo()
        if not repo:
            raise RuntimeError("AGMI_HDP_REPO is not set")
        self._repo = repo
        probe = self._bridge({"op": "probe"})
        if probe.get("major") != NODE_MAJOR:
            raise RuntimeError(f"Node {probe.get('node')}, pinned major {NODE_MAJOR}")
        head = subprocess.run(["git", "-C", repo, "rev-parse", "--short", "HEAD"],
                              capture_output=True, text=True, timeout=60).stdout.strip()
        if not PIN.startswith(head) and not head.startswith(PIN):
            raise RuntimeError(f"HDP checkout at {head}, pinned {PIN}; re-measure before re-pinning")
        self._root: str | None = None

    @staticmethod
    def measured_on() -> str:
        return f"@helixar_ai/hdp {HDP_VERSION} at {PIN}, Node {NODE_MAJOR}"

    # --- the bridge ---------------------------------------------------------

    def _bridge(self, payload: dict) -> dict:
        env = dict(os.environ, AGMI_HDP_REPO=self._repo)
        proc = subprocess.run(["node", str(BRIDGE)], input=json.dumps(payload),
                              capture_output=True, text=True, timeout=300, env=env)
        if proc.returncode != 0:
            raise RuntimeError(f"hdp bridge exited {proc.returncode}: {proc.stderr.strip()[-300:]}")
        return json.loads(proc.stdout)

    # --- lifecycle ----------------------------------------------------------

    def setup(self) -> None:
        self._root = tempfile.mkdtemp(prefix="agmi-hdp-")

    def teardown(self) -> None:
        if self._root:
            shutil.rmtree(self._root, ignore_errors=True)
        self._root = None

    def _store_file(self, ctx: str) -> Path:
        return Path(self._root) / f"store-{ctx}.json"

    def _ordered(self, ctx: str) -> list[list]:
        """The store as it sits on disk: reference and token, in the order the
        agent wrote them. A slot is a position, not a digest."""
        path = self._store_file(ctx)
        return json.loads(path.read_text()) if path.exists() else []

    def _write_ordered(self, ctx: str, ordered: list[list]) -> None:
        self._store_file(ctx).write_text(json.dumps(ordered, indent=1))

    # --- the agent's write path ---------------------------------------------

    def seed(self, n: int) -> None:
        out = self._bridge({"op": "seed", "dir": self._root, "ctx": CTX, "n": n})
        if not out.get("ok"):
            raise RuntimeError(f"seed failed: {out.get('error')}")

    def seed_other(self, n: int) -> None:
        out = self._bridge({"op": "seed", "dir": self._root, "ctx": OTHER, "n": n})
        if not out.get("ok"):
            raise RuntimeError(f"seed_other failed: {out.get('error')}")

    # --- records ------------------------------------------------------------

    def _is_content(self, ref: str) -> bool:
        return ref.startswith("sha256:")

    def _slots(self, ctx: str) -> list[int]:
        """Positions in the store holding this row's kind of reference."""
        return [i for i, (ref, _t) in enumerate(self._ordered(ctx))
                if self._is_content(ref) == self.by_content_reference]

    def _records(self, ctx: str) -> list[Record]:
        ordered = self._ordered(ctx)
        # The store position is the adapter's bookkeeping, never a field of
        # the record: a deletion shifts it, and the guard would read that as
        # every later record having changed.
        return [Record(seq=i, fields={"ctx": ctx, "ref": ordered[slot][0],
                                      "token": ordered[slot][1]})
                for i, slot in enumerate(self._slots(ctx))]

    def read_all_raw(self) -> list[Record]:
        return self._records(CTX)

    def read_other_raw(self) -> list[Record]:
        return self._records(OTHER)

    def _sibling(self, ordered: list[list], slot: int) -> int | None:
        """storeToken writes each token twice, under its UUID and its digest.
        An attacker rewriting the store rewrites both copies."""
        ref, token = ordered[slot]
        token_id = token["header"]["token_id"]
        for i, (other_ref, other) in enumerate(ordered):
            if i != slot and (other_ref == token_id
                              or other["header"]["token_id"] == token_id):
                return i
        return None

    # --- the attacker's edits -----------------------------------------------

    def write_raw(self, record: Record) -> None:
        ordered = self._ordered(CTX)
        slots = self._slots(CTX)
        token = record.fields["token"]
        if record.seq < len(slots):
            # The slot keeps its own reference and takes the new bytes, which
            # is what an attacker rewriting the store does.
            slot = slots[record.seq]
            sibling = self._sibling(ordered, slot)
            ordered[slot][1] = token
            if sibling is not None:
                ordered[sibling][1] = json.loads(json.dumps(token))
        else:
            ordered.append([record.fields["ref"], token])
        self._write_ordered(CTX, ordered)

    def delete_raw(self, seq: int) -> None:
        ordered = self._ordered(CTX)
        slots = self._slots(CTX)
        if seq < 0 or seq >= len(slots):
            raise IndexError(f"no entry at position {seq}")
        slot = slots[seq]
        drop = {slot, self._sibling(ordered, slot)} - {None}
        self._write_ordered(CTX, [e for i, e in enumerate(ordered) if i not in drop])

    def replay_onto(self, victim_seq: int, donor: Record) -> None:
        ordered = self._ordered(CTX)
        slot = self._slots(CTX)[victim_seq]
        donor_token = json.loads(json.dumps(donor.fields["token"]))
        sibling = self._sibling(ordered, slot)
        # The victim's slot keeps its own reference; the donor's genuine,
        # signed token from the other context arrives in it.
        ordered[slot][1] = donor_token
        if sibling is not None:
            ordered[sibling][1] = json.loads(json.dumps(donor_token))
        self._write_ordered(CTX, ordered)

    def mutate_payload(self, record: Record) -> Record:
        fields = json.loads(json.dumps(record.fields))
        fields["token"]["chain"][-1]["action_summary"] += " [agmi-tampered]"
        return Record(seq=record.seq, fields=fields)

    def forge_record(self, template: Record) -> Record:
        token = json.loads(json.dumps(template.fields["token"]))
        token["chain"][-1]["action_summary"] = "the limit is 999"
        token["header"]["token_id"] = "00000000-0000-4000-8000-00000000f0f0"
        # The attacker can compute a content digest; it needs no key, so the
        # forged entry arrives under a well-formed reference of either kind.
        ref = (self._bridge({"op": "contentref", "token": token})["reference"]
               if self.by_content_reference else token["header"]["token_id"])
        return Record(seq=template.seq + 1, fields={"ctx": CTX, "ref": ref, "token": token})

    # --- metadata -----------------------------------------------------------

    def read_meta(self, seq: int) -> dict:
        token = self._records(CTX)[seq].fields["token"]
        return {k: v for k, v in token["header"].items()}

    def write_meta(self, seq: int, meta: dict) -> None:
        record = self._records(CTX)[seq]
        record.fields["token"]["header"] = json.loads(json.dumps(meta))
        self.write_raw(record)

    # --- identity -----------------------------------------------------------

    def identity_of(self, record: Record) -> str:
        return record.fields["ref"]

    def payload_of(self, record: Record) -> str:
        chain = record.fields["token"].get("chain") or []
        return " | ".join(hop.get("action_summary", "") for hop in chain)

    def owner_of(self, record: Record) -> str | None:
        # The context is the store the record was read from, not anything the
        # token claims about itself.
        return str(self._store_file(record.fields["ctx"]).resolve())

    # --- T9 ------------------------------------------------------------------

    def snapshot_store(self):
        return self._copy_store(Path(self._root))

    def restore_store(self, token) -> None:
        self._restore_store(token, Path(self._root))
        shutil.rmtree(Path(token).parent, ignore_errors=True)

    def append_genuine(self) -> None:
        before = len(self._ordered(CTX))
        out = self._bridge({"op": "seed", "dir": self._root, "ctx": CTX, "n": 1, "append": True})
        if not out.get("ok"):
            raise RuntimeError(f"the genuine append failed: {out.get('error')}")
        if len(self._ordered(CTX)) == before:
            raise RuntimeError("the genuine append wrote nothing")

    # --- the recipient's read path ------------------------------------------

    def reload(self) -> None:
        # Every read is a fresh Node process, which is a restart.
        return None

    def verify(self) -> bool:
        """Resolve every record of this row's reference kind, then verify it."""
        self.verify_detail = None
        bad = []
        for record in self._records(CTX):
            ref = record.fields["ref"]
            out = self._bridge({"op": "read", "dir": self._root, "ctx": CTX, "reference": ref})
            if not out.get("ok"):
                bad.append(f"{out.get('stage')}: {out.get('error')}")
        if bad:
            self.verify_detail = bad[0][:200]
            return False
        self.verify_detail = f"resolved and verified {len(self._records(CTX))} tokens"
        return True


class HdpTokenStoreUuidAdapter(HdpTokenStoreAdapter):
    """HDP tokens read back by their UUID reference, the substitution point
    section 8.2 steers implementers away from."""

    name = "hdp-token-uuid"
    by_content_reference = False
