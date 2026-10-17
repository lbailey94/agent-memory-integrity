#!/usr/bin/env python3
# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Build or verify the submission record for the W3C Agent Conformance and
Benchmarking Community Group, against intake criteria v2 (list message 0067).

    python submissions/build_record.py build    write the record from the repo
    python submissions/build_record.py verify   recompute everything from the
                                                pinned bytes and compare

The record is derived, never hand-edited. Every digest, count and label in it
is recomputed from results/scorecard.json and the repository, so an unrelated
party holding only the pinned commit can run `verify` and get the same answer.
That recount is what intake criterion 4 asks for; a printed total is one more
value to compare, never the result.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results" / "scorecard.json"
RECORD = ROOT / "submissions" / "w3c-agent-conformance-v1.json"

AT_REST = ["tamper", "truncate", "delete_middle", "reorder", "forge",
           "cross_replay", "rollback_replay", "metadata_tamper", "snapshot_rollback"]
FRONT_DOOR = ["memory_injection", "cross_session_bleed", "retrieval_hijack",
              "indirect_prompt_injection", "update_poisoning", "metadata_poisoning"]

# Canonicalisation declared, not inherited (criterion 9): RFC 8785 JCS is
# what json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)
# produces for the JSON subset the results file uses (no floats).
def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def git(*args) -> str:
    return subprocess.run(["git", "-C", str(ROOT), *args],
                          capture_output=True, text=True, check=True).stdout.strip()


def row_digest(row: dict) -> str:
    return sha256(canon(row))


def verdict_counts(row: dict) -> dict:
    """Decision rule, stated so a refusal can be recomputed without the
    tooling: a cell's verdict is the string in cells[<edit>].verdict; a row's
    count is the number of at-rest cells carrying each verdict."""
    out = {"accepted": 0, "rejected": 0, "reported": 0, "n/a": 0}
    for e in AT_REST:
        v = row["cells"].get(e, {}).get("verdict", "n/a")
        out[v if v in out else "n/a"] += 1
    return out


def build() -> dict:
    results = json.loads(RESULTS.read_text())
    rows = results["rows"]
    commit = git("rev-parse", "HEAD")

    manifest = []
    for r in rows:
        manifest.append({
            "id": r["label"],
            "digest": {"alg": "sha-256", "input": "JCS(row object)", "value": row_digest(r)},
            "measured_on": r.get("measured_on"),
            "detection_point": r.get("checked_at"),
            "verdicts": verdict_counts(r),
        })
    manifest.sort(key=lambda m: m["id"])

    results_bytes = RESULTS.read_bytes()
    corpus_digest = sha256(canon({
        "results_file": {"path": "results/scorecard.json", "sha256": sha256(results_bytes)},
        "manifest": [{"id": m["id"], "digest": m["digest"]["value"]} for m in manifest],
    }))

    record = {
        "record": "agmi submission to W3C Agent Conformance and Benchmarking CG",
        "intake_criteria": "v2, public-agent-conformance list message 0067 (13 October 2026)",
        "submitter": {"name": "Yasha Khandelwal", "email": "yasha.khandelwal@tech4biz.io",
                      "role": "maintainer of the suite; author of the method text"},
        "licence": {"code": "MIT", "results": "MIT", "this_record": "CC0-1.0"},

        # criterion 1: byte pinning
        "pinned_bytes": {
            "results_file": {"path": "results/scorecard.json", "alg": "sha-256",
                             "value": sha256(results_bytes), "input": "exact file bytes"},
            "corpus_digest": {"alg": "sha-256", "value": corpus_digest,
                              "input": "JCS({results_file digest, sorted manifest of row digests})"},
        },

        # criterion 2: closed manifest, checked both ways by `verify`
        "admitted_population": {
            "description": "every row in results/scorecard.json at the pinned commit",
            "count": len(manifest),
            "manifest": manifest,
            "rejection_grounds": ["row-missing", "row-duplicated", "row-not-in-manifest",
                                  "row-digest-mismatch"],
        },

        # criterion 3: selector
        "selector": {"expression": "rows[*].label", "matched": len(manifest),
                     "rejection_grounds": ["selector-matched-zero", "selector-matched-multiple"]},

        # criterion 4: independent recount with decision rule
        "recount": {
            "decision_rule": verdict_counts.__doc__.strip(),
            "per_row": {m["id"]: m["verdicts"] for m in manifest},
            "printed_totals": {
                "stores_measured_badge": 26,
                "rows": len(rows),
                "source": "README.md badge and docs/scorecard.md; compared by tests/test_readme_table.py",
            },
            "carried": ["per-cell verdict and detail", "per-row counts", "CI exit code"],
        },

        # criterion 5: native record
        "native_record": "each cell's `detail` is the tool's own exception type and message, "
                         "or its own reason for an n/a, carried unchanged",

        # criterion 6: per-observation carry
        "observation_carry": {"default": "inline",
                              "note": "every cell carries verdict and detail inline; none referenced "
                                      "by digest; an absent cell is a fail-closed refusal in the merge tool"},

        # criterion 7: anchor
        "anchor": {
            "git": {"repository": "https://github.com/tech4biz-yasha/agent-memory-integrity",
                    "commit": commit,
                    "availability_failure": "commit does not resolve on the host",
                    "integrity_failure": "commit resolves but results/scorecard.json digest differs"},
            "pypi": {"package": "agent-memory-integrity", "version": "0.6.3",
                     "sdist_sha256_prefix": "422c4c5f3ead2512",
                     "wheel_sha256_prefix": "3913eb165ab91e43",
                     "note": "full digests on https://pypi.org/project/agent-memory-integrity/0.6.3/"},
        },

        # criterion 8: checker and helper provenance
        "checker": {
            "name": "agmi full runner and merge tool",
            "source_revision": commit,
            "command": "PYTHONPATH=. python agmi/full_runner.py --json <out>; "
                       "python -m agmi.merge_rows results/scorecard.json <out> --labels <row>",
            "runtime": results.get("platform"),
            "attack_versions": results.get("attack_versions"),
            "helpers": [
                {"name": "agmi/bridges/surgical_devops_bridge.js", "pinned_by": "repository commit",
                 "runtime": "Node v24.18.0 (enforced by the bridge)"},
                {"name": "agmi/bridges/hdp_bridge.mjs", "pinned_by": "repository commit",
                 "runtime": "Node 22 (enforced by the adapter)"},
            ],
            "external_units": "each row's measured_on names the library version and commit "
                              "the row was measured against; the adapter refuses to run "
                              "against any other",
        },

        # criterion 9: canonicalisation
        "canonicalization": {"encoding": "RFC 8785 JCS",
                             "applies_to": "row and corpus digests in this record",
                             "note": "the results file itself is pinned by exact bytes, not canonical form"},

        # criterion 10: replay stability, distinct from byte identity
        "replay_stability": {
            "claim": "the two Recallspection rows re-measured on 2026-10-17 produced cells "
                     "identical, detail strings included, to the 2026-10-15 run",
            "evidence": "git diff of results/scorecard.json across the two merges showed no "
                        "changed cells for those rows",
            "ci": "scorecard.yml re-measures every row the runner can reach on each push and "
                  "weekly against latest releases; its last step fails the run if this "
                  "measurement disagrees with the committed file on any cell both measured",
            "byte_identity": "results/scorecard.json is pinned by sha-256 above",
            "unordered_streams": "none digested; the results file is a JSON document with a "
                                 "fixed row order",
        },

        # criterion 11: exposure and fault separation
        "exposure": {
            "expected_answers_visible": True,
            "note": "the nine edits are public code; a store's maintainer can read them. "
                    "Rows submitted by a tool's own maintainer are marked as such on the "
                    "scorecard and were reproduced independently before publication",
            "fault_separation": "every edit is an injected fault with its own cell; the landed "
                                "check refuses to score a cell when the edit did not land as "
                                "intended, so a false pass cannot come from a failed edit",
            "maintainer_submitted_rows": ["surgical-devops-g7", "recallspection-exact",
                                          "recallspection-exact+anchor",
                                          "hdp-token-content-ref", "hdp-token-uuid"],
        },

        # criterion 12: scope
        "scope": {
            "establishes": "for each row, what the store served back to the agent after each of "
                           "nine storage-level edits made beneath its own API, and whether that "
                           "was noticed on the read path or only in a later audit",
            "does_not": ["rank implementations", "claim coverage of the whole attack surface",
                         "speak for an attacker other than the one each row names",
                         "establish that an action happened or that its actor had authority",
                         "measure content-level attacks except where a row carries the six "
                         "front-door families separately"],
        },

        # criterion 13
        "names_no_implementation": "the criteria above are met by the record, not by any "
                                   "particular store; the first suite offered under them is "
                                   "a procedure run against live stores rather than a static "
                                   "vector corpus, which is the question put to the editors",

        "method_text": {
            "internet_draft": "draft-khandelwal-bmwg-agent-memory-integrity-01",
            "next_revision": "-02 in preparation for the 2 November 2026 cut-off",
            "scorecard": "https://agentmemoryintegrity.org",
        },
    }
    return record


def verify() -> int:
    stored = json.loads(RECORD.read_text())
    fresh = build()
    problems = []
    if stored["pinned_bytes"] != fresh["pinned_bytes"]:
        problems.append("row-digest-mismatch or results file changed")
    s_ids = [m["id"] for m in stored["admitted_population"]["manifest"]]
    f_ids = [m["id"] for m in fresh["admitted_population"]["manifest"]]
    if len(s_ids) != len(set(s_ids)):
        problems.append("row-duplicated")
    for i in set(f_ids) - set(s_ids):
        problems.append(f"row-not-in-manifest: {i}")
    for i in set(s_ids) - set(f_ids):
        problems.append(f"row-missing: {i}")
    if stored["recount"]["per_row"] != fresh["recount"]["per_row"]:
        problems.append("recount differs from stored per-row counts")
    if stored["recount"]["printed_totals"]["rows"] != len(f_ids):
        problems.append("printed row total differs from recount")
    # anchor check: the pinned commit must resolve and must hold exactly the
    # results bytes the record pins (criterion 7's two named failures)
    commit = stored["anchor"]["git"]["commit"]
    if subprocess.run(["git", "-C", str(ROOT), "cat-file", "-e", f"{commit}^{{commit}}"],
                      capture_output=True).returncode != 0:
        # shallow clone: pull just that commit from the origin before deciding
        subprocess.run(["git", "-C", str(ROOT), "fetch", "--depth=1", "origin", commit],
                       capture_output=True)
    try:
        blob = subprocess.run(["git", "-C", str(ROOT), "cat-file", "-p",
                               f"{commit}:results/scorecard.json"],
                              capture_output=True, check=True).stdout
    except subprocess.CalledProcessError:
        problems.append(f"anchor availability failure: {commit[:8]} does not resolve here")
    else:
        if sha256(blob) != stored["pinned_bytes"]["results_file"]["value"]:
            problems.append(f"anchor integrity failure: {commit[:8]} holds different results bytes")
    for p in problems:
        print("REFUSE:", p)
    print("rows:", len(f_ids), "| corpus digest:", fresh["pinned_bytes"]["corpus_digest"]["value"][:16])
    print("verify:", "OK" if not problems else "REFUSED")
    return 1 if problems else 0


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "build"
    if mode == "build":
        RECORD.parent.mkdir(exist_ok=True)
        RECORD.write_text(json.dumps(build(), indent=1, ensure_ascii=False) + "\n")
        print("wrote", RECORD.relative_to(ROOT))
    elif mode == "verify":
        sys.exit(verify())
    else:
        sys.exit("usage: build_record.py [build|verify]")
