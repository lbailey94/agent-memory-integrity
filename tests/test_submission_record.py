# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""The committed submission record must still verify against the results file.

Anything that changes results/scorecard.json without rebuilding the record
fails here, so the record cannot drift from the bytes it pins."""

import json
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
RECORD = ROOT / "submissions" / "w3c-agent-conformance-v1.json"


def test_record_verifies_against_results():
    r = subprocess.run([sys.executable, "submissions/build_record.py", "verify"],
                       cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout


def test_record_population_matches_results():
    rec = json.loads(RECORD.read_text())
    res = json.loads((ROOT / "results" / "scorecard.json").read_text())
    assert rec["admitted_population"]["count"] == len(res["rows"])
    assert sorted(m["id"] for m in rec["admitted_population"]["manifest"]) == \
        sorted(r["label"] for r in res["rows"])



def _verify(tmp_path, mutate):
    """Copy the record, apply one edit, and run the verifier against the copy."""
    rec = json.loads(RECORD.read_text())
    mutate(rec)
    p = tmp_path / "rec.json"
    p.write_text(json.dumps(rec, indent=1))
    r = subprocess.run([sys.executable, "submissions/build_record.py", "verify", str(p)],
                       cwd=ROOT, capture_output=True, text=True)
    return r.returncode, r.stdout


@pytest.mark.parametrize("name, mutate, refusal", [
    # the three cases an outside party ran against the first verifier
    ("row digest zeroed",
     lambda d: d["admitted_population"]["manifest"].__getitem__(0)["digest"].__setitem__("value", "0" * 64),
     "row-digest-mismatch: "),
    ("selector count zeroed",
     lambda d: d["selector"].__setitem__("matched", 0),
     "selector-matched-count"),
    ("results digest zeroed",
     lambda d: d["pinned_bytes"]["results_file"].__setitem__("value", "0" * 64),
     "anchor integrity failure"),
    # and three more of the same shape
    ("row verdict count edited",
     lambda d: d["recount"]["per_row"][sorted(d["recount"]["per_row"])[0]].__setitem__("accepted", 99),
     "field-differs-from-derivation: /recount/per_row/"),
    ("row dropped from manifest",
     lambda d: d["admitted_population"]["manifest"].pop(),
     "row-not-in-manifest: "),
    ("population count edited",
     lambda d: d["admitted_population"].__setitem__("count", 1),
     "field-differs-from-derivation: /admitted_population/count"),
])
def test_edited_record_is_refused(tmp_path, name, mutate, refusal):
    code, out = _verify(tmp_path, mutate)
    assert code == 1, (name, out)
    assert refusal in out, (name, out)


def test_unedited_copy_verifies(tmp_path):
    code, out = _verify(tmp_path, lambda d: None)
    assert code == 0, out
