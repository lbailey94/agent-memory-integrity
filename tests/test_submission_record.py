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
