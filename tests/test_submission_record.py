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


def _leaves(o, path=()):
    if isinstance(o, dict):
        for k, v in o.items():
            yield from _leaves(v, path + (k,))
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from _leaves(v, path + (i,))
    else:
        yield path, o


def _containers(o, path=()):
    if isinstance(o, (dict, list)):
        yield path, o
        items = o.items() if isinstance(o, dict) else enumerate(o)
        for k, v in items:
            yield from _containers(v, path + (k,))


def _get(o, path):
    for k in path:
        o = o[k]
    return o


def _mutated(v):
    if isinstance(v, bool):
        return not v
    if isinstance(v, (int, float)):
        return v + 1
    if isinstance(v, str):
        return v + "X"
    return "X"


def test_every_field_is_protected():
    """Edit every leaf, delete every key and element, insert a key into
    every object: each must be refused, and the untouched record must not.
    This is the sweep an outside party would run; it runs here first."""
    import copy
    import importlib.util
    spec = importlib.util.spec_from_file_location("build_record", ROOT / "submissions" / "build_record.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    rec = json.loads(RECORD.read_text())
    fresh = mod.build()
    assert mod.compare(rec, fresh) == []
    slipped = []
    for path, val in _leaves(rec):
        d = copy.deepcopy(rec)
        _get(d, path[:-1])[path[-1]] = _mutated(val)
        if not mod.compare(d, fresh):
            slipped.append(("edit", path))
    for path, c in list(_containers(rec)):
        keys = list(c.keys()) if isinstance(c, dict) else list(range(len(c)))
        for k in keys:
            d = copy.deepcopy(rec)
            del _get(d, path)[k]
            if not mod.compare(d, fresh):
                slipped.append(("delete", path + (k,)))
        if isinstance(c, dict):
            d = copy.deepcopy(rec)
            _get(d, path)["extra"] = "X"
            if not mod.compare(d, fresh):
                slipped.append(("insert", path))
    assert not slipped, slipped
