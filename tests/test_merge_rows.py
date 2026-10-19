# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
import json

import pytest

from agmi.merge_rows import MergeError, main, merge

V = {"tamper": 1}


def run(rows, versions=V, date="2026-10-08"):
    return {"date": date, "platform": "p", "attack_versions": versions, "attackers": {},
            "rows": [{"label": lb, "cells": {"tamper": {"verdict": v}}, "measured_on": None}
                     for lb, v in rows]}


def test_replaces_in_place_and_keeps_order_and_header():
    base = run([("a", "accepted"), ("x", "accepted"), ("b", "accepted")])
    extra = run([("x", "reported"), ("y", "reported")], date="2026-10-10")
    out = merge(base, extra, ["x"], "elsewhere")
    assert [r["label"] for r in out["rows"]] == ["a", "x", "b"]
    assert out["rows"][1]["cells"]["tamper"]["verdict"] == "reported"
    assert out["rows"][1]["measured_on"] == "elsewhere"
    assert out["date"] == "2026-10-08"
    assert base["rows"][1]["cells"]["tamper"]["verdict"] == "accepted"


def test_appends_a_new_label():
    out = merge(run([("a", "accepted")]), run([("z", "reported")]), ["z"])
    assert [r["label"] for r in out["rows"]] == ["a", "z"]


def test_refuses_different_attack_versions():
    with pytest.raises(MergeError):
        merge(run([("a", "accepted")]), run([("a", "reported")], versions={"tamper": 2}), ["a"])


def test_refuses_a_missing_label():
    with pytest.raises(MergeError):
        merge(run([("a", "accepted")]), run([("b", "reported")]), ["a"])


def test_cli_writes_the_file_in_the_runner_format(tmp_path):
    b, e = tmp_path / "b.json", tmp_path / "e.json"
    b.write_text(json.dumps(run([("a", "accepted")]), indent=2) + "\n")
    e.write_text(json.dumps(run([("a", "reported")]), indent=2) + "\n")
    assert main([str(b), str(e), "--labels", "a"]) == 0
    out = json.loads(b.read_text())
    assert out["rows"][0]["cells"]["tamper"]["verdict"] == "reported"
    assert b.read_text() == json.dumps(out, indent=2) + "\n"
    e.write_text(json.dumps(run([("q", "reported")]), indent=2) + "\n")
    assert main([str(b), str(e), "--labels", "a"]) == 1


def test_a_merged_row_carries_the_date_it_was_measured():
    base = run([("a", "accepted")])
    out = merge(base, run([("z", "reported")], date="2026-10-12"), ["z"])
    assert out["rows"][1]["measured_date"] == "2026-10-12"
    assert out["date"] == "2026-10-08" and "measured_date" not in out["rows"][0]


def test_a_row_from_before_a_new_attack_carries_an_na_cell_for_it():
    base = {"attack_versions": {"tamper": 1, "erase_resurrect": 1},
            "rows": [{"label": "x", "cells": {"tamper": {"verdict": "accepted"},
                                              "erase_resurrect": {"verdict": "accepted"}}}]}
    extra = {"attack_versions": {"tamper": 1}, "date": "2026-10-01",
             "rows": [{"label": "y", "cells": {"tamper": {"verdict": "reported"}}}]}
    out = merge(base, extra, ["y"])
    y = out["rows"][1]
    assert y["cells"]["tamper"]["verdict"] == "reported"
    assert y["cells"]["erase_resurrect"]["status"] == "n/a"
    assert "before erase_resurrect@v1 existed" in y["cells"]["erase_resurrect"]["detail"]


def test_a_run_with_an_unknown_attack_or_a_moved_version_is_refused():
    base = {"attack_versions": {"tamper": 1}, "rows": []}
    with pytest.raises(MergeError, match="does not know"):
        merge(base, {"attack_versions": {"tamper": 1, "new": 1}, "rows": [{"label": "y", "cells": {}}]}, ["y"])
    with pytest.raises(MergeError, match="different versions"):
        merge(base, {"attack_versions": {"tamper": 2}, "rows": [{"label": "y", "cells": {}}]}, ["y"])
