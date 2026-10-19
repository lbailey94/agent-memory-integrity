# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""The v0.1 report emitted from the committed results file is accepted by the
group's reference reader, recounts to the results file, is byte-stable, and
each single-change control is rejected under exactly the row it targets."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

w3c = pytest.importorskip("agent_evidence_vectors.w3creport")

from agmi import report_v01  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results" / "scorecard.json"
REPORT = ROOT / "results" / "report-v01.json"


@pytest.fixture(scope="module")
def results():
    return json.loads(RESULTS.read_bytes())


@pytest.fixture(scope="module")
def report(results):
    return report_v01.emit(results, RESULTS.read_bytes(), "results/scorecard.json")


def test_status_to_state_mapping_is_pinned():
    assert report_v01.STATE_OF_STATUS == {
        "safe": "pass",
        "VULNERABLE": "fail",
        "reported": "fail",
        "n/a": "not-exercised",
    }


def test_reference_reader_accepts_the_emitted_report(report):
    assert report["format"] == w3c.FORMAT
    assert w3c.shape_errors(report) == []
    assert w3c.rejections(report) == []
    assert w3c.check_set_refusal(report) is None


def test_one_check_per_cell_and_the_root_recomputes(results, report):
    cells = len(results["rows"]) * len(results["attack_versions"])
    assert report["check-set"]["leaf-count"] == cells == len(report["checks"])
    assert report["check-set"]["sha256"] == w3c.check_set_root(report["checks"], "flat")
    assert len({c["check"] for c in report["checks"]}) == cells


def test_counts_recount_to_the_results_file(results, report):
    status = {"safe": 0, "VULNERABLE": 0, "reported": 0, "n/a": 0}
    for row in results["rows"]:
        for cell in row["cells"].values():
            status[cell["status"]] += 1
    rollup = report["roll-up"]
    assert rollup["pass"] == status["safe"]
    assert rollup["fail"] == status["VULNERABLE"] + status["reported"]
    assert rollup["not-exercised"] == status["n/a"]
    assert rollup["void"] == 0 and rollup["inconclusive"] == 0
    assert rollup["declared"] == len(report["checks"])
    assert rollup["exercised"] == rollup["declared"] - rollup["not-exercised"]
    assert rollup["negative-capable"] == {"kind": "shown-by-run"}


def test_reported_cells_keep_their_detection_point(results, report):
    by_id = {c["check"]: c for c in report["checks"]}
    seen = 0
    for row in results["rows"]:
        for edit, cell in row["cells"].items():
            if cell["status"] != "reported":
                continue
            record = by_id[f"{row['label']}/{edit}@v{results['attack_versions'][edit]}"]
            assert record["state"] == "fail"
            assert record["annotations"]["detection"] == "audit"
            seen += 1
    assert seen > 0


def test_every_not_exercised_record_carries_a_closed_cause_and_a_reason(report):
    for record in report["checks"]:
        if record["state"] == "not-exercised":
            assert record["cause"]["code"] in ("not_applicable", "unavailable", "unsupported_input")
            assert record["cause"]["code"] in w3c.CAUSES
            assert record["cause"]["detail"]
            assert "other-verdict" not in record and "discrimination" not in record
        else:
            assert "cause" not in record
            assert record["other-verdict"] == {"value": "unknown"}
            assert record["discrimination"] == {"value": "unknown"}


def test_emission_is_byte_stable(results, report):
    again = report_v01.emit(results, RESULTS.read_bytes(), "results/scorecard.json")
    assert report_v01.dumps(again) == report_v01.dumps(report)


def test_committed_report_matches_the_results_file():
    assert REPORT.exists(), "results/report-v01.json is missing: regenerate it"
    assert report_v01.main(
        ["results/scorecard.json", "results/report-v01.json", "--check"]
    ) == 0


@pytest.mark.parametrize(
    "change, expected",
    [
        ("flip-state", {"W3C-R-017", "W3C-R-020"}),
        ("edit-annotation", {"W3C-R-020"}),
        ("drop-leaf", {"W3C-R-015", "W3C-R-017", "W3C-R-023"}),
        ("zero-root", {"W3C-R-020"}),
        ("inflate-pass", {"W3C-R-017"}),
    ],
)
def test_each_control_flips_exactly_its_row(report, change, expected):
    control = copy.deepcopy(report)
    if change == "flip-state":
        first = next(c for c in control["checks"] if c["state"] == "pass")
        first["state"] = "fail"
    elif change == "edit-annotation":
        control["checks"][0]["annotations"]["detail"] += " (edited)"
    elif change == "drop-leaf":
        control["checks"].pop()
    elif change == "zero-root":
        control["check-set"]["sha256"] = "0" * 64
    elif change == "inflate-pass":
        control["roll-up"]["pass"] += 1
    assert w3c.shape_errors(control) == []
    assert set(w3c.rejections(control)) == expected
    if "W3C-R-020" in expected:
        assert w3c.check_set_refusal(control) == "W3C-R-020 (digests-differ)"
