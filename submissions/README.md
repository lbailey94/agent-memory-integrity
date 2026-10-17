# Submissions

Records that put the agmi scorecard in front of a standards or conformance
group, in that group's own intake shape.

| File | Group | Criteria |
|---|---|---|
| `w3c-agent-conformance-v1.json` | W3C Agent Conformance and Benchmarking CG | intake criteria v2 (list message 0067) |

The record is generated, never edited by hand:

    python submissions/build_record.py build     # from results/scorecard.json at HEAD
    python submissions/build_record.py verify    # recompute and compare; refuses on any mismatch

`verify` is the independent recount the criteria ask for. An unrelated party
holding only the pinned commit can run it and either get the same digests,
counts and labels, or a named refusal (`row-missing`, `row-duplicated`,
`row-not-in-manifest`, `row-digest-mismatch`).
