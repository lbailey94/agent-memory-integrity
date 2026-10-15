# site/content

The prose of agentmemoryintegrity.org, kept in the repo rather than only on
the live site.

The generator that built the published site was never committed and went with
a machine failure in October 2026. For a while the only copy of these words
was the deployed HTML. This directory ends that: the hand-written parts are
extracted here as data, versioned and reviewable like everything else, and the
generator's job is reduced to what can be derived from results/scorecard.json.

- `stores/<label>.json` — per row: the title and subtitle, the two prose
  sections ("What this means", "Where the attacker stands"), the source link,
  and the reproduce command. Verdicts, counts, levels and tallies are NOT
  here; those come from the results file, because a number that can drift
  from the measurement does not belong in content.
- `pages/*.html` — whole pages that carry no generated data: method, run,
  agent, architecture, ecosystem, cite, about, and the edits, findings and
  levels sections.

`site/extract_content.py` is how this was recovered. It is kept for the record
and should not need running again; edit the content files directly.
