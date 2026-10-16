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

## Rendering

`site/render.py` builds the site from `results/scorecard.json` plus this
directory. It takes the chrome (head, nav, footer) and the static assets from
a reference build, so the design stays exactly as published rather than being
re-invented.

    python site/render.py --reference <a published build> --out site/dist
    python site/render.py --reference <a published build> --check

`--check` compares what it built against the reference and names every file
that differs. That is the test: a change to the renderer that makes a page
differ for a reason you cannot explain is a bug in the renderer.

Status, 16 October 2026: 62 of the 79 pages come out byte-identical. The rest
split three ways.

- Four pages (Surgical DevOps, Bedrock AgentCore, and the two Recallspection
  rows) differ because the live copies were produced by a one-off script and
  carry the template row's name in places the renderer gets right. The
  renderer's output is the correct one here.
- Seven pages, the front-door rows among them, have a different structure and
  no "The 9 verdicts" section. The renderer carries them through from the
  reference untouched rather than guessing, and says so when it runs.
- The remainder differ only in the JSON-LD description, where the published
  pages used a shorter version string than the one on the page itself.

Neither of the last two affects a verdict, a count or a level: those come from
the results file and match everywhere.
