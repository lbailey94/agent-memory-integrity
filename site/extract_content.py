#!/usr/bin/env python3
"""Pull the hand-written prose out of the deployed site into content files.

The generator that built agentmemoryintegrity.org was never committed. The
deployed pages are the only copy of the prose in them, so step one of
rebuilding the generator is getting that prose into the repo as data, where
it can be reviewed and versioned like everything else.

Everything else on those pages is derivable from results/scorecard.json and
is the generator's job, not content.

Writes site/content/ as:
  stores/<label>.json   the two prose sections per store row
  pages/<name>.html     whole pages that carry no generated data
"""

import json
import pathlib
import re

SRC = pathlib.Path("/home/claude/site-out")
OUT = pathlib.Path("/home/claude/agmi/site/content")

# Pages that are prose end to end: no cells, no counts, nothing from results.
# They are kept whole rather than templated, because templating them would
# invent structure the author never asked for.
PROSE_PAGES = ["about.html", "cite.html", "method.html", "run.html",
               "agent.html", "architecture.html", "ecosystem.html"]

STORE_SECTIONS = ["What this means", "Where the attacker stands"]


def slug_to_label(name: str) -> str:
    """stores/recallspection-exact-anchor.html -> recallspection-exact+anchor

    The file name flattens "+" to "-", so the mapping back is ambiguous in
    general. Resolve it against the labels that actually exist.
    """
    return name[:-5]


def extract_store(path: pathlib.Path) -> dict | None:
    html = path.read_text()
    out = {}
    for head in STORE_SECTIONS:
        m = re.search(rf"<h2>{re.escape(head)}</h2>\n(.*?)\n</section>", html, re.S)
        if not m:
            return None
        out[head] = m.group(1).strip()
    title = re.search(r"<h1>(.*?)</h1>", html, re.S)
    subtitle = re.search(r'<p class="subtitle">(.*?)</p>', html, re.S)
    source = re.search(r"<dt>Source</dt><dd><a href=\"(.*?)\">(.*?)</a></dd>", html, re.S)
    repro = re.search(r"<h2>Reproduce this row</h2>\n<p>(.*?)</p>\n<pre><code>(.*?)</code></pre>",
                      html, re.S)
    out["title"] = title.group(1).strip() if title else ""
    out["subtitle"] = subtitle.group(1).strip() if subtitle else ""
    out["source_url"] = source.group(1) if source else ""
    out["source_label"] = source.group(2) if source else ""
    out["reproduce_intro"] = repro.group(1).strip() if repro else ""
    out["reproduce"] = repro.group(2) if repro else ""
    return out


def main() -> int:
    (OUT / "stores").mkdir(parents=True, exist_ok=True)
    (OUT / "pages").mkdir(parents=True, exist_ok=True)

    results = json.loads((pathlib.Path("/home/claude/agmi/results/scorecard.json")).read_text())
    labels = {r["label"] for r in results["rows"]}
    def to_file(label: str) -> str:
        # The deployed file names flatten the characters a label may carry:
        # "+" and parentheses both become "-", and a trailing ")" is dropped.
        return label.replace("+", "-").replace("(", "-").replace(")", "").replace(",", "-")

    by_file = {to_file(lb): lb for lb in labels}

    stores = unmatched = 0
    for f in sorted((SRC / "stores").glob("*.html")):
        if f.name == "index.html":
            continue
        label = by_file.get(slug_to_label(f.name))
        if label is None:
            unmatched += 1
            print("  no row for", f.name)
            continue
        data = extract_store(f)
        if data is None:
            print("  prose sections missing in", f.name)
            continue
        data["label"] = label
        (OUT / "stores" / f"{slug_to_label(f.name)}.json").write_text(
            json.dumps(data, indent=1, ensure_ascii=False))
        stores += 1

    pages = 0
    for name in PROSE_PAGES:
        p = SRC / name
        if p.exists():
            (OUT / "pages" / name).write_text(p.read_text())
            pages += 1

    for section in ("edits", "findings", "levels"):
        d = OUT / "pages" / section
        d.mkdir(parents=True, exist_ok=True)
        for f in sorted((SRC / section).glob("*.html")):
            (d / f.name).write_text(f.read_text())
            pages += 1

    print(f"stores: {stores} extracted, {unmatched} with no row")
    print(f"pages: {pages} carried whole")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
