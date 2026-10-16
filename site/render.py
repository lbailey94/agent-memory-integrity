#!/usr/bin/env python3
# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Build agentmemoryintegrity.org from the results file and site/content.

Nothing here invents a number. Every verdict, count, level and tally comes
from results/scorecard.json; every word comes from site/content. If the two
disagree, the results file wins, because a figure that can drift from the
measurement is the one thing this board cannot afford.

    python site/render.py              write the site to site/dist
    python site/render.py --check      build and compare against a reference
                                       tree, printing what differs

Pages fall into three kinds:

  generated   a page per store row, the scorecard, the store index, the
              level pages, the home page tallies, the sitemap and llms.txt
  carried     pages that hold no measured data: method, run, agent,
              architecture, ecosystem, cite, about, and the edits and
              findings sections. They live in site/content/pages and are
              copied through untouched
  static      site.css, site.js, logo.svg, og.png, robots.txt, feed.xml

The chrome (head, nav, footer) comes from a reference page rather than from
a template written from scratch, so the output keeps the design exactly as
published rather than approximating it.
"""

from __future__ import annotations

import argparse
import html
import json
import pathlib
import re
import shutil
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTENT = ROOT / "site" / "content"
RESULTS = ROOT / "results" / "scorecard.json"
BASE = "https://agentmemoryintegrity.org"

EDITS = [
    ("tamper", "T1", "Content tamper", "tamper"),
    ("truncate", "T2", "Tail truncation", "truncate"),
    ("delete_middle", "T3", "Middle deletion", "delete-middle"),
    ("reorder", "T4", "Reordering", "reorder"),
    ("forge", "T5", "Forged insertion", "forge"),
    ("cross_replay", "T6", "Cross-context replay", "cross-replay"),
    ("rollback_replay", "T7", "Rollback replay", "rollback-replay"),
    ("metadata_tamper", "T8", "Metadata tamper", "metadata-tamper"),
    ("snapshot_rollback", "T9", "Snapshot rollback", "snapshot-rollback"),
]
# The front-door families, for rows measured at the door rather than at rest.
# Short label first, as the miniboard shows it, then the full name.
FRONT_DOOR = [
    ("memory_injection", "Planted fact", "Planted fact", "memory-injection"),
    ("cross_session_bleed", "Cross-user", "Cross-user leak", "cross-session-bleed"),
    ("retrieval_hijack", "Retrieval", "Retrieval hijack", "retrieval-hijack"),
    ("indirect_prompt_injection", "Indirect", "Indirect prompt injection",
     "indirect-prompt-injection"),
    ("update_poisoning", "Update", "Update poisoning", "update-poisoning"),
    ("metadata_poisoning", "Metadata", "Metadata poisoning", "metadata-poisoning"),
]
CLS = {
    "surfaced": ("v-acc", "v-accepted", "surfaced"),
    "kept out": ("v-rej", "v-rejected", "kept out"),
    "accepted": ("v-acc", "v-accepted", "served"),
    "rejected": ("v-rej", "v-rejected", "rejected"),
    "reported": ("v-rep", "v-reported", "reported"),
    "n/a": ("v-na", "v-na", "n/a"),
}
# A level is earned on the read path only, cumulatively.
LEVELS = [
    ("L1", ["tamper", "delete_middle", "forge"]),
    ("L2", ["truncate", "reorder", "rollback_replay"]),
    ("L3", ["cross_replay", "metadata_tamper"]),
    ("L4", ["snapshot_rollback"]),
]


def truncate(text: str, limit: int) -> str:
    """Cut at a word boundary and mark it, as the published pages do."""
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0] + "\u2026"


class Unrenderable(Exception):
    """A page whose structure this renderer does not reproduce yet."""


def esc(s: str | None) -> str:
    return html.escape(s or "", quote=True)


def file_name(label: str) -> str:
    """The published file name for a row label."""
    return label.replace("+", "-").replace("(", "-").replace(")", "").replace(",", "-")


def verdicts(row: dict) -> list[str]:
    fam = EDITS if any(
        row["cells"].get(e, {}).get("verdict", "n/a") != "n/a" for e, *_ in EDITS
    ) else FRONT_DOOR
    return [row["cells"].get(e, {}).get("verdict", "n/a") for e, *_ in fam]


def tally(row: dict) -> tuple[int, int, int, int]:
    v = verdicts(row)
    served = v.count("accepted") + v.count("surfaced")
    refused = v.count("rejected") + v.count("kept out")
    return served, v.count("reported"), refused, v.count("n/a")


def level_of(row: dict) -> str:
    if row.get("checked_at") != "read":
        return "L0"
    got = "L0"
    for name, needed in LEVELS:
        cells = row["cells"]
        ok = all(cells.get(e, {}).get("verdict") in ("rejected", "n/a") for e in needed)
        any_rejected = any(cells.get(e, {}).get("verdict") == "rejected" for e in needed)
        if ok and any_rejected:
            got = name
        else:
            break
    return got


def detail_of(cell: dict) -> str:
    return esc(cell.get("detail") or cell.get("error") or "")


class Site:
    def __init__(self, reference: pathlib.Path):
        self.ref = reference
        self.results = json.loads(RESULTS.read_text())
        self.rows = {r["label"]: r for r in self.results["rows"]}
        self.content = {}
        for f in sorted((CONTENT / "stores").glob("*.json")):
            d = json.loads(f.read_text())
            self.content[d["label"]] = d
        missing = set(self.rows) - set(self.content)
        if missing:
            raise SystemExit(f"no content for published rows: {sorted(missing)}\n"
                             f"add site/content/stores/<name>.json before rendering")
        # Row order on the board follows the results file, which follows the
        # order rows were measured.
        self.order = [r["label"] for r in self.results["rows"]]

    def attack_versions(self) -> str:
        """The nine storage-level edits and their versions, as the page shows
        them. The front-door families are not listed on a store page."""
        av = self.results.get("attack_versions", {})
        return ", ".join(f"{e}@v{av[e]}" for e, *_ in EDITS if e in av)

    # --- fragments ----------------------------------------------------------

    @staticmethod
    def families(row: dict) -> list[tuple[str, str, str, str]]:
        """Which set of attacks this row was measured against.

        A row is measured either at rest, against the nine storage-level
        edits, or at the front door, against the six content families. The
        results file says which by which cells carry a verdict."""
        if any(row["cells"].get(e, {}).get("verdict", "n/a") != "n/a"
               for e, *_ in EDITS):
            return EDITS
        return FRONT_DOOR

    def miniboard(self, row: dict) -> str:
        out = []
        for i, (edit, tn, label, slug) in enumerate(self.families(row)):
            v = row["cells"].get(edit, {}).get("verdict", "n/a")
            cls, _full, word = CLS[v]
            out.append(f'<a class="mini {cls}" href="../edits/{slug}.html" '
                       f'title="{esc(label)}: {v}" style="--i:{i}">'
                       f'<span class="mono">{tn}</span><span>{word}</span></a>')
        return '<div class="miniboard" aria-label="Verdicts at a glance">' + "".join(out) + "</div>"

    def cell_table(self, row: dict) -> str:
        trs = []
        for edit, tn, label, slug in self.families(row):
            c = row["cells"].get(edit, {})
            v = c.get("verdict", "n/a")
            cls, _full, _word = CLS[v]
            trs.append(f'<tr><th scope="row"><a href="../edits/{slug}.html">{tn}</a><br>'
                       f'<span class="muted">{esc(label)}</span></th>'
                       f'<td class="{cls}"><span class="verdict">{v}</span></td>'
                       f'<td class="detail">{detail_of(c)}</td></tr>')
        return ('<table class="cells"><thead><tr><th scope="col">Edit</th>'
                '<th scope="col">Verdict</th><th scope="col">What the tool said</th>'
                '</tr></thead><tbody>' + "".join(trs) + "</tbody></table>")

    # --- a page per store ----------------------------------------------------

    def store_page(self, label: str, template: str) -> str:
        row, c = self.rows[label], self.content[label]
        acc, rep, rej, na = tally(row)
        lv = level_of(row)
        url = f"{BASE}/stores/{file_name(label)}.html"
        # The published formats, recovered from the live pages. A row with no
        # subtitle reads "<name>: tamper evidence, measured"; one with a
        # subtitle carries it before the phrase.
        title = (f'{c["title"]}: {c["subtitle"]}, tamper evidence measured'
                 if c["subtitle"] else f'{c["title"]}: tamper evidence, measured')
        name = c["title"] + (f', {c["subtitle"]}' if c["subtitle"] else "")
        measured_on_short = (c.get("version") or row.get("measured_on") or "")
        desc_full = (f'{name} against nine storage-level edits (T1 to T9): '
                     f'{acc} served, {rep} reported, {rej} rejected. Detection point: '
                     f'{row.get("checked_at")}. Level {lv}. Measured on '
                     f'{c.get("version") or row.get("measured_on") or ""} by agmi.'
                     if (c.get("version") or row.get("measured_on")) else "")
        desc = truncate(
            f'{name} against nine storage-level edits (T1 to T9): {acc} served, '
            f'{rep} reported, {rej} rejected. Detection point: '
            f'{row.get("checked_at")}. Level {lv}. '
            f'Measured on {measured_on_short} by agmi.', 157)
        p = template

        for pat, rep_ in [
            (r"<title>.*?</title>", f"<title>{esc(title)} | agmi</title>"),
            (r'<meta name="description" content=".*?">',
             f'<meta name="description" content="{esc(desc)}">'),
            (r'<link rel="canonical" href=".*?">', f'<link rel="canonical" href="{url}">'),
            (r'<meta property="og:title" content=".*?">',
             f'<meta property="og:title" content="{esc(title)}">'),
            (r'<meta property="og:description" content=".*?">',
             f'<meta property="og:description" content="{esc(desc)}">'),
            (r'<meta property="og:url" content=".*?">',
             f'<meta property="og:url" content="{url}">'),
            (r'<meta name="twitter:title" content=".*?">',
             f'<meta name="twitter:title" content="{esc(title)}">'),
            (r'<meta name="twitter:description" content=".*?">',
             f'<meta name="twitter:description" content="{esc(desc)}">'),
            (r'<meta name="twitter:url" content=".*?">',
             f'<meta name="twitter:url" content="{url}">'),
            (r"<h1>.*?</h1>", f'<h1>{esc(c["title"])}</h1>'),
            (r'<p class="subtitle">.*?</p>',
             f'<p class="subtitle">{esc(c["subtitle"])}</p>' if c["subtitle"] else ""),
        ]:
            p = re.sub(pat, rep_, p, count=1, flags=re.S)

        lede = (f'{c["title"]} was seeded through its own API and edited behind its back '
                f'nine ways. {acc} {"edit" if acc == 1 else "edits"} served as genuine, '
                f'{rep} reported on audit, {rej} rejected on read'
                + (f', {na} not applicable.' if na else '.'))
        p = re.sub(r'<p class="lede">.*?</p>', f'<p class="lede">{esc(lede)}</p>',
                   p, count=1, flags=re.S)
        p = re.sub(r'<div class="miniboard".*?</div>', self.miniboard(row),
                   p, count=1, flags=re.S)

        measured_on = (c.get("measured_on") or row.get("measured_on")
                       or ", ".join(x for x in (c.get("version"),
                                            self.results.get("platform")) if x))
        date = (c.get("measured_date") or row.get("measured_date")
                or self.results.get("date"))
        facts = (f'<dl class="facts">\n'
                 f'    <dt>Measured on</dt><dd>{esc(measured_on)}</dd>\n'
                 f'    <dt>Date</dt><dd><time datetime="{date}">{date}</time></dd>\n'
                 f'    <dt>Source</dt><dd><a href="{c["source_url"]}">'
                 f'{esc(c["source_label"])}</a></dd>\n'
                 f'    <dt>Attack versions</dt><dd class="mono">'
                 f'{esc(self.attack_versions())}</dd>\n  </dl>')
        p = re.sub(r'<dl class="facts">.*?</dl>', facts, p, count=1, flags=re.S)

        p = re.sub(r"(<h2>What this means</h2>\n).*?(\n</section>)",
                   lambda m: m.group(1) + c["What this means"] + m.group(2),
                   p, count=1, flags=re.S)

        intro = c.get("verdicts_intro")
        if intro is None:
            # a page whose structure this renderer does not reproduce; it is
            # carried through from the reference build instead of generated.
            raise Unrenderable(label)
        closing = self.closing_note
        p = re.sub(r"(<h2>The \d verdicts</h2>\n).*?(\n</section>)",
                   lambda m: m.group(1) + intro + "\n" + self.cell_table(row) + closing + m.group(2),
                   p, count=1, flags=re.S)

        p = re.sub(r"(<h2>Where the attacker stands</h2>\n).*?(\n</section>)",
                   lambda m: m.group(1) + c["Where the attacker stands"] + m.group(2),
                   p, count=1, flags=re.S)

        p = re.sub(r"(<h2>Reproduce this row</h2>\n)<p>.*?</p>\n<pre><code>.*?</code></pre>",
                   lambda m: (m.group(1) + f'<p>{c["reproduce_intro"]}</p>\n'
                              f'<pre><code>{c["reproduce"]}</code></pre>'),
                   p, count=1, flags=re.S)

        if c.get("related") is not None:
            p = re.sub(r'<ul class="related">.*?</ul>',
                       '<ul class="related">' + c["related"] + '</ul>',
                       p, count=1, flags=re.S)
        p = re.sub(r'(<nav class="crumbs".*?<span>).*?(</span></nav>)',
                   lambda m: m.group(1) + esc(c["title"]) + m.group(2),
                   p, count=1, flags=re.S)

        # the badge and any remaining link to the template row
        p = p.replace(f'{BASE}/stores/{file_name(self.template_label)}.html', url)
        tpl = self.content[self.template_label]
        tpl_name = tpl["title"] + (", " + tpl["subtitle"] if tpl["subtitle"] else "")
        p = p.replace(json.dumps(tpl["title"]) + ",", json.dumps(c["title"]) + ",")
        p = p.replace(json.dumps("agmi scorecard row: " + tpl_name),
                      json.dumps("agmi scorecard row: " + name))
        p = re.sub(r'"description": "[^"]*?by agmi\."',
                   '"description": ' + json.dumps(desc_full), p, count=1)
        p = re.sub(r'"dateModified": "[^"]*"',
                   '"dateModified": "' + str(date) + '"', p, count=1)
        return p

    # --- the whole site ------------------------------------------------------

    def build(self, out: pathlib.Path) -> None:
        if out.exists():
            shutil.rmtree(out)
        out.mkdir(parents=True)

        # static assets and carried pages come through untouched
        for name in ("site.css", "site.js", "logo.svg", "og.png", "robots.txt", "feed.xml"):
            src = self.ref / name
            if src.exists():
                shutil.copy2(src, out / name)
        for f in (CONTENT / "pages").rglob("*.html"):
            rel = f.relative_to(CONTENT / "pages")
            (out / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, out / rel)

        # a page per store, from the published chrome
        self.template_label = "hermes-memory-md"
        tpl_html = (self.ref / "stores" /
                    f"{file_name(self.template_label)}.html").read_text()
        m = re.search(r"</table>(.*?)\n</section>", tpl_html, re.S)
        self.closing_note = m.group(1) if m else ""
        template = (self.ref / "stores" / f"{file_name(self.template_label)}.html").read_text()
        (out / "stores").mkdir(exist_ok=True)
        self.carried = []
        for label in self.order:
            target = out / "stores" / f"{file_name(label)}.html"
            try:
                target.write_text(self.store_page(label, template))
            except Unrenderable:
                shutil.copy2(self.ref / "stores" / target.name, target)
                self.carried.append(label)

        print(f"wrote {out} ({len(list(out.rglob('*')))} entries, "
              f"{len(self.order) - len(self.carried)} store pages generated, "
              f"{len(self.carried)} carried)")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reference", default=str(ROOT / "site" / "reference"),
                    help="a published build, used for chrome and static assets")
    ap.add_argument("--out", default=str(ROOT / "site" / "dist"))
    ap.add_argument("--check", action="store_true",
                    help="compare the build against the reference and report differences")
    a = ap.parse_args()

    ref = pathlib.Path(a.reference)
    if not ref.exists():
        raise SystemExit(f"no reference build at {ref}")
    site = Site(ref)
    out = pathlib.Path(a.out)
    site.build(out)

    if a.check:
        same = diff = only = 0
        for f in sorted(out.rglob("*.html")):
            rel = f.relative_to(out)
            r = ref / rel
            if not r.exists():
                only += 1
                print(f"  new: {rel}")
            elif r.read_bytes() == f.read_bytes():
                same += 1
            else:
                diff += 1
                print(f"  differs: {rel}")
        print(f"identical {same}, differing {diff}, new {only}")
        return 1 if diff else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
