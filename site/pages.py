# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""The pages of agentmemoryintegrity.org that list or count rows: the home
board, the scorecard, the store index, the level pages, the edit pages,
llms.txt and the sitemap. Each is the published page with its data regions
regenerated from results/scorecard.json, so the chrome and the prose stay
exactly as published and nothing on the site can say a number the results
file does not.

Used by site/render.py; not run on its own.

Rules the regions follow, recovered from the published pages:
  claim       an at-rest row makes an integrity claim when any applicable
              cell is rejected or reported; rows where every applicable cell
              is served make no claim
  serve/refuse  on the edit cards, "serve" counts accepted (or surfaced)
              cells and "refuse" counts rejected (or kept out) cells;
              reported cells are neither
  stores      the store count is the hand-maintained README badge, the one
              number on the site that is not recounted; the submission
              record says the same
"""

from __future__ import annotations

import html
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORDS = {6: "six", 7: "seven", 8: "eight", 9: "nine", 10: "ten", 11: "eleven", 12: "twelve",
         13: "thirteen", 14: "fourteen", 15: "fifteen", 16: "sixteen", 17: "seventeen", 18: "eighteen"}
NAV_EDITS = ("tamper", "truncate", "delete_middle", "reorder", "forge", "cross_replay",
             "rollback_replay", "metadata_tamper", "snapshot_rollback", "erase_resurrect")
FINDINGS_RE = re.compile(r'<ul class="findings">.*?</ul>', re.S)


def esc(s: str | None) -> str:
    return html.escape(s or "", quote=True)


def badge_count() -> int:
    m = re.search(r"stores%20measured-(\d+)-", (ROOT / "README.md").read_text())
    if not m:
        raise SystemExit("README badge with the store count not found")
    return int(m.group(1))


class Pages:
    def __init__(self, site, render):
        self.site = site
        self.r = render  # the render module, for EDITS, FRONT_DOOR, CLS, tally, level_of
        self.results = site.results
        self.date = self.results["date"]
        self.rows = [site.rows[label] for label in site.order]
        self.content = site.content
        self.stores = badge_count()
        self.at_rest = [row for row in self.rows if site.families(row) is render.EDITS]
        self.front = [row for row in self.rows if site.families(row) is render.FRONT_DOOR]
        self.no_claim = [row for row in self.at_rest if not self.claims(row)]
        self.claim = [row for row in self.at_rest if self.claims(row)]
        self.n_edits = len(render.EDITS)
        self.n_front = len(render.FRONT_DOOR)

    # --- small pieces --------------------------------------------------------

    @staticmethod
    def claims(row: dict) -> bool:
        return any(c.get("verdict") in ("rejected", "reported") for c in row["cells"].values())

    def name(self, row: dict) -> str:
        c = self.content[row["label"]]
        return c["title"] + (f', {c["subtitle"]}' if c.get("subtitle") else "")

    def version(self, row: dict) -> str:
        c = self.content[row["label"]]
        return c.get("version") or row.get("measured_on") or ""

    def href(self, row: dict, prefix: str) -> str:
        return f'{prefix}stores/{self.r.file_name(row["label"])}.html'

    def stat(self, row: dict) -> str:
        if row in self.front:
            v = self.r.verdicts(row)
            return f'{v.count("surfaced")} surfaced · {v.count("kept out")} kept out'
        acc, rep, rej, _na = self.r.tally(row)
        return (f'{self.r.level_of(row)} · {acc} served · {rep} reported · {rej} rejected · '
                f'detection on {row.get("checked_at")}')

    def footer(self, page: str) -> str:
        """The figures in every page's footer, and in the JSON-LD description
        the home and scorecard pages carry, from the results file."""
        page = re.sub(r"Measured tamper evidence for \d+ agent memory and checkpoint stores: each row "
                      r"seeded through the store's own API, edited behind its back \w+ ways",
                      f"Measured tamper evidence for {self.stores} agent memory and checkpoint stores: "
                      f"each row seeded through the store's own API, edited behind its back "
                      f"{WORDS[self.n_edits]} ways", page)
        return re.sub(
            r"Measured \d{4}-\d\d-\d\d\. \d+ rows, \d+ stores, \w+ storage-level edits, "
            r"\w+ front-door attacks\.",
            f"Measured {self.date}. {len(self.rows)} rows, {self.stores} stores, "
            f"{WORDS[self.n_edits]} storage-level edits, {WORDS[self.n_front]} front-door attacks.",
            page)

    # --- the matrix, as the board and the scorecard show it ---------------------

    def matrix(self, rows: list[dict], caption: str, prefix: str) -> str:
        fam = self.r.EDITS if rows and rows[0] in self.at_rest else self.r.FRONT_DOOR
        kind = "at-rest" if fam is self.r.EDITS else "front"
        head = "".join(
            f'<th scope="col"><a href="{prefix}edits/{slug}.html"><abbr title="{esc(label)}">'
            f'{tn}</abbr></a></th>'
            for _e, tn, label, slug in fam)
        trs = []
        for i, row in enumerate(rows):
            name = self.name(row)
            meta = self.version(row)
            if fam is self.r.EDITS:
                meta = f"{meta} · {self.r.level_of(row)}"
            tds = []
            for edit, tn, label, _slug in fam:
                c = row["cells"].get(edit, {})
                v = c.get("verdict", "n/a")
                cls, _full, _word = self.r.CLS[v]
                full = "v-" + re.sub(r"[^a-z]+", "-", v)
                data_name = f"{tn}, {label}" if fam is self.r.EDITS else label
                point = row.get("checked_at") or "" if fam is self.r.EDITS else ""
                tds.append(
                    f'<td class="{cls} {full}"><button type="button" class="cellbtn" '
                    f'data-row="{esc(row["label"])}" data-attack="{edit}" '
                    f'data-name="{esc(data_name)}" data-verdict="{v}" '
                    f'data-detail="{esc(c.get("detail") or c.get("error") or "")}" '
                    f'data-point="{point}" aria-label="{esc(name)}, {esc(data_name)}: {v}">'
                    f'{v}</button></td>')
            trs.append(f'<tr style="--i:{i}"><th scope="row"><a class="rowlink" '
                       f'href="{self.href(row, prefix)}"><span class="rowname">{esc(name)}</span>'
                       f'<span class="rowmeta">{esc(meta)}</span></a></th>' + "".join(tds) + "</tr>")
        return (f'<table class="matrix {kind}"><caption>{caption}</caption><thead><tr>'
                f'<th scope="col" class="corner">Store</th>{head}</tr></thead><tbody>'
                + "".join(trs) + "</tbody></table>")

    def matrices(self, prefix: str) -> list[str]:
        return [self.matrix(self.no_claim, "Stores that make no integrity claim", prefix),
                self.matrix(self.claim, "Stores that claim tamper evidence", prefix),
                self.matrix(self.front, "Retrieval stores attacked through their own API", prefix)]

    @staticmethod
    def replace_tables(page: str, tables: list[str]) -> str:
        found = re.findall(r"<table class=\"matrix.*?</table>", page, re.S)
        if len(found) != len(tables):
            raise SystemExit(f"expected {len(tables)} matrix tables on the page, found {len(found)}")
        it = iter(tables)
        return re.sub(r"<table class=\"matrix.*?</table>", lambda _m: next(it), page, flags=re.S)

    # --- pages ---------------------------------------------------------------

    def scorecard(self, page: str) -> str:
        page = self.replace_tables(page, self.matrices(""))
        page = re.sub(r'<p class="lede">.*?</p>',
                      f'<p class="lede">{len(self.at_rest)} at-rest rows against '
                      f'{WORDS[self.n_edits]} edits, {len(self.front)} front-door rows against '
                      f'{WORDS[self.n_front]} attacks, from one results file, {self.date}. The same '
                      f'file renders the README and this page, so they cannot disagree.</p>',
                      page, count=1, flags=re.S)
        page = re.sub(r"<h2>At rest: \w+ edits, \d+ rows</h2>",
                      f"<h2>At rest: {WORDS[self.n_edits]} edits, {len(self.at_rest)} rows</h2>", page)
        page = re.sub(r"<h2>Front door: \w+ attacks, \d+ rows</h2>",
                      f"<h2>Front door: {WORDS[self.n_front]} attacks, {len(self.front)} rows</h2>", page)
        return self.footer(page)

    def home(self, page: str) -> str:
        page = self.replace_tables(page, self.matrices(""))
        lede = (f'<strong>{len(self.no_claim)} of the {len(self.no_claim)} rows that make no '
                f'integrity claim served every applicable edit as genuine.</strong> {self.stores} '
                f'agent memory and checkpoint stores, {len(self.rows)} rows, seeded through their own '
                f'APIs, edited behind their backs {WORDS[self.n_edits]} ways, and asked to read their '
                f'memory again. The {len(self.claim)} that claim tamper evidence were measured against '
                f'that claim, with the detection point named.')
        page = re.sub(r'<p class="lede">.*?</p>', f'<p class="lede">{lede}</p>', page, count=1, flags=re.S)
        page = re.sub(r'<p class="mono muted">Measured \d{4}-\d\d-\d\d · .*? · agmi (\S+)</p>',
                      lambda m: f'<p class="mono muted">Measured {self.date} · '
                                f'{esc(self.results.get("platform", ""))} · agmi {m.group(1)}</p>',
                      page, count=1)
        return self.footer(page)

    def store_index(self, page: str) -> str:
        def ol(rows: list[dict]) -> str:
            return '<ol class="storelist">' + "".join(
                f'<li><a href="{self.href(row, "../")}"><span class="rowname">{esc(self.name(row))}'
                f'</span><span class="rowmeta">{esc(self.version(row))}</span></a>'
                f'<span class="rowstat mono">{esc(self.stat(row))}</span></li>'
                for row in rows) + "</ol>"
        lists = [ol(self.no_claim), ol(self.claim), ol(self.front)]
        found = re.findall(r'<ol class="storelist">.*?</ol>', page, re.S)
        if len(found) != 3:
            raise SystemExit(f"expected 3 store lists, found {len(found)}")
        it = iter(lists)
        page = re.sub(r'<ol class="storelist">.*?</ol>', lambda _m: next(it), page, flags=re.S)
        page = re.sub(r'<p class="lede">\d+ rows across \d+ stores, measured \d{4}-\d\d-\d\d\.',
                      f'<p class="lede">{len(self.rows)} rows across {self.stores} stores, '
                      f'measured {self.date}.', page, count=1)
        return self.footer(page)

    def level_page(self, page: str, level: str) -> str:
        at = [row for row in self.at_rest if self.r.level_of(row) == level]
        above = [row for row in self.at_rest if self.r.level_of(row) > level]
        at_html = '<ul class="dist">' + "".join(
            f'<li><a href="{self.href(row, "../")}">{esc(self.name(row))}</a> '
            f'<span class="muted">detection on {row.get("checked_at")}</span></li>'
            for row in at) + "</ul>"
        above_html = '<ul class="dist">' + "".join(
            f'<li><a href="{self.href(row, "../")}">{esc(self.name(row))}</a> '
            f'<span class="mono">{self.r.level_of(row)}</span></li>'
            for row in above) + "</ul>"
        page = re.sub(rf"(<h2>Stores at {level} today</h2>).*?(</section>)",
                      lambda m: m.group(1) + at_html + m.group(2), page, count=1, flags=re.S)
        page = re.sub(rf"(<h2>Stores above {level}</h2>).*?(</section>)",
                      lambda m: m.group(1) + above_html + m.group(2), page, count=1, flags=re.S)
        return self.footer(page)

    # --- edit pages ------------------------------------------------------------

    def _rows_for(self, edit: str) -> list[dict]:
        fam = self.at_rest if any(edit == e for e, *_ in self.r.EDITS) else self.front
        return fam

    def edit_counts(self, edit: str) -> tuple[int, int]:
        vs = [row["cells"].get(edit, {}).get("verdict", "n/a") for row in self._rows_for(edit)]
        return (vs.count("accepted") + vs.count("surfaced"),
                vs.count("rejected") + vs.count("kept out"))

    def every_store(self, edit: str) -> str:
        rows = self._rows_for(edit)
        order = (["accepted", "reported", "rejected", "n/a"] if rows is self.at_rest
                 else ["surfaced", "kept out", "n/a"])
        out = []
        for v in order:
            hits = [row for row in rows if row["cells"].get(edit, {}).get("verdict", "n/a") == v]
            if not hits:
                continue
            cls, _full, _word = self.r.CLS[v]
            items = []
            for row in hits:
                c = row["cells"].get(edit, {})
                detail = c.get("detail") or c.get("error") or ""
                extra = (f' <span class="muted">{esc(detail)}</span>'
                         if v in ("reported", "rejected", "kept out") and detail else "")
                items.append(f'<li><a href="{self.href(row, "../")}">{esc(self.name(row))}</a>{extra}</li>')
            out.append(f'<h3 class="{cls}"><span class="verdict">{v}</span> {len(hits)}</h3>'
                       f'<ul class="dist">' + "".join(items) + "</ul>")
        return "".join(out)

    def today(self, edit: str) -> str:
        rows = self._rows_for(edit)
        groups = ([("v-rej-t", "rejected on read", "rejected"), ("v-rep-t", "reported on audit", "reported"),
                   ("v-acc-t", "accepted", "accepted")] if rows is self.at_rest
                  else [("v-rej-t", "kept out", "kept out"), ("v-acc-t", "surfaced", "surfaced")])
        parts = []
        for cls, word, v in groups:
            names = [self.name(row) for row in rows
                     if row["cells"].get(edit, {}).get("verdict", "n/a") == v]
            if names:
                parts.append(f'<dt class="{cls}">{word}</dt><dd>{esc(", ".join(names))}</dd>')
        return f'<h4>Today, measured {self.date}</h4><dl class="today">' + "".join(parts) + "</dl>"

    def edit_page(self, page: str, edit: str) -> str:
        page = re.sub(r"<h4>Today, measured \d{4}-\d\d-\d\d</h4><dl class=\"today\">.*?</dl>",
                      lambda _m: self.today(edit), page, count=1, flags=re.S)
        page = re.sub(r"(<h2>Every store, this edit</h2>).*?(</section>)",
                      lambda m: m.group(1) + self.every_store(edit) + m.group(2),
                      page, count=1, flags=re.S)
        page = re.sub(r"All \d+ edits and attacks",
                      f"All {self.n_edits + self.n_front} edits and attacks", page)
        return self.footer(page)

    def edits_index(self, page: str) -> str:
        def card(m: re.Match) -> str:
            slug = m.group(1)
            edit = next((e for e, _t, _l, s in self.r.EDITS + self.r.FRONT_DOOR if s == slug), None)
            if edit is None:
                return m.group(0)
            serve, refuse = self.edit_counts(edit)
            return re.sub(r'<p class="mono muted">\d+ serve it · \d+ refuse it</p>',
                          f'<p class="mono muted">{serve} serve it · {refuse} refuse it</p>', m.group(0))
        page = re.sub(r'<li><a href="\.\./edits/([a-z-]+)\.html">.*?</li>', card, page, flags=re.S)
        page = page.replace("Fifteen ways to change what an agent remembers. Nine need access",
                            f"{WORDS[self.n_edits + self.n_front].capitalize()} ways to change what an "
                            f"agent remembers. {WORDS[self.n_edits].capitalize()} need access")
        page = page.replace("Nine storage-level edits (", f"{WORDS[self.n_edits].capitalize()} storage-level edits (")
        return self.footer(page)

    # --- machine-readable ------------------------------------------------------

    def llms(self, text: str) -> str:
        base = "https://agentmemoryintegrity.org"
        lines = []
        for row in self.rows:
            if row in self.front:
                v = self.r.verdicts(row)
                stat = f'{v.count("surfaced")} surfaced, {v.count("kept out")} kept out'
            else:
                acc, rep, rej, _na = self.r.tally(row)
                stat = (f"{acc} served, {rep} reported, {rej} rejected, detection on "
                        f"{row.get('checked_at')}, level {self.r.level_of(row)}")
            lines.append(f"- [{self.name(row)}]({base}/stores/{self.r.file_name(row['label'])}.html): "
                         f"{self.version(row)}; {stat}")
        text = re.sub(r"(## Stores \(one page each\)\n).*?(\n\n)", lambda m: m.group(1) + "\n".join(lines) + m.group(2),
                      text, count=1, flags=re.S)
        text = re.sub(r"\(0\.6\.\d+, measured \d{4}-\d\d-\d\d\)",
                      lambda m: m.group(0).split(", measured")[0] + f", measured {self.date})", text, count=1)
        text = text.replace("Nine storage-level edits (T1 to T9)",
                            f"{WORDS[self.n_edits].capitalize()} storage-level edits (T1 to T{self.n_edits})")
        return text

    def sitemap(self, out: pathlib.Path) -> str:
        pages = sorted(p.relative_to(out).as_posix() for p in out.rglob("*.html"))
        urls = "".join(f"<url><loc>https://agentmemoryintegrity.org/{p}</loc>"
                       f"<lastmod>{self.date}</lastmod></url>" for p in pages)
        return ('<?xml version="1.0" encoding="UTF-8"?>'
                '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' + urls + "</urlset>")

    # --- driver --------------------------------------------------------------

    def build(self, ref: pathlib.Path, out: pathlib.Path) -> None:
        def read(rel: str) -> str:
            src = out / rel
            if not src.exists():
                src = ref / rel
            return src.read_text()

        (out / "index.html").write_text(self.home(read("index.html")))
        (out / "scorecard.html").write_text(self.scorecard(read("scorecard.html")))
        (out / "stores").mkdir(exist_ok=True)
        (out / "stores" / "index.html").write_text(self.store_index(read("stores/index.html")))
        for level in ("L0", "L1", "L2", "L3", "L4"):
            rel = f"levels/{level.lower()}.html"
            (out / rel).write_text(self.level_page(read(rel), level))
        for edit, _tn, _label, slug in self.r.EDITS + self.r.FRONT_DOOR:
            rel = f"edits/{slug}.html"
            if not (out / rel).exists() and not (ref / rel).exists():
                raise SystemExit(f"no page for edit {edit}: add site/content/pages/{rel}")
            (out / rel).write_text(self.edit_page(read(rel), edit))
        (out / "edits" / "index.html").write_text(self.edits_index(read("edits/index.html")))
        # every other page only needs its footer figures brought up to date
        for p in out.rglob("*.html"):
            p.write_text(self.footer(p.read_text()))
        (out / "llms.txt").write_text(self.llms(read("llms.txt")))
        (out / "sitemap.xml").write_text(self.sitemap(out))
        for name in ("edits.html", "findings.html"):
            if (ref / name).exists() and not (out / name).exists():
                (out / name).write_text(self.footer((ref / name).read_text()))
        if (ref / "findings").exists():
            (out / "findings").mkdir(exist_ok=True)
            for f in (ref / "findings").glob("*.html"):
                if not (out / "findings" / f.name).exists():
                    (out / "findings" / f.name).write_text(self.footer(f.read_text()))
        print(f"pages: home, scorecard, store index, 5 level pages, "
              f"{len(self.r.EDITS) + len(self.r.FRONT_DOOR)} edit pages, llms.txt, sitemap "
              f"({self.date}, {len(self.rows)} rows, {self.stores} stores)")
