#!/usr/bin/env python3
"""
Zero-dependency documentation build.

`npm run build` (SvelteKit) is the primary path, but a documentation site that
can only be built when a JavaScript toolchain installs successfully is a
liability — especially for an air-gapped reviewer. This script renders the same
`site/content/**.md` files, with the same navigation manifest and the same
stylesheet, into plain HTML under `site/dist/` using nothing but the standard
library.

    python3 site/tools/build_static.py [--out site/dist]

Differences from the SvelteKit build are limited to interactivity: search is
performed client-side against `assets/search-index.json` instead of a bundled
index, and there is no client-side router (plain links).
"""
from __future__ import annotations

import argparse
import html
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

SITE_DIR = Path(__file__).resolve().parents[1]
CONTENT = SITE_DIR / "content"
NAV_FILE = SITE_DIR / "nav.json"
CSS = SITE_DIR / "src" / "app.css"

LANGUAGES = {"jocky", "python", "bash", "sh", "json", "text", "console", ""}

KEYWORDS = {
    "jocky": {"let", "set", "if", "elif", "else", "while", "for", "in", "fn", "return",
              "break", "continue", "emit", "try", "catch", "and", "or", "not",
              "true", "false", "nil"},
    "python": {"def", "class", "import", "from", "as", "if", "elif", "else", "while",
               "for", "in", "return", "yield", "try", "except", "finally", "with",
               "lambda", "not", "and", "or", "is", "None", "True", "False", "self",
               "raise", "pass", "async", "await", "match", "case"},
    "bash": {"if", "then", "else", "fi", "for", "while", "do", "done", "case", "esac",
             "export", "local", "echo", "cd", "set", "sudo", "curl", "wget", "grep",
             "sed", "awk", "cat", "chmod", "mkdir", "rm", "git", "npm", "python3",
             "pip", "docker", "vercel", "tar", "kill", "find", "xargs"},
}
NAMESPACES = {"proc", "net", "fs", "sys", "det", "ioc", "mem"}
TOKEN_CLASSES = {
    "comment": "tok-comment", "string": "tok-string", "number": "tok-number",
    "keyword": "tok-keyword", "namespace": "tok-builtin", "call": "tok-func",
    "property": "tok-property", "punct": "tok-punct",
}


def _span(kind: str, text: str) -> str:
    return f'<span class="{TOKEN_CLASSES[kind]}">{html.escape(text)}</span>'


def highlight(code: str, language: str) -> str:
    """Minimal, dependency-free highlighter mirroring `src/lib/highlight.js`.

    Both build paths must produce the same-looking page, so the token vocabulary
    lives here too: comments, strings, numbers, keywords, namespaces, call sites
    and assignment targets — enough for documentation snippets.
    """
    names = KEYWORDS.get(language, set())
    namespace_pattern = re.compile(r"^(?:" + "|".join(sorted(NAMESPACES)) + r")\b")
    comment_pattern = re.compile(r"^#[^\n]*")
    string_pattern = re.compile(r'^"""(?:.|\n)*?"""|^"(?:[^"\\]|\\.)*"|^\'(?:[^\'\\]|\\.)*\'')
    word_pattern = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*")
    number_pattern = re.compile(r"^\d+(?:\.\d+)?")
    punct_pattern = re.compile(r"^[{}()\[\];:,.]")

    out: List[str] = []
    index = 0
    while index < len(code):
        rest = code[index:]
        match = comment_pattern.match(rest)
        if match:
            out.append(_span("comment", match.group(0)))
            index += len(match.group(0))
            continue
        match = string_pattern.match(rest)
        if match:
            out.append(_span("string", match.group(0)))
            index += len(match.group(0))
            continue
        match = namespace_pattern.match(rest)
        if match:
            out.append(_span("namespace", match.group(0)))
            index += len(match.group(0))
            continue
        match = word_pattern.match(rest)
        if match:
            word = match.group(0)
            following = rest[len(word):].lstrip()
            if word in names:
                out.append(_span("keyword", word))
            elif following.startswith("("):
                out.append(_span("call", word))
            elif following.startswith(("=", ":")) and language != "bash":
                out.append(_span("property", word))
            else:
                out.append(html.escape(word))
            index += len(word)
            continue
        match = number_pattern.match(rest)
        if match:
            out.append(_span("number", match.group(0)))
            index += len(match.group(0))
            continue
        match = punct_pattern.match(rest)
        if match:
            out.append(_span("punct", match.group(0)))
            index += 1
            continue
        out.append(html.escape(code[index]))
        index += 1
    return "".join(out)


# --------------------------------------------------------------------- markdown
def slugify(text: str) -> str:
    text = re.sub(r"<[^>]+>", "", text)
    text = html.unescape(text).lower()
    text = re.sub(r"[^\w\s-]", "", text, flags=re.UNICODE)
    return re.sub(r"\s+", "-", text.strip())[:80]


def inline(text: str) -> str:
    """Escape HTML, then apply inline markdown (code, links, emphasis).

    A small set of inline HTML tags is preserved verbatim: the documentation uses
    ``<strong>``/``<em>``/``<code>`` inside markdown on purpose, and escaping them
    would show the tags to the reader.
    """
    stash: List[str] = []

    def keep(snippet: str) -> str:
        stash.append(snippet)
        return f"\x00{len(stash) - 1}\x00"

    text = re.sub(r"`([^`]+)`", lambda m: keep(f"<code>{html.escape(m.group(1))}</code>"), text)
    text = re.sub(
        r"\[([^\]]+)\]\(([^)]+)\)",
        lambda m: keep(
            f'<a href="{html.escape(m.group(2), quote=True)}"'
            + (' target="_blank" rel="noreferrer noopener"' if m.group(2).startswith("http") else "")
            + f">{html.escape(m.group(1))}</a>"
        ),
        text,
    )
    text = re.sub(r"</?(?:strong|em|b|i|code|kbd|br|sub|sup)\s*/?>", lambda m: keep(m.group(0)), text)
    # emphasis is inserted through the stash as well: escaping runs afterwards,
    # and tags inserted before it would be shown to the reader as literal text
    text = re.sub(r"\*\*([^*]+)\*\*",
                  lambda m: keep(f"<strong>{html.escape(m.group(1))}</strong>"), text)
    text = re.sub(r"(?<!\*)\*([^*\n]+)\*(?!\*)",
                  lambda m: keep(f"<em>{html.escape(m.group(1))}</em>"), text)
    text = html.escape(text)
    # restore in reverse: an outer snippet can contain the placeholder of an
    # inner one, and replacing the inner one first would strand a marker
    for index in range(len(stash) - 1, -1, -1):
        text = text.replace(f"\x00{index}\x00", stash[index])
    return text


def render_table(rows: List[str]) -> str:
    cells: List[List[str]] = []
    for row in rows:
        stripped = row.strip().strip("|")
        cells.append([cell.strip() for cell in stripped.split("|")])
    header, body = cells[0], cells[2:]
    head_html = "".join(f"<th>{inline(cell)}</th>" for cell in header)
    body_html = "".join(
        "<tr>" + "".join(f"<td>{inline(cell)}</td>" for cell in row) + "</tr>" for row in body
    )
    return (
        f'<div class="table-wrap"><table><thead><tr>{head_html}</tr></thead>'
        f"<tbody>{body_html}</tbody></table></div>"
    )


def render_markdown(markdown: str) -> Tuple[str, List[Dict[str, Any]]]:
    """Render the markdown subset used by this documentation."""
    # generated pages carry an HTML comment telling maintainers not to edit them;
    # rendered literally it would be shown to the reader
    markdown = re.sub(r"<!--.*?-->", "", markdown, flags=re.DOTALL)
    lines = markdown.replace("\r\n", "\n").split("\n")
    out: List[str] = []
    toc: List[Dict[str, Any]] = []
    index = 0
    paragraph: List[str] = []
    list_stack: List[str] = []
    in_list = False

    def flush_paragraph() -> None:
        if paragraph:
            out.append(f"<p>{inline(' '.join(paragraph))}</p>")
            paragraph.clear()

    def close_lists() -> None:
        nonlocal in_list
        while list_stack:
            out.append(f"</{list_stack.pop()}>")
        in_list = False

    while index < len(lines):
        line = lines[index]

        fence = re.match(r"^```(\w*)\s*$", line)
        if fence:
            flush_paragraph()
            close_lists()
            language = fence.group(1).lower()
            index += 1
            code: List[str] = []
            while index < len(lines) and not lines[index].startswith("```"):
                code.append(lines[index])
                index += 1
            index += 1
            label = language if language in LANGUAGES and language else "text"
            source = "\n".join(code)
            body = html.escape(source) if label in ("text", "console") else highlight(source, label)
            out.append(f'<pre data-lang="{label}"><code class="language-{label}">{body}</code></pre>')
            continue

        heading = re.match(r"^(#{1,4})\s+(.*)$", line)
        if heading:
            flush_paragraph()
            close_lists()
            depth = len(heading.group(1))
            text = heading.group(2).strip()
            anchor = slugify(text)
            if depth in (2, 3):
                toc.append({"depth": depth, "id": anchor,
                            "text": re.sub(r"<[^>]+>", "", inline(text))})
            out.append(
                f'<h{depth} id="{anchor}"><a class="anchor" href="#{anchor}" aria-hidden="true">#</a>'
                f"{inline(text)}</h{depth}>"
            )
            index += 1
            continue

        if re.match(r"^\s*\|.*\|\s*$", line):
            flush_paragraph()
            close_lists()
            rows: List[str] = []
            while index < len(lines) and re.match(r"^\s*\|.*\|\s*$", lines[index]):
                rows.append(lines[index])
                index += 1
            if len(rows) >= 2 and set(rows[1].replace("|", "").replace(" ", "")) <= set("-:"):
                out.append(render_table(rows))
            else:
                out.append("<pre><code>" + html.escape("\n".join(rows)) + "</code></pre>")
            continue

        if re.match(r"^\s*[-*]\s+", line):
            flush_paragraph()
            if not list_stack or list_stack[-1] != "ul":
                close_lists()
                out.append("<ul>")
                list_stack.append("ul")
            out.append(f"<li>{inline(re.sub(r'^\s*[-*]\s+', '', line))}</li>")
            in_list = True
            index += 1
            continue

        if re.match(r"^\s*\d+\.\s+", line):
            flush_paragraph()
            if not list_stack or list_stack[-1] != "ol":
                close_lists()
                out.append("<ol>")
                list_stack.append("ol")
            out.append(f"<li>{inline(re.sub(r'^\s*\d+\.\s+', '', line))}</li>")
            in_list = True
            index += 1
            continue

        if line.startswith(">"):
            flush_paragraph()
            close_lists()
            quote: List[str] = []
            while index < len(lines) and lines[index].startswith(">"):
                quote.append(lines[index].lstrip("> ").strip())
                index += 1
            out.append(f"<blockquote><p>{inline(' '.join(quote))}</p></blockquote>")
            continue

        if re.match(r"^\s*(---|\*\*\*)\s*$", line):
            flush_paragraph()
            close_lists()
            out.append("<hr />")
            index += 1
            continue

        if not line.strip():
            flush_paragraph()
            if in_list and (index + 1 >= len(lines) or not re.match(r"^\s*([-*]|\d+\.)\s+", lines[index + 1] or "")):
                close_lists()
            index += 1
            continue

        paragraph.append(line.strip())
        index += 1

    flush_paragraph()
    close_lists()
    return "\n".join(out), toc


# ------------------------------------------------------------------------- site
def page_title(markdown: str, fallback: str) -> str:
    match = re.search(r"^#\s+(.+)$", markdown, re.MULTILINE)
    return match.group(1).strip() if match else fallback


def description(markdown: str) -> str:
    body = re.sub(r"^#.*$", "", markdown, count=1, flags=re.MULTILINE)
    match = re.search(r"^(?![#>|`-])(.{40,200}?)(?:\.\s|\n\n)", body, re.MULTILINE)
    return (match.group(1).strip() + ".") if match else ""


def sidebar_html(items: List[Dict[str, str]], active: str) -> str:
    parts: List[str] = []
    manifest = json.loads(NAV_FILE.read_text(encoding="utf-8"))["navigation"]
    for section in manifest:
        parts.append(f"<h2>{html.escape(section['title'])}</h2><ul>")
        for item in section["items"]:
            css = ' class="active"' if item["slug"] == active else ""
            parts.append(
                f'<li><a href="/docs/{item["slug"]}.html"{css}>{html.escape(item["title"])}</a></li>'
            )
        parts.append("</ul>")
    return "\n".join(parts)


THEME_SCRIPT = """<script>
(function () {
  try {
    var stored = localStorage.getItem('jocky-theme');
    var light = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches;
    document.documentElement.dataset.theme = stored || (light ? 'light' : 'dark');
  } catch (e) { document.documentElement.dataset.theme = 'dark'; }
})();
</script>"""


def render_page(slug: str, title: str, body: str, toc: List[Dict[str, Any]],
                previous: Dict[str, str] | None, next_item: Dict[str, str] | None,
                version: str) -> str:
    toc_html = ""
    if len(toc) > 2:
        links = "\n".join(
            f'<li><a href="#{entry["id"]}" class="depth-{entry["depth"]}">{html.escape(entry["text"])}</a></li>'
            for entry in toc
        )
        toc_html = f'<nav class="toc" aria-label="On this page"><h3>On this page</h3><ul>{links}</ul></nav>'

    pager = ["<nav class=\"pager\" aria-label=\"Pagination\">"]
    if previous:
        pager.append(
            f'<a href="/docs/{previous["slug"]}.html"><span class="dir">Previous</span>'
            f'<span>{html.escape(previous["title"])}</span></a>'
        )
    else:
        pager.append("<span></span>")
    if next_item:
        pager.append(
            f'<a href="/docs/{next_item["slug"]}.html" style="text-align:right">'
            f'<span class="dir">Next</span><span>{html.escape(next_item["title"])}</span></a>'
        )
    pager.append("</nav>")

    return f"""<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>{html.escape(title)} · JOCKY docs</title>
<link rel="icon" href="/favicon.svg" />
<link rel="stylesheet" href="/assets/app.css" />
{THEME_SCRIPT}
</head>
<body>
<header class="topbar">
  <button class="plain menu-toggle" type="button" aria-expanded="false">Menu</button>
  <a class="brand" href="/"><span class="mark">JK</span><span>JOCKY</span></a>
  <span class="tag pill" title="Documented version">{html.escape(version)}</span>
  <div class="search">
    <input type="search" id="search" placeholder="Search docs  ( / )" aria-label="Search documentation" />
    <div class="search-results" id="search-results" hidden></div>
  </div>
  <nav>
    <a href="/docs/getting-started/installation.html">Docs</a>
    <a href="/docs/operations/evidence.html">Evidence</a>
    <a href="/docs/project/roadmap.html">Roadmap</a>
    <button class="plain" type="button" id="theme-toggle" title="Toggle colour theme">◐</button>
  </nav>
</header>
<div class="shell">
  <aside class="sidebar" aria-label="Documentation">
{sidebar_html([], slug)}
  </aside>
  <main class="main">
    <div class="content prose">
{body}
{''.join(pager)}
    </div>
    {toc_html}
  </main>
</div>
<script src="/assets/site.js"></script>
</body>
</html>
"""


def build(out_dir: Path) -> Dict[str, Any]:
    from jocky import __version__  # repository package: version comes from source

    manifest = json.loads(NAV_FILE.read_text(encoding="utf-8"))["navigation"]
    flat = [(section["title"], item) for section in manifest for item in section["items"]]
    by_slug = {item["slug"]: item for _section, item in flat}

    pages: Dict[str, Dict[str, Any]] = {}
    for path in sorted(CONTENT.rglob("*.md")):
        slug = str(path.relative_to(CONTENT).with_suffix("")).replace("\\", "/")
        markdown = path.read_text(encoding="utf-8")
        body, toc = render_markdown(markdown)
        pages[slug] = {"title": page_title(markdown, slug), "body": body, "toc": toc,
                       "description": description(markdown), "markdown": markdown}

    missing = sorted(set(by_slug) - set(pages))
    orphaned = sorted(set(pages) - set(by_slug))

    if out_dir.exists():
        shutil.rmtree(out_dir)
    (out_dir / "docs").mkdir(parents=True, exist_ok=True)
    (out_dir / "assets").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(CSS, out_dir / "assets" / "app.css")
    favicon = SITE_DIR / "static" / "favicon.svg"
    if favicon.exists():
        shutil.copyfile(favicon, out_dir / "favicon.svg")

    for index, (_section_title, item) in enumerate(flat):
        slug = item["slug"]
        if slug not in pages:
            continue
        previous = flat[index - 1][1] if index > 0 else None
        following = flat[index + 1][1] if index + 1 < len(flat) else None
        page = pages[slug]
        target = out_dir / "docs" / f"{slug}.html"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            render_page(slug, page["title"], page["body"], page["toc"],
                        previous, following, __version__),
            encoding="utf-8",
        )
    written = sorted(str(path.relative_to(out_dir)) for path in (out_dir / "docs").rglob("*.html"))

    index_html = f"""<!doctype html>
<html lang="en" data-theme="dark"><head><meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>JOCKY — forensic scripting language (SIH26148)</title>
<link rel="icon" href="/favicon.svg" /><link rel="stylesheet" href="/assets/app.css" />
{THEME_SCRIPT}</head><body>
<header class="topbar">
  <a class="brand" href="/"><span class="mark">JK</span><span>JOCKY</span></a>
  <span class="tag pill">{html.escape(__version__)}</span>
  <div class="search"><input type="search" id="search" placeholder="Search docs  ( / )" />
  <div class="search-results" id="search-results" hidden></div></div>
  <nav><a href="/docs/getting-started/installation.html">Docs</a>
  <a href="/docs/operations/evidence.html">Evidence</a>
  <a href="/docs/project/roadmap.html">Roadmap</a>
  <button class="plain" type="button" id="theme-toggle">◐</button></nav>
</header>
<main class="main" style="grid-template-columns:minmax(0,1fr)"><div class="content prose">
{render_markdown((SITE_DIR / 'content' / 'index.md').read_text(encoding='utf-8'))[0]
 if (SITE_DIR / 'content' / 'index.md').exists()
 else '<h1>JOCKY</h1><p>See <a href="/docs/getting-started/installation.html">installation</a>.</p>'}
</div></main>
<script src="/assets/site.js"></script></body></html>
"""
    (out_dir / "index.html").write_text(index_html, encoding="utf-8")

    search_index = [
        {
            "slug": slug,
            "title": page["title"],
            "section": next((section for section, item in flat if item["slug"] == slug), ""),
            "headings": [entry["text"] for entry in page["toc"]],
            "text": re.sub(r"\s+", " ", re.sub(r"[#*`>|-]", " ", page["markdown"]))[:2400],
        }
        for slug, page in pages.items()
    ]
    (out_dir / "assets" / "search-index.json").write_text(
        json.dumps(search_index, ensure_ascii=False), encoding="utf-8"
    )
    (out_dir / "assets" / "site.js").write_text(CLIENT_JS, encoding="utf-8")

    # Publisability: a crawler entry point, a sitemap built from the same
    # manifest the navigation uses, and a 404 page so a mistyped URL does not
    # land on the host's default error screen.
    base = os.environ.get("DOCS_BASE_URL", "https://jocky.vercel.app").rstrip("/")
    urls = [f"{base}/"] + [f"{base}/docs/{item['slug']}" for _s, item in flat
                           if item["slug"] in pages]
    (out_dir / "sitemap.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + "\n".join(f"  <url><loc>{url}</loc></url>" for url in urls)
        + "\n</urlset>\n",
        encoding="utf-8",
    )
    (out_dir / "robots.txt").write_text(
        f"User-agent: *\nAllow: /\nSitemap: {base}/sitemap.xml\n", encoding="utf-8"
    )
    (out_dir / "404.html").write_text(
        render_page("404", "Page not found",
                    "<h1>Page not found</h1><p>That documentation page does not exist. "
                    'Start from the <a href="/">overview</a> or use the search box.</p>',
                    [], None, None, __version__),
        encoding="utf-8",
    )

    return {
        "out": str(out_dir),
        "pages": len(pages),
        "written": written,
        "missing": missing,
        "orphaned": orphaned,
        "bytes": sum(path.stat().st_size for path in out_dir.rglob("*") if path.is_file()),
        "built_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "version": __version__,
    }


CLIENT_JS = """// Theme toggle, copy buttons and offline search for the static build.
(function () {
	var toggle = document.getElementById('theme-toggle');
	if (toggle) {
		toggle.addEventListener('click', function () {
			var root = document.documentElement;
			var next = root.dataset.theme === 'dark' ? 'light' : 'dark';
			root.dataset.theme = next;
			try { localStorage.setItem('jocky-theme', next); } catch (e) {}
		});
	}
	var menu = document.querySelector('.menu-toggle');
	if (menu) {
		menu.addEventListener('click', function () {
			var sidebar = document.querySelector('.sidebar');
			sidebar.classList.toggle('open');
			menu.setAttribute('aria-expanded', sidebar.classList.contains('open'));
		});
	}
	document.querySelectorAll('.prose pre').forEach(function (pre) {
		if (pre.dataset.enhanced) return;
		pre.dataset.enhanced = '1';
		var button = document.createElement('button');
		button.className = 'copy';
		button.type = 'button';
		button.textContent = 'Copy';
		button.addEventListener('click', function () {
			var code = pre.querySelector('code');
			navigator.clipboard.writeText(code ? code.innerText : '').then(function () {
				button.textContent = 'Copied';
				setTimeout(function () { button.textContent = 'Copy'; }, 1500);
			});
		});
		pre.appendChild(button);
	});
	var input = document.getElementById('search');
	var results = document.getElementById('search-results');
	var index = null;
	function load() {
		if (index) return Promise.resolve(index);
		return fetch('/assets/search-index.json').then(function (r) { return r.json(); })
			.then(function (data) { index = data; return data; })
			.catch(function () { index = []; return []; });
	}
	if (input && results) {
		window.addEventListener('keydown', function (event) {
			if (event.key === '/' && document.activeElement !== input) { event.preventDefault(); input.focus(); }
			if (event.key === 'Escape') { results.hidden = true; }
		});
		input.addEventListener('input', function () {
			var query = input.value.trim().toLowerCase();
			if (query.length < 2) { results.hidden = true; return; }
			load().then(function (entries) {
				var terms = query.split(/\\s+/);
				var scored = entries.map(function (entry) {
					var score = 0;
					var title = entry.title.toLowerCase();
					var headings = entry.headings.join(' ').toLowerCase();
					var text = entry.text.toLowerCase();
					terms.forEach(function (term) {
						if (title.indexOf(term) >= 0) score += 12;
						if (headings.indexOf(term) >= 0) score += 5;
						if (text.indexOf(term) >= 0) score += 2;
					});
					return { entry: entry, score: score };
				}).filter(function (row) { return row.score > 0; })
					.sort(function (a, b) { return b.score - a.score; })
					.slice(0, 8);
				if (!scored.length) { results.hidden = true; return; }
				results.innerHTML = scored.map(function (row) {
					return '<a href="/docs/' + row.entry.slug + '.html">' + row.entry.title +
						'<small>' + row.entry.section + '</small></a>';
				}).join('');
				results.hidden = false;
			});
		});
	}
})();
"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the documentation without npm")
    parser.add_argument("--out", default=str(SITE_DIR / "dist"))
    args = parser.parse_args()
    summary = build(Path(args.out))
    print(json.dumps(summary, indent=2))
    if summary["missing"]:
        print(f"WARNING: navigation references {len(summary['missing'])} missing page(s): "
              f"{', '.join(summary['missing'])}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
