/**
 * Markdown → HTML pipeline for the docs.
 *
 * `marked` does the parsing; everything site-specific (heading anchors and ids,
 * table-of-contents extraction, syntax highlighting, external-link handling)
 * lives here so pages stay plain markdown files that any editor can open.
 */
import { marked } from 'marked';
import { highlight } from './highlight.js';

/** GitHub-style slug used for heading ids and the TOC. */
export function slugify(text) {
	return String(text)
		.toLowerCase()
		.replace(/<[^>]+>/g, '')
		.replace(/&[a-z]+;/g, '')
		.replace(/[^\p{L}\p{N}\s-]/gu, '')
		.trim()
		.replace(/\s+/g, '-')
		.slice(0, 80);
}

const renderer = {
	heading({ tokens, depth }) {
		const text = this.parser.parseInline(tokens);
		const id = slugify(text);
		return `<h${depth} id="${id}"><a class="anchor" href="#${id}" aria-hidden="true">#</a>${text}</h${depth}>\n`;
	},
	code({ text, lang }) {
		const language = (lang || 'text').split(/\s+/)[0];
		const html = highlight(text, language);
		return `<pre data-lang="${language}"><code class="language-${language}">${html}</code></pre>\n`;
	},
	link({ href, title, tokens }) {
		const text = this.parser.parseInline(tokens);
		const external = /^https?:\/\//i.test(href);
		const attrs = external ? ' target="_blank" rel="noreferrer noopener"' : '';
		const titleAttr = title ? ` title="${title}"` : '';
		return `<a href="${href}"${titleAttr}${attrs}>${text}</a>`;
	},
	table(token) {
		// wrap tables so wide evidence tables scroll instead of breaking layout.
		// parseInline() takes a token array — building the cells first and then
		// parsing the concatenation would feed it strings and throw.
		const header = `<thead><tr>${token.header
			.map((cell) => `<th>${this.parser.parseInline(cell.tokens)}</th>`)
			.join('')}</tr></thead>`;
		const body = `<tbody>${token.rows
			.map(
				(row) =>
					`<tr>${row
						.map((cell) => `<td>${this.parser.parseInline(cell.tokens)}</td>`)
						.join('')}</tr>`
			)
			.join('')}</tbody>`;
		return `<div class="table-wrap"><table>${header}${body}</table></div>\n`;
	}
};

marked.use({ renderer, gfm: true, breaks: false, mangle: false, headerIds: false });

/** Extract h2/h3 headings from rendered HTML for the "on this page" rail. */
export function extractToc(html) {
	const toc = [];
	const pattern = /<h([23]) id="([^"]+)"[^>]*>([\s\S]*?)<\/h\1>/g;
	let match;
	while ((match = pattern.exec(html))) {
		const depth = Number(match[1]);
		const text = match[3].replace(/<[^>]+>/g, '').trim();
		toc.push({ depth, id: match[2], text });
	}
	return toc;
}

/** Render markdown, returning both HTML and the heading outline. */
export function renderMarkdown(markdown) {
	const html = marked.parse(markdown || '');
	return { html, toc: extractToc(html) };
}

/** Strip markdown/frontmatter down to searchable plain text. */
export function toPlainText(markdown) {
	return String(markdown || '')
		.replace(/^---[\s\S]*?---/, '')
		.replace(/```[\s\S]*?```/g, ' ')
		.replace(/`[^`]*`/g, ' ')
		.replace(/!\[[^\]]*\]\([^)]*\)/g, ' ')
		.replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
		.replace(/[#>*_|-]+/g, ' ')
		.replace(/\s+/g, ' ')
		.trim();
}

export { marked };
