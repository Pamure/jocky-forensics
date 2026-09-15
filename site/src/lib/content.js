/**
 * Content loader.
 *
 * Every `content/**\/*.md` file is read at build time, rendered to HTML and
 * indexed for search.  The manifest in `nav.js` is validated against the files
 * that actually exist so a renamed page cannot silently produce a dead link.
 */
import { renderMarkdown, toPlainText } from './markdown.js';
import { flatNavigation } from './nav.js';

const modules = import.meta.glob('../../content/**/*.md', {
	eager: true,
	query: '?raw',
	import: 'default'
});

function firstHeading(markdown, fallback) {
	const match = /^#\s+(.+)$/m.exec(markdown || '');
	return match ? match[1].trim() : fallback;
}

function firstParagraph(markdown) {
	const body = String(markdown || '').replace(/^#[^\n]*\n/, '');
	const match = /^(?![#>|`-])(.{40,220}?)(?:\.\s|\n\n)/m.exec(body);
	if (match) return match[1].replace(/[*_`]/g, '').trim() + '.';
	return '';
}

function slugFromPath(path) {
	return path.replace('../../content/', '').replace(/\.md$/, '');
}

export const pages = Object.entries(modules)
	.map(([path, raw]) => {
		const slug = slugFromPath(path);
		const { html, toc } = renderMarkdown(raw);
		return {
			slug,
			raw: String(raw),
			html,
			toc,
			title: firstHeading(raw, slug),
			description: firstParagraph(raw),
			words: toPlainText(raw).length
		};
	})
	.sort((a, b) => a.slug.localeCompare(b.slug));

const bySlug = new Map(pages.map((page) => [page.slug, page]));

/** Get one page, or `undefined` when the slug does not exist. */
export function getPage(slug) {
	return bySlug.get(slug);
}

/** Slugs that exist, in reading order where known. */
export function allSlugs() {
	const known = flatNavigation.map((item) => item.slug).filter((slug) => bySlug.has(slug));
	const extra = pages.map((page) => page.slug).filter((slug) => !known.includes(slug));
	return [...known, ...extra];
}

/**
 * Fail loudly at build time when navigation references a page that is missing,
 * or when a content file is not reachable from the navigation.
 */
export function validate() {
	const missing = flatNavigation
		.map((item) => item.slug)
		.filter((slug) => !bySlug.has(slug));
	const orphaned = pages
		.map((page) => page.slug)
		.filter((slug) => !flatNavigation.some((item) => item.slug === slug));
	return { missing, orphaned };
}

/** Compact search index: title, section, headings and a text excerpt. */
export const searchIndex = pages.map((page) => ({
	slug: page.slug,
	title: page.title,
	section: flatNavigation.find((item) => item.slug === page.slug)?.section ?? '',
	headings: page.toc.map((entry) => entry.text),
	text: toPlainText(page.raw).slice(0, 2400)
}));

/** Simple ranked search: title hits beat headings, which beat body text. */
export function search(query, limit = 8) {
	const needle = query.trim().toLowerCase();
	if (needle.length < 2) return [];
	const terms = needle.split(/\s+/);
	const scored = [];
	for (const entry of searchIndex) {
		let score = 0;
		const title = entry.title.toLowerCase();
		const headings = entry.headings.join(' ').toLowerCase();
		const text = entry.text.toLowerCase();
		for (const term of terms) {
			if (title.includes(term)) score += 12;
			if (headings.includes(term)) score += 5;
			if (text.includes(term)) score += 2;
		}
		if (score > 0) scored.push({ ...entry, score });
	}
	return scored.sort((a, b) => b.score - a.score).slice(0, limit);
}
