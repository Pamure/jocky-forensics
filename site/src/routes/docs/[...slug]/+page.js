import { error, redirect } from '@sveltejs/kit';
import { allSlugs, getPage, validate } from '$lib/content.js';

// Fail the build instead of shipping dead links.
const problems = validate();
if (problems.missing.length) {
	throw new Error(
		`docs navigation references pages that do not exist: ${problems.missing.join(', ')}`
	);
}

/** Enumerate every documentation page so the site can be prerendered. */
export function entries() {
	return allSlugs().map((slug) => ({ slug }));
}

export function load({ params }) {
	if (!params.slug) {
		// `/docs/` reaches the catch-all with an empty slug; the index listing is
		// served by /docs, so send the request there instead of 404ing.
		redirect(307, '/docs');
	}
	const page = getPage(params.slug);
	if (!page) {
		error(404, `No documentation page at /docs/${params.slug}`);
	}
	return {
		slug: page.slug,
		title: page.title,
		description: page.description,
		html: page.html,
		toc: page.toc
	};
}
