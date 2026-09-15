/**
 * Sidebar manifest (data lives in `../../nav.json` so the zero-dependency
 * static builder and the SvelteKit app cannot disagree about the navigation).
 *
 * Ordering is explicit rather than alphabetical: it is the reading path a new
 * user should follow, and it lets `content.js` fail the build when a listed page
 * is missing.
 */
import manifest from '../../nav.json';

export const navigation = manifest.navigation;

/** Flat list in reading order (used for prev/next pagination). */
export const flatNavigation = navigation.flatMap((section) =>
	section.items.map((item) => ({ ...item, section: section.title }))
);

/** Look up the section a slug belongs to. */
export function sectionOf(slug) {
	for (const section of navigation) {
		if (section.items.some((item) => item.slug === slug)) return section.title;
	}
	return '';
}

/** Previous/next page in reading order. */
export function neighbours(slug) {
	const index = flatNavigation.findIndex((item) => item.slug === slug);
	return {
		previous: index > 0 ? flatNavigation[index - 1] : null,
		next: index >= 0 && index < flatNavigation.length - 1 ? flatNavigation[index + 1] : null
	};
}
