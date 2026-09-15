import adapter from '@sveltejs/adapter-static';

/**
 * The documentation site is fully prerendered so it can be published to any
 * static host (Vercel, GitHub Pages, an air-gapped nginx box) and read offline.
 */
export default {
	kit: {
		adapter: adapter({
			pages: 'build',
			assets: 'build',
			fallback: null,
			precompress: false
		}),
		prerender: { entries: ['*'], handleHttpError: 'warn' }
	}
};
