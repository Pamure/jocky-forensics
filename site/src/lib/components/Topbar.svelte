<script>
	import { page } from '$app/state';
	import Search from '$lib/components/Search.svelte';
	import versions from '$lib/versions.generated.js';

	let { sidebarOpen = false, onToggleSidebar = () => {} } = $props();

	const currentVersion = versions.find((entry) => entry.current) ?? versions[0];

	function toggleTheme() {
		const root = document.documentElement;
		const next = root.dataset.theme === 'dark' ? 'light' : 'dark';
		root.dataset.theme = next;
		try {
			localStorage.setItem('jocky-theme', next);
		} catch (error) {
			/* private mode: the theme simply will not persist */
		}
	}
</script>

<header class="topbar">
	<button class="plain menu-toggle" type="button" aria-expanded={sidebarOpen} onclick={onToggleSidebar}>
		Menu
	</button>

	<a class="brand" href="/">
		<span class="mark">JK</span>
		<span>JOCKY</span>
	</a>
	<span class="tag pill" title="Documented version">
		{currentVersion?.version ?? 'dev'}
	</span>

	<Search />

	<nav>
		<a href="/docs/getting-started/installation" class:active={page.url.pathname.startsWith('/docs')}>Docs</a>
		<a href="/docs/operations/evidence">Evidence</a>
		<a href="/docs/project/roadmap">Roadmap</a>
		<button class="plain" type="button" onclick={toggleTheme} title="Toggle colour theme" aria-label="Toggle colour theme">
			◐
		</button>
	</nav>
</header>
