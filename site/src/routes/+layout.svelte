<script>
	import { page } from '$app/state';
	import { afterNavigate } from '$app/navigation';
	import { getPage } from '$lib/content.js';
	import { flatNavigation, sectionOf, neighbours } from '$lib/nav.js';
	import Topbar from '$lib/components/Topbar.svelte';
	import Sidebar from '$lib/components/Sidebar.svelte';
	import Toc from '$lib/components/Toc.svelte';
	import Pager from '$lib/components/Pager.svelte';
	import '../app.css';

	let { children } = $props();

	const slug = $derived(page.url.pathname.replace(/^\/docs\/?/, '').replace(/\/$/, ''));
	const current = $derived(slug ? getPage(slug) : undefined);
	const section = $derived(slug ? sectionOf(slug) : '');
	const { previous, next } = $derived(neighbours(slug));
	let sidebarOpen = $state(false);

	afterNavigate(() => {
		sidebarOpen = false;
		// Code blocks arrive from the server rendered; attach copy buttons once
		// the new page is in the DOM (client-side navigation re-renders them).
		for (const pre of document.querySelectorAll('.prose pre')) {
			if (pre.dataset.enhanced) continue;
			pre.dataset.enhanced = '1';
			const button = document.createElement('button');
			button.type = 'button';
			button.className = 'copy';
			button.textContent = 'Copy';
			button.addEventListener('click', () => {
				const code = pre.querySelector('code');
				navigator.clipboard?.writeText(code ? code.innerText : '').then(() => {
					button.textContent = 'Copied';
					setTimeout(() => (button.textContent = 'Copy'), 1500);
				});
			});
			pre.appendChild(button);
		}
	});
</script>

<svelte:head>
	<title>{current ? `${current.title} · JOCKY` : 'JOCKY — forensic scripting language'}</title>
	{#if current?.description}
		<meta name="description" content={current.description} />
	{/if}
</svelte:head>

<Topbar {sidebarOpen} onToggleSidebar={() => (sidebarOpen = !sidebarOpen)} />

<div class="shell">
	<Sidebar items={flatNavigation} {section} activeSlug={slug} open={sidebarOpen} />
	<main class="main">
		<div class="content prose">
			{@render children()}
			{#if current}
				<Pager {previous} {next} />
			{/if}
		</div>
		{#if current && current.toc.length > 2}
			<Toc entries={current.toc} />
		{/if}
	</main>
</div>
