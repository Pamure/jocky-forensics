<script>
	import { navigation } from '$lib/nav.js';

	let { activeSlug = '', open = false } = $props();
</script>

<aside class="sidebar" class:open aria-label="Documentation">
	{#each navigation as section}
		<h2>{section.title}</h2>
		<ul>
			{#each section.items as item}
				<li>
					<a
						href="/docs/{item.slug}"
						class:active={activeSlug === item.slug}
						aria-current={activeSlug === item.slug ? 'page' : undefined}
					>
						{item.title}
					</a>
				</li>
			{/each}
		</ul>
	{/each}
</aside>
