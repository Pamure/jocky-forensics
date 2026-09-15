<script>
	import { navigation } from '$lib/nav.js';
	import { getPage } from '$lib/content.js';
</script>

<svelte:head>
	<title>Documentation · JOCKY</title>
	<meta
		name="description"
		content="JOCKY documentation: installation, the scripting language, runtime collectors, execution modes, CLI, agents and the evidence harness."
	/>
</svelte:head>

# Documentation

Everything JOCKY does, in reading order. The language and runtime pages contain
runnable examples; the operations pages describe the multi-host side; the
security pages state plainly what the tool cannot do.

{#each navigation as section}
	<h2>{section.title}</h2>
	<ul>
		{#each section.items as item}
			{@const page = getPage(item.slug)}
			<li>
				<a href="/docs/{item.slug}">{item.title}</a>
				{#if page?.description}— {page.description}{/if}
			</li>
		{/each}
	</ul>
{/each}
