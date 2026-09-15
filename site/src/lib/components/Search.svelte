<script>
	import { goto } from '$app/navigation';
	import { search } from '$lib/content.js';

	let query = $state('');
	let open = $state(false);
	let cursor = $state(0);
	let input = $state(null);

	const results = $derived(query.trim().length > 1 ? search(query, 8) : []);

	function go(slug) {
		open = false;
		query = '';
		goto(`/docs/${slug}`);
	}

	function onKeydown(event) {
		if (event.key === 'Escape') {
			open = false;
			input?.blur();
		} else if (event.key === 'ArrowDown' && results.length) {
			event.preventDefault();
			cursor = (cursor + 1) % results.length;
		} else if (event.key === 'ArrowUp' && results.length) {
			event.preventDefault();
			cursor = (cursor - 1 + results.length) % results.length;
		} else if (event.key === 'Enter' && results.length) {
			event.preventDefault();
			go(results[Math.min(cursor, results.length - 1)].slug);
		}
	}

	function onWindowKeydown(event) {
		if (event.key === '/' && document.activeElement !== input) {
			event.preventDefault();
			input?.focus();
			open = true;
		}
	}
</script>

<svelte:window onkeydown={onWindowKeydown} />

<div class="search">
	<input
		bind:this={input}
		bind:value={query}
		type="search"
		placeholder="Search docs  ( / )"
		aria-label="Search documentation"
		onfocus={() => (open = true)}
		oninput={() => {
			open = true;
			cursor = 0;
		}}
		onkeydown={onKeydown}
	/>
	{#if open && results.length}
		<div class="search-results" role="listbox">
			{#each results as result, index}
				<a
					href="/docs/{result.slug}"
					class:active={index === Math.min(cursor, results.length - 1)}
					onclick={(event) => {
						event.preventDefault();
						go(result.slug);
					}}
				>
					{result.title}
					<small>{result.section}{result.headings.length ? ` · ${result.headings.slice(0, 2).join(' · ')}` : ''}</small>
				</a>
			{/each}
		</div>
	{/if}
</div>
