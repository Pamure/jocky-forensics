<script>
	let { previous = null, next = null } = $props();
</script>

<nav class="pager" aria-label="Pagination">
	{#if previous}
		<a href="/docs/{previous.slug}">
			<span class="dir">Previous</span>
			<span>{previous.title}</span>
		</a>
	{:else}
		<span></span>
	{/if}
	{#if next}
		<a href="/docs/{next.slug}" style="text-align: right">
			<span class="dir">Next</span>
			<span>{next.title}</span>
		</a>
	{/if}
</nav>
