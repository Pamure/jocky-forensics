<script>
	let { data } = $props();
</script>

<svelte:head>
	<title>{data.title} · JOCKY docs</title>
	{#if data.description}
		<meta name="description" content={data.description} />
	{/if}
</svelte:head>

{@html data.html}
