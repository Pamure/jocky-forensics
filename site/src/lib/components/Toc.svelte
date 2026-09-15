<script>
	import { onMount } from 'svelte';

	let { entries = [] } = $props();
	let activeId = $state('');

	onMount(() => {
		const headings = entries
			.map((entry) => document.getElementById(entry.id))
			.filter(Boolean);
		if (!headings.length) return;

		const observer = new IntersectionObserver(
			(records) => {
				for (const record of records) {
					if (record.isIntersecting) {
						activeId = record.target.id;
						break;
					}
				}
			},
			{ rootMargin: '-72px 0px -70% 0px', threshold: [0, 1] }
		);
		for (const heading of headings) observer.observe(heading);
		return () => observer.disconnect();
	});
</script>

<nav class="toc" aria-label="On this page">
	<h3>On this page</h3>
	<ul>
		{#each entries as entry}
			<li>
				<a href="#{entry.id}" class="depth-{entry.depth}" class:active={activeId === entry.id}>
					{entry.text}
				</a>
			</li>
		{/each}
	</ul>
</nav>
