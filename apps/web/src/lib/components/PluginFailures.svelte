<script lang="ts">
	import type { PluginFailureReview } from '$lib/api';

	let { failures }: { failures: PluginFailureReview[] } = $props();
</script>

<section class="plugin-section">
	<header><h2>Failures</h2></header>
	{#if failures.length === 0}
		<div class="subtle-empty">No recorded failures.</div>
	{:else}
		<div class="failure-list">
			{#each failures as failure (`${failure.class}:${failure.last_seen_at}`)}
				<div class="failure-row">
					<strong>{failure.class}</strong>
					<span>{failure.count}</span>
					<time>{new Date(failure.last_seen_at).toLocaleString()}</time>
					<code>{failure.diagnostic_digest}</code>
				</div>
			{/each}
		</div>
	{/if}
</section>
