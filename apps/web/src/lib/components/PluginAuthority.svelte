<script lang="ts">
	import type { JsonValue, PluginComponentReview } from '$lib/api';

	let { components }: { components: PluginComponentReview[] } = $props();

	function text(value: JsonValue): string {
		return typeof value === 'string' ? value : JSON.stringify(value);
	}
</script>

<section class="plugin-section">
	<header><h2>Authority</h2></header>
	<div class="authority-table" role="table" aria-label="Plugin authority">
		<div class="authority-header" role="row">
			<span>Component</span><span>Requested</span><span>Effective grants</span><span>Revision</span>
		</div>
		{#each components as component (component.id)}
			<div class="authority-row" role="row">
				<strong>{component.id}</strong>
				<div>
					{#each component.requested_capabilities as capability}
						<code>{text(capability)}</code>
					{/each}
				</div>
				<div>
					{#each component.effective_grants as grant}
						<code>{text(grant)}</code>
					{/each}
				</div>
				<div>
					<span>{component.grant_revision}</span>
					<code>{component.grant_set_digest}</code>
				</div>
			</div>
		{/each}
	</div>
</section>
