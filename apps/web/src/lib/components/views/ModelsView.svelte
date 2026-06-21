<script lang="ts">
	import { models } from '$lib/mockData';
</script>

<div class="stack">
	<div class="notice">
		<strong>Provider visibility only.</strong>
		<span> Model status and endpoints are placeholder values. No provider is called from this UI.</span>
	</div>

	<div class="cards">
		{#each models as model}
			<article class="panel item-card">
				<div class="panel-head">
					<h2>{model.provider}</h2>
					<span class="badge {model.status}">Status: {model.status}</span>
				</div>
				<dl class="detail-list compact-list">
					<dt>Model</dt><dd>{model.model}</dd>
					<dt>Endpoint</dt><dd>{model.endpoint}</dd>
					<dt>Streaming</dt><dd>{model.streaming ? 'yes' : 'no'}</dd>
					<dt>Role</dt><dd>{model.role}</dd>
				</dl>
			</article>
		{:else}
			<p class="empty">No model providers configured.</p>
		{/each}
	</div>
</div>
