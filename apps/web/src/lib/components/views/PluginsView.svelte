<script lang="ts">
	import { plugins } from '$lib/mock';
</script>

<div class="stack">
	<div class="notice">
		<strong>Permissioned plugins.</strong>
		<span> Every plugin declares scope and permissions before touching local systems.</span>
	</div>

	<div class="cards">
		{#each plugins as plugin}
			<article class="panel item-card">
				<div class="panel-head">
					<h2>{plugin.name}</h2>
					<span class="badge {plugin.enabled ? 'enabled' : 'disabled'}">
						State: {plugin.enabled ? 'enabled' : 'disabled'}
					</span>
				</div>
				<dl class="detail-list compact-list">
					<dt>Permissions</dt><dd>{plugin.permissions.join(', ')}</dd>
					<dt>Version</dt><dd>{plugin.version}</dd>
					<dt>Hash</dt><dd>{plugin.hash}</dd>
					<dt>Scope</dt><dd>{plugin.scope}</dd>
				</dl>
				<button type="button" disabled>{plugin.enabled ? 'Disable' : 'Install'}</button>
			</article>
		{:else}
			<p class="empty">No plugins installed.</p>
		{/each}
	</div>
</div>
