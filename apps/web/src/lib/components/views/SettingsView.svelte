<script lang="ts">
	import { settingsGroups } from '$lib/mockData';
</script>

<div class="settings-grid">
	{#each settingsGroups as group}
		<section class="panel settings-panel">
			<div class="panel-head">
				<h2>{group.name}</h2>
				<span class="badge neutral">not wired</span>
			</div>
			{#each group.fields as field}
				<label>
					<span>{field}</span>
					<input disabled value="Placeholder only" />
				</label>
			{/each}
		</section>
	{:else}
		<p class="empty">No settings groups.</p>
	{/each}
</div>
