<script lang="ts">
	import type { PluginSettingReview } from '$lib/api';

	let { settings }: { settings: PluginSettingReview[] } = $props();
</script>

<section class="plugin-section">
	<header><h2>Settings</h2></header>
	{#if settings.length === 0}
		<div class="subtle-empty">No scoped settings.</div>
	{:else}
		<div class="settings-list">
			{#each settings as setting (`${setting.scope_type}:${setting.scope_id}:${setting.config_version}`)}
				<article class="setting-row">
					<div>
						<strong>{setting.scope_type}</strong>
						<code>{setting.scope_id}</code>
					</div>
					<span>v{setting.config_version}</span>
					<pre>{JSON.stringify(setting.config, null, 2)}</pre>
					<dl>
						<div><dt>Schema</dt><dd><code>{setting.schema_digest}</code></dd></div>
						<div><dt>Settings</dt><dd><code>{setting.settings_digest}</code></dd></div>
					</dl>
				</article>
			{/each}
		</div>
	{/if}
</section>
