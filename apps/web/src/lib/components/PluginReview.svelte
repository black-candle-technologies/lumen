<script lang="ts">
	import Check from '@lucide/svelte/icons/check';
	import Pause from '@lucide/svelte/icons/pause';
	import ShieldAlert from '@lucide/svelte/icons/shield-alert';
	import type { PluginVersionDetails, StagedPluginReview } from '$lib/api';
	import PluginAuthority from './PluginAuthority.svelte';
	import PluginFailures from './PluginFailures.svelte';
	import PluginSettings from './PluginSettings.svelte';

	let {
		staged,
		detail,
		busy = false,
		onAction
	}: {
		staged: StagedPluginReview | null;
		detail: PluginVersionDetails | null;
		busy?: boolean;
		onAction: (kind: string, digest: string) => void;
	} = $props();
</script>

{#if staged}
	<section class="plugin-review">
		<header class="plugin-title">
			<div>
				<span>{staged.runtime}</span>
				<h2>{staged.plugin_id}</h2>
				<p>{staged.version}</p>
			</div>
			<div class="plugin-actions">
				<button class="secondary" type="button" onclick={() => onAction('plugin.disable', staged.package_digest)} disabled={busy}>
					<Pause size={15} /> Disable
				</button>
				<button class="primary" type="button" onclick={() => onAction('plugin.enable', staged.package_digest)} disabled={busy}>
					<Check size={15} /> Enable
				</button>
			</div>
		</header>

		<div class="hash-grid">
			<div><span>Package</span><code>{staged.package_digest}</code></div>
			<div><span>Manifest</span><code>{staged.manifest_digest}</code></div>
			<div><span>Artifact</span><code>{staged.artifact_digest}</code></div>
		</div>

		<details class="file-hashes">
			<summary>Package files</summary>
			{#each Object.entries(staged.file_hashes) as [path, digest]}
				<div><code>{path}</code><code>{digest}</code></div>
			{/each}
		</details>

		{#if detail}
			<div class="state-line"><ShieldAlert size={15} /> {detail.state}</div>
			<PluginAuthority components={detail.components} />
			<PluginSettings settings={detail.settings} />
			<PluginFailures failures={detail.failures} />
		{/if}
	</section>
{/if}
