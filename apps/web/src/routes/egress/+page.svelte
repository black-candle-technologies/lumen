<script lang="ts">
	import { onMount } from 'svelte';
	import RefreshCw from '@lucide/svelte/icons/refresh-cw';
	import ShieldCheck from '@lucide/svelte/icons/shield-check';
	import ShieldOff from '@lucide/svelte/icons/shield-off';
	import { ApiClient, ApiError, type ChannelMapping } from '$lib/api';
	import { connection, isConfigured } from '$lib/connection';

	let mappings = $state<ChannelMapping[]>([]);
	let loading = $state(true);
	let busyKey = $state('');
	let error = $state('');
	let notice = $state('');

	onMount(load);

	async function load() {
		if (!isConfigured($connection)) { loading = false; return; }
		loading = true;
		try {
			mappings = await new ApiClient($connection).listChannelMappings();
			error = '';
		} catch (cause) {
			error = cause instanceof ApiError ? cause.message : 'Egress controls could not be loaded.';
		} finally { loading = false; }
	}

	async function setAllowed(mapping: ChannelMapping, allowed: boolean) {
		const key = mappingKey(mapping);
		busyKey = key;
		try {
			const updated = await new ApiClient($connection).updateChannelMapping({
				provider: mapping.provider,
				external_workspace_id: mapping.external_workspace_id,
				channel_id: mapping.channel_id,
				external_user_id: mapping.external_user_id,
				lumen_provider: mapping.lumen_identity.provider,
				lumen_subject: mapping.lumen_identity.subject,
				allowed
			});
			mappings = mappings.map((current) => mappingKey(current) === key ? updated : current);
			notice = `${allowed ? 'Allowed' : 'Disabled'} ${channelScope(updated)}`;
			error = '';
		} catch (cause) {
			error = cause instanceof ApiError ? cause.message : 'Channel allowlist update failed.';
		} finally { busyKey = ''; }
	}

	function mappingKey(mapping: ChannelMapping): string {
		return `${mapping.provider}:${mapping.external_workspace_id}:${mapping.channel_id}:${mapping.external_user_id}`;
	}

	function channelScope(mapping: ChannelMapping): string {
		return `${mapping.provider}:${mapping.external_workspace_id}:${mapping.channel_id}`;
	}
</script>

<section class="page egress-page">
	<header class="page-heading">
		<div><h1>Egress</h1><p>{mappings.length} channel identities</p></div>
		<button class="icon-button" type="button" aria-label="Refresh egress controls" title="Refresh" onclick={load} disabled={loading}><RefreshCw size={17} /></button>
	</header>
	{#if error}<div class="notice error">{error}</div>{/if}
	{#if notice}<div class="notice">{notice}</div>{/if}

	{#if loading}
		<div class="empty">Loading egress controls...</div>
	{:else if mappings.length === 0}
		<div class="empty">No channel mappings.</div>
	{:else}
		<div class="egress-table" role="table" aria-label="Channel egress mappings">
			<div class="egress-header" role="row"><span>Channel</span><span>External user</span><span>Lumen identity</span><span>Status</span><span></span></div>
			{#each mappings as mapping (mappingKey(mapping))}
				<div class="egress-row" role="row">
					<div>
						<span class="field-label">Channel</span>
						<code>{channelScope(mapping)}</code>
					</div>
					<div>
						<span class="field-label">External user</span>
						<code>{mapping.external_user_id}</code>
					</div>
					<div>
						<span class="field-label">Lumen identity</span>
						<code>{mapping.lumen_identity.provider}/{mapping.lumen_identity.subject}</code>
					</div>
					<div>
						<span class:allowed={mapping.allowed} class="egress-status">{mapping.allowed ? 'allowed' : 'disabled'}</span>
					</div>
					<div class="egress-actions">
						{#if mapping.allowed}
							<button class="icon-button" type="button" aria-label={`Disable ${mapping.provider} ${mapping.external_workspace_id} ${mapping.channel_id}`} title="Disable channel" onclick={() => setAllowed(mapping, false)} disabled={busyKey === mappingKey(mapping)}><ShieldOff size={17} /></button>
						{:else}
							<button class="icon-button" type="button" aria-label={`Allow ${mapping.provider} ${mapping.external_workspace_id} ${mapping.channel_id}`} title="Allow channel" onclick={() => setAllowed(mapping, true)} disabled={busyKey === mappingKey(mapping)}><ShieldCheck size={17} /></button>
						{/if}
					</div>
				</div>
			{/each}
		</div>
	{/if}
</section>

<style>
	.egress-table { border: 1px solid #dfe3dc; border-radius: 6px; background: #fff; overflow: hidden; }
	.egress-header, .egress-row { display: grid; grid-template-columns: minmax(170px, 1.15fr) minmax(120px, 0.7fr) minmax(140px, 0.8fr) 96px 42px; gap: 12px; align-items: center; min-height: 48px; padding: 0 10px; border-bottom: 1px solid #edf0ea; }
	.egress-header { min-height: 34px; color: #73786f; background: #f3f5f1; font-size: 10px; font-weight: 700; text-transform: uppercase; }
	.egress-row { font-size: 12px; }
	.egress-row > div { min-width: 0; display: grid; gap: 4px; }
	.egress-row code { overflow-wrap: anywhere; word-break: break-word; font-size: 11px; }
	.egress-status { width: max-content; border-radius: 4px; padding: 3px 6px; background: #f1e6d5; color: #865a1c; font-size: 11px; font-weight: 700; }
	.egress-status.allowed { background: #e0eee5; color: #276344; }
	.egress-actions { justify-items: end; }
	.empty { padding: 48px 20px; border: 1px solid #dfe3dc; border-radius: 6px; background: #fff; color: #777d75; text-align: center; font-size: 13px; }
	@media (max-width: 760px) {
		.egress-page { padding-left: 0; padding-right: 0; }
		.egress-page .page-heading, .egress-page :global(.notice) { margin-left: 16px; margin-right: 16px; }
		.egress-table { border-left: 0; border-right: 0; border-radius: 0; }
		.egress-header { display: none; }
		.egress-row { grid-template-columns: minmax(0, 1fr) 40px; gap: 8px; min-height: 0; padding: 10px 12px; }
		.egress-row > div:nth-child(1), .egress-row > div:nth-child(2), .egress-row > div:nth-child(3), .egress-row > div:nth-child(4) { grid-column: 1; }
		.egress-actions { grid-column: 2; grid-row: 1 / span 4; align-self: center; }
	}
</style>
