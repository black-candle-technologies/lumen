<script lang="ts">
	import { onMount } from 'svelte';
	import RefreshCw from '@lucide/svelte/icons/refresh-cw';
	import { ApiClient, ApiError, type PluginVersionDetails, type StagedPluginReview } from '$lib/api';
	import PluginReview from '$lib/components/PluginReview.svelte';
	import { connection, connectionState } from '$lib/connection';

	let staged = $state<StagedPluginReview[]>([]);
	let selected = $state<StagedPluginReview | null>(null);
	let detail = $state<PluginVersionDetails | null>(null);
	let loadState = $state<'loading' | 'success' | 'error'>('loading');
	let loadError = $state('');
	let lastLoadedAt = $state('');
	let loadedWorkspace = $state('');
	let busyKeys = $state<string[]>([]);
	let detailGeneration = 0;
	let detailAbort: AbortController | null = null;
	let error = $state('');
	let notice = $state('');

	onMount(load);

	async function load() {
		if ($connectionState.kind !== 'connected') {
			loadState = 'error';
			loadError = 'Runtime connection is not verified. Open connection settings.';
			return;
		}
		loadState = 'loading';
		try {
			const client = new ApiClient($connection);
			staged = await client.listStagedPlugins(50);
			selected = staged[0] ?? null;
			detail = selected ? await client.getPluginVersion(selected.plugin_id, selected.version) : null;
			loadError = '';
			error = '';
			lastLoadedAt = new Date().toLocaleString();
			loadedWorkspace = $connection.workspaceId;
			loadState = 'success';
		} catch (cause) {
			loadError = cause instanceof ApiError ? cause.message : 'Plugin controls could not be loaded.';
			loadState = 'error';
		}
	}

	async function select(plugin: StagedPluginReview) {
		selected = plugin;
		detail = null;
		detailGeneration += 1;
		const generation = detailGeneration;
		detailAbort?.abort();
		detailAbort = new AbortController();
		const expectedKey = `${plugin.plugin_id}@${plugin.version}`;
		const connectionSnapshot = { ...$connection };
		try {
			const loaded = await new ApiClient(connectionSnapshot, fetch, detailAbort.signal)
				.getPluginVersion(plugin.plugin_id, plugin.version);
			if (generation !== detailGeneration || !selected || `${selected.plugin_id}@${selected.version}` !== expectedKey) return;
			if (loaded.plugin_id !== plugin.plugin_id || loaded.version !== plugin.version) {
				throw new Error('Plugin detail identity mismatch');
			}
			detail = loaded;
			error = '';
		} catch (cause) {
			if (generation !== detailGeneration || detailAbort.signal.aborted) return;
			error = cause instanceof ApiError ? cause.message : 'Plugin details could not be loaded.';
		}
	}

	async function requestAction(kind: string, digest: string) {
		if (!selected || !detail || detail.plugin_id !== selected.plugin_id || detail.version !== selected.version || detail.package_digest !== selected.package_digest) return;
		const key = `${selected.plugin_id}@${selected.version}:${kind}`;
		if (busyKeys.includes(key)) return;
		busyKeys = [...busyKeys, key];
		try {
			const result = await new ApiClient($connection).requestPluginAction({
				kind,
				plugin_id: selected.plugin_id,
				plugin_version: selected.version,
				expected_digest: digest
			});
			notice = `${result.state}: ${result.run_id}`;
			error = '';
		} catch (cause) {
			error = cause instanceof ApiError ? cause.message : 'Plugin action request failed.';
		} finally { busyKeys = busyKeys.filter((current) => current !== key); }
	}
</script>

<section class="page plugins-page">
	<header class="page-heading">
		<div><h1>Plugins</h1><p>{lastLoadedAt ? `${staged.length} staged for review${loadState === 'error' ? ' (stale)' : ''}` : 'Count unavailable'}</p></div>
		<button class="icon-button" type="button" aria-label="Refresh plugins" title="Refresh" onclick={load} disabled={loadState === 'loading'}><RefreshCw size={17} /></button>
	</header>
	{#if loadError}
		<div class="notice error" role="alert">{loadError} <button type="button" onclick={load}>Retry</button></div>
	{/if}
	{#if loadState === 'error' && lastLoadedAt}
		<div class="notice" role="status">Showing stale data for workspace {loadedWorkspace} from {lastLoadedAt}.</div>
	{/if}
	{#if error}<div class="notice error">{error}</div>{/if}
	{#if notice}<div class="notice">{notice}</div>{/if}
	{#if loadState === 'loading' && !lastLoadedAt}
		<div class="empty">Loading plugins...</div>
	{:else if loadState === 'error' && !lastLoadedAt}
		<div class="empty">Plugin data is unavailable.</div>
	{:else if staged.length === 0}
		<div class="empty">{loadState === 'error' ? 'The previously loaded staged plugin list was empty.' : 'No staged plugins.'}</div>
	{:else}
		<div class="plugins-layout">
			<div class="plugin-list" aria-label="Plugin packages">
				{#each staged as plugin (`${plugin.plugin_id}@${plugin.version}`)}
					<button class:active={selected === plugin} type="button" onclick={() => select(plugin)}>
						<strong>{plugin.plugin_id}</strong>
						<span>{plugin.version}</span>
						<code>{plugin.package_digest}</code>
					</button>
				{/each}
			</div>
			<PluginReview staged={selected} {detail} busy={busyKeys.length > 0} onAction={requestAction} />
		</div>
	{/if}
</section>
