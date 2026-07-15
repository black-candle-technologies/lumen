<script lang="ts">
	import { onMount } from 'svelte';
	import RefreshCw from '@lucide/svelte/icons/refresh-cw';
	import ShieldCheck from '@lucide/svelte/icons/shield-check';
	import ShieldOff from '@lucide/svelte/icons/shield-off';
	import {
		ApiClient,
		ApiError,
		type ChannelMapping,
		type DataClass,
		type DestinationPolicy,
		type ProviderPolicy
	} from '$lib/api';
	import { connection, isConfigured } from '$lib/connection';

	let providers = $state<ProviderPolicy[]>([]);
	let destinations = $state<DestinationPolicy[]>([]);
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
			const client = new ApiClient($connection);
			[providers, destinations, mappings] = await Promise.all([
				client.listProviderPolicies(),
				client.listDestinationPolicies(),
				client.listChannelMappings()
			]);
			error = '';
		} catch (cause) {
			error = cause instanceof ApiError ? cause.message : 'Egress controls could not be loaded.';
		} finally { loading = false; }
	}

	async function setDestinationEnabled(policy: DestinationPolicy, enabled: boolean) {
		const key = `destination:${policy.destination}`;
		busyKey = key;
		try {
			const updated = await new ApiClient($connection).updateDestinationPolicy({
				destination: policy.destination,
				enabled,
				allowed_data_classes: policy.allowed_data_classes
			});
			destinations = destinations.map((current) => current.destination === policy.destination ? updated : current);
			notice = `${enabled ? 'Allowed' : 'Disabled'} ${updated.destination}`;
			error = '';
		} catch (cause) {
			error = cause instanceof ApiError ? cause.message : 'Destination policy update failed.';
		} finally { busyKey = ''; }
	}

	async function setProviderEnabled(policy: ProviderPolicy, enabled: boolean) {
		await updateProvider(policy, enabled, workspaceClasses(policy));
	}

	async function setProviderClass(policy: ProviderPolicy, dataClass: DataClass, allowed: boolean) {
		const current = workspaceClasses(policy);
		const next = allowed
			? Array.from(new Set([...current, dataClass]))
			: current.filter((value) => value !== dataClass);
		await updateProvider(policy, policy.enabled, orderedClasses(next));
	}

	async function updateProvider(policy: ProviderPolicy, enabled: boolean, allowedClasses: DataClass[]) {
		const key = `provider:${policy.provider_id}`;
		busyKey = key;
		try {
			const updated = await new ApiClient($connection).updateProviderPolicy({
				provider_id: policy.provider_id,
				enabled,
				workspace_allowed_data_classes: allowedClasses
			});
			providers = providers.map((current) => current.provider_id === policy.provider_id ? updated : current);
			notice = updated.state === 'approval_requested'
				? `Approval requested for provider ${updated.provider_id}`
				: `${enabled ? 'Enabled' : 'Disabled'} provider ${updated.provider_id}`;
			error = '';
		} catch (cause) {
			error = cause instanceof ApiError ? cause.message : 'Provider policy update failed.';
		} finally { busyKey = ''; }
	}

	async function setChannelAllowed(mapping: ChannelMapping, allowed: boolean) {
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

	function classList(policy: DestinationPolicy | ProviderPolicy): string {
		return policy.allowed_data_classes.join(', ');
	}

	function workspaceClasses(policy: ProviderPolicy): DataClass[] {
		return policy.workspace_policy?.allowed_data_classes ?? policy.allowed_data_classes;
	}

	function workspaceClassList(policy: ProviderPolicy): string {
		return workspaceClasses(policy).join(', ');
	}

	function orderedClasses(classes: DataClass[]): DataClass[] {
		return (['public', 'workspace', 'sensitive'] as DataClass[]).filter((dataClass) => classes.includes(dataClass));
	}
</script>

<section class="page egress-page">
	<header class="page-heading">
		<div><h1>Egress</h1><p>{providers.length} providers, {destinations.length} destinations, {mappings.length} channel identities</p></div>
		<button class="icon-button" type="button" aria-label="Refresh egress controls" title="Refresh" onclick={load} disabled={loading}><RefreshCw size={17} /></button>
	</header>
	{#if error}<div class="notice error">{error}</div>{/if}
	{#if notice}<div class="notice">{notice}</div>{/if}

	{#if loading}
		<div class="empty">Loading egress controls...</div>
	{:else if providers.length === 0 && destinations.length === 0 && mappings.length === 0}
		<div class="empty">No egress policies.</div>
	{:else}
		<section class="egress-section">
			<h2>Providers</h2>
			{#if providers.length === 0}
				<div class="subtle-empty">No provider policies.</div>
			{:else}
				<div class="egress-table" role="table" aria-label="Provider egress policies">
					<div class="egress-header provider-header" role="row"><span>Provider</span><span>Endpoint</span><span>Workspace classes</span><span>Status</span><span></span></div>
					{#each providers as policy (policy.provider_id)}
						<div class="egress-row provider-row" role="row">
							<div>
								<span class="field-label">Provider</span>
								<code>{policy.provider_id}</code>
								<span class="micro">{policy.endpoint_class} · {policy.model} · priority {policy.priority}</span>
								{#if policy.credential_configured}<span class="micro">credential configured</span>{/if}
							</div>
							<div>
								<span class="field-label">Endpoint</span>
								<code>{policy.endpoint}</code>
							</div>
							<div>
								<span class="field-label">Workspace classes</span>
								<code>{workspaceClassList(policy)}</code>
								<div class="class-toggles" aria-label={`Workspace data classes for provider ${policy.provider_id}`}>
									{#each (['public', 'workspace', 'sensitive'] as DataClass[]) as dataClass}
										<label>
											<input
												type="checkbox"
												checked={workspaceClasses(policy).includes(dataClass)}
												disabled={busyKey === `provider:${policy.provider_id}`}
												onchange={(event) => setProviderClass(policy, dataClass, event.currentTarget.checked)}
											/>
											<span>{dataClass}</span>
										</label>
									{/each}
								</div>
							</div>
							<div>
								<span class:allowed={policy.enabled} class="egress-status">{policy.enabled ? 'enabled' : 'disabled'}</span>
							</div>
							<div class="egress-actions">
								{#if policy.enabled}
									<button class="icon-button" type="button" aria-label={`Disable provider ${policy.provider_id}`} title="Disable provider" onclick={() => setProviderEnabled(policy, false)} disabled={busyKey === `provider:${policy.provider_id}`}><ShieldOff size={17} /></button>
								{:else}
									<button class="icon-button" type="button" aria-label={`Enable provider ${policy.provider_id}`} title="Enable provider" onclick={() => setProviderEnabled(policy, true)} disabled={busyKey === `provider:${policy.provider_id}`}><ShieldCheck size={17} /></button>
								{/if}
							</div>
						</div>
					{/each}
				</div>
			{/if}
		</section>

		<section class="egress-section">
			<h2>Destinations</h2>
			{#if destinations.length === 0}
				<div class="subtle-empty">No destination policies.</div>
			{:else}
				<div class="egress-table" role="table" aria-label="Destination egress policies">
					<div class="egress-header destination-header" role="row"><span>Destination</span><span>Data classes</span><span>Revision</span><span>Status</span><span></span></div>
					{#each destinations as policy (policy.destination)}
						<div class="egress-row destination-row" role="row">
							<div>
								<span class="field-label">Destination</span>
								<code>{policy.destination}</code>
							</div>
							<div>
								<span class="field-label">Data classes</span>
								<code>{classList(policy)}</code>
							</div>
							<div>
								<span class="field-label">Revision</span>
								<code>{policy.revision}</code>
							</div>
							<div>
								<span class:allowed={policy.enabled} class="egress-status">{policy.enabled ? 'allowed' : 'disabled'}</span>
							</div>
							<div class="egress-actions">
								{#if policy.enabled}
									<button class="icon-button" type="button" aria-label={`Disable destination ${policy.destination}`} title="Disable destination" onclick={() => setDestinationEnabled(policy, false)} disabled={busyKey === `destination:${policy.destination}`}><ShieldOff size={17} /></button>
								{:else}
									<button class="icon-button" type="button" aria-label={`Allow destination ${policy.destination}`} title="Allow destination" onclick={() => setDestinationEnabled(policy, true)} disabled={busyKey === `destination:${policy.destination}`}><ShieldCheck size={17} /></button>
								{/if}
							</div>
						</div>
					{/each}
				</div>
			{/if}
		</section>

		<section class="egress-section">
			<h2>Channels</h2>
			{#if mappings.length === 0}
				<div class="subtle-empty">No channel mappings.</div>
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
									<button class="icon-button" type="button" aria-label={`Disable ${mapping.provider} ${mapping.external_workspace_id} ${mapping.channel_id}`} title="Disable channel" onclick={() => setChannelAllowed(mapping, false)} disabled={busyKey === mappingKey(mapping)}><ShieldOff size={17} /></button>
								{:else}
									<button class="icon-button" type="button" aria-label={`Allow ${mapping.provider} ${mapping.external_workspace_id} ${mapping.channel_id}`} title="Allow channel" onclick={() => setChannelAllowed(mapping, true)} disabled={busyKey === mappingKey(mapping)}><ShieldCheck size={17} /></button>
								{/if}
							</div>
						</div>
					{/each}
				</div>
			{/if}
		</section>
	{/if}
</section>

<style>
	.egress-section { display: grid; gap: 9px; margin-bottom: 18px; }
	.egress-section h2 { margin: 0; font-size: 14px; }
	.egress-table { border: 1px solid #dfe3dc; border-radius: 6px; background: #fff; overflow: hidden; }
	.egress-header, .egress-row { display: grid; grid-template-columns: minmax(170px, 1.15fr) minmax(120px, 0.7fr) minmax(140px, 0.8fr) 96px 42px; gap: 12px; align-items: center; min-height: 48px; padding: 0 10px; border-bottom: 1px solid #edf0ea; }
	.destination-header, .destination-row { grid-template-columns: minmax(220px, 1.4fr) minmax(120px, 0.8fr) 72px 96px 42px; }
	.egress-header { min-height: 34px; color: #73786f; background: #f3f5f1; font-size: 10px; font-weight: 700; text-transform: uppercase; }
	.egress-row { font-size: 12px; }
	.egress-row > div { min-width: 0; display: grid; gap: 4px; }
	.egress-row code { overflow-wrap: anywhere; word-break: break-word; font-size: 11px; }
	.micro { display: block; color: #73786f; font-size: 11px; }
	.egress-status { width: max-content; border-radius: 4px; padding: 3px 6px; background: #f1e6d5; color: #865a1c; font-size: 11px; font-weight: 700; }
	.egress-status.allowed { background: #e0eee5; color: #276344; }
	.egress-actions { justify-items: end; }
	.provider-header, .provider-row { grid-template-columns: minmax(150px, 0.9fr) minmax(190px, 1.2fr) minmax(180px, 1fr) 96px 42px; }
	.class-toggles { display: flex; flex-wrap: wrap; gap: 5px; }
	.class-toggles label { display: inline-flex; align-items: center; gap: 4px; color: #555b53; font-size: 11px; }
	.class-toggles input { width: 13px; height: 13px; margin: 0; }
	.empty { padding: 48px 20px; border: 1px solid #dfe3dc; border-radius: 6px; background: #fff; color: #777d75; text-align: center; font-size: 13px; }
	@media (max-width: 760px) {
		.egress-page { padding-left: 0; padding-right: 0; }
		.egress-page .page-heading, .egress-page :global(.notice) { margin-left: 16px; margin-right: 16px; }
		.egress-table { border-left: 0; border-right: 0; border-radius: 0; }
		.egress-header { display: none; }
		.egress-section h2 { margin-left: 12px; }
		.egress-row, .destination-row { grid-template-columns: minmax(0, 1fr) 40px; gap: 8px; min-height: 0; padding: 10px 12px; }
		.egress-row > div:nth-child(1), .egress-row > div:nth-child(2), .egress-row > div:nth-child(3), .egress-row > div:nth-child(4) { grid-column: 1; }
		.egress-actions { grid-column: 2; grid-row: 1 / span 4; align-self: center; }
	}
</style>
