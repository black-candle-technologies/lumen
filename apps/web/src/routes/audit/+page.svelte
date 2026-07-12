<script lang="ts">
	import { onMount } from 'svelte';
	import ChevronDown from '@lucide/svelte/icons/chevron-down';
	import ChevronRight from '@lucide/svelte/icons/chevron-right';
	import RefreshCw from '@lucide/svelte/icons/refresh-cw';
	import { ApiClient, ApiError, type AuditEvent } from '$lib/api';
	import { connection, isConfigured } from '$lib/connection';

	let events = $state<AuditEvent[]>([]);
	let expanded = $state<number | null>(null);
	let loading = $state(true);
	let error = $state('');

	onMount(load);

	async function load() {
		if (!isConfigured($connection)) { loading = false; return; }
		loading = true;
		try { events = await new ApiClient($connection).listAudit(); error = ''; }
		catch (cause) { error = cause instanceof ApiError ? cause.message : 'Audit events could not be loaded.'; }
		finally { loading = false; }
	}
</script>

<section class="page audit-page">
	<header class="page-heading">
		<div><h1>Audit</h1><p>Ordered runtime events</p></div>
		<button class="icon-button" type="button" aria-label="Refresh audit events" title="Refresh" onclick={load} disabled={loading}><RefreshCw size={17} /></button>
	</header>
	{#if error}<div class="notice error">{error}</div>{/if}
	<div class="audit-table" role="table" aria-label="Audit events">
		<div class="audit-header" role="row"><span>Seq</span><span>Event</span><span>Outcome</span><span>Time</span><span></span></div>
		{#each events as event (event.sequence)}
			<div class="audit-row" role="row">
				<span class="sequence">{event.sequence}</span>
				<strong>{event.kind}</strong>
				<span class:success={event.outcome === 'success'} class="outcome">{event.outcome}</span>
				<time>{new Date(event.timestamp).toLocaleString()}</time>
				<button class="icon-button" type="button" aria-label={`Inspect audit event ${event.sequence}`} title="Inspect" onclick={() => (expanded = expanded === event.sequence ? null : event.sequence)}>
					{#if expanded === event.sequence}<ChevronDown size={16} />{:else}<ChevronRight size={16} />{/if}
				</button>
			</div>
			{#if expanded === event.sequence}
				<div class="audit-detail"><pre>{JSON.stringify(event.payload, null, 2)}</pre><code>{event.event_id}</code></div>
			{/if}
		{/each}
		{#if !loading && events.length === 0}<div class="empty">No audit events.</div>{/if}
	</div>
</section>

<style>
	.audit-table { border-top: 1px solid #d9ddd6; background: #fff; }
	.audit-header, .audit-row { display: grid; grid-template-columns: 60px minmax(180px, 1.3fr) 110px minmax(170px, 1fr) 38px; align-items: center; gap: 12px; min-height: 45px; padding: 0 10px; border-bottom: 1px solid #e3e6e0; }
	.audit-header { min-height: 34px; color: #777d75; background: #f2f4f0; font-size: 10px; font-weight: 700; text-transform: uppercase; }
	.audit-row { color: #434841; font-size: 12px; }
	.audit-row strong { color: #2f342e; font-size: 12px; overflow-wrap: anywhere; }
	.sequence { font-family: "SFMono-Regular", Consolas, monospace; color: #777d75; }
	.outcome { width: max-content; border-radius: 4px; padding: 3px 6px; background: #f1e6d5; color: #865a1c; }
	.outcome.success { background: #e0eee5; color: #276344; }
	.audit-row time { color: #6f746d; }
	.audit-detail { padding: 14px 20px 16px 82px; border-bottom: 1px solid #e3e6e0; background: #fafbf8; }
	.audit-detail pre { margin: 0 0 9px; font-size: 12px; line-height: 1.55; white-space: pre-wrap; overflow-wrap: anywhere; }
	.audit-detail code { color: #777d75; font-size: 10px; }
	.empty { padding: 48px 20px; color: #777d75; text-align: center; font-size: 13px; }
	@media (max-width: 760px) {
		.audit-page { padding-left: 0; padding-right: 0; }
		.audit-page .page-heading, .audit-page :global(.notice) { margin-left: 16px; margin-right: 16px; }
		.audit-header { display: none; }
		.audit-row { grid-template-columns: 42px minmax(0, 1fr) 82px 34px; gap: 7px; padding: 7px 8px; }
		.audit-row time { display: none; }
		.audit-detail { padding-left: 58px; }
	}
</style>
