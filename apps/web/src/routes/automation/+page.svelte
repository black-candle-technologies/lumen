<script lang="ts">
	import { onMount } from 'svelte';
	import Pause from '@lucide/svelte/icons/pause';
	import Play from '@lucide/svelte/icons/play';
	import RefreshCw from '@lucide/svelte/icons/refresh-cw';
	import { ApiClient, ApiError, type JobReview, type ServiceIdentity } from '$lib/api';
	import { connection, isConfigured } from '$lib/connection';

	let identities = $state<ServiceIdentity[]>([]);
	let jobs = $state<JobReview[]>([]);
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
			[identities, jobs] = await Promise.all([client.listServiceIdentities(), client.listJobs()]);
			error = '';
		} catch (cause) {
			error = cause instanceof ApiError ? cause.message : 'Automation controls could not be loaded.';
		} finally { loading = false; }
	}

	async function setJobEnabled(job: JobReview, enabled: boolean) {
		busyKey = job.job_id;
		try {
			const result = await new ApiClient($connection).requestJobAction(job.job_id, {
				service_subject: job.service.subject,
				schedule: job.schedule,
				prompt: job.prompt,
				data_class: job.data_class,
				max_model_turns: job.max_model_turns,
				max_actions: job.max_actions,
				enabled,
				idempotent: job.idempotent
			});
			jobs = jobs.map((current) => current.job_id === job.job_id ? { ...current, enabled } : current);
			notice = `Approval requested: ${result.run_id}`;
			error = '';
		} catch (cause) {
			error = cause instanceof ApiError ? cause.message : 'Scheduled job update failed.';
		} finally { busyKey = ''; }
	}

	function scheduleText(job: JobReview): string {
		return job.schedule.kind === 'once'
			? `once at ${job.schedule.run_at}`
			: `every ${job.schedule.interval_millis} ms from ${job.schedule.start_at}`;
	}
</script>

<section class="page automation-page">
	<header class="page-heading">
		<div><h1>Automation</h1><p>{jobs.length} jobs, {identities.length} service identities</p></div>
		<button class="icon-button" type="button" aria-label="Refresh automation controls" title="Refresh" onclick={load} disabled={loading}><RefreshCw size={17} /></button>
	</header>
	{#if error}<div class="notice error">{error}</div>{/if}
	{#if notice}<div class="notice">{notice}</div>{/if}

	{#if loading}
		<div class="empty">Loading automation controls...</div>
	{:else}
		<section class="automation-section">
			<h2>Jobs</h2>
			{#if jobs.length === 0}
				<div class="subtle-empty">No scheduled jobs.</div>
			{:else}
				<div class="automation-table" role="table" aria-label="Scheduled jobs">
					<div class="automation-header job-row" role="row"><span>Prompt</span><span>Schedule</span><span>Service</span><span>Status</span><span></span></div>
					{#each jobs as job (job.job_id)}
						<div class="automation-record job-row" role="row">
							<div><span class="field-label">Prompt</span><strong>{job.prompt}</strong><code>{job.job_id}</code></div>
							<div><span class="field-label">Schedule</span><code>{scheduleText(job)}</code><span class="micro">next {job.next_due_at ?? 'none'} · rev {job.revision}</span></div>
							<div><span class="field-label">Service</span><code>{job.service.provider}/{job.service.subject}</code><span class="micro">{job.data_class} · {job.max_actions} actions</span></div>
							<div><span class:allowed={job.enabled} class="automation-status">{job.enabled ? 'enabled' : 'paused'}</span></div>
							<div class="automation-actions">
								{#if job.enabled}
									<button class="icon-button" type="button" aria-label={`Pause job ${job.job_id}`} title="Pause job" onclick={() => setJobEnabled(job, false)} disabled={busyKey === job.job_id}><Pause size={17} /></button>
								{:else}
									<button class="icon-button" type="button" aria-label={`Resume job ${job.job_id}`} title="Resume job" onclick={() => setJobEnabled(job, true)} disabled={busyKey === job.job_id}><Play size={17} /></button>
								{/if}
							</div>
						</div>
					{/each}
				</div>
			{/if}
		</section>

		<section class="automation-section">
			<h2>Service Identities</h2>
			{#if identities.length === 0}
				<div class="subtle-empty">No service identities.</div>
			{:else}
				<div class="automation-table" role="table" aria-label="Service identities">
					<div class="automation-header identity-row" role="row"><span>Identity</span><span>Owner</span><span>Grants</span><span>Status</span></div>
					{#each identities as identity (`${identity.principal.provider}:${identity.principal.subject}`)}
						<div class="automation-record identity-row" role="row">
							<div><span class="field-label">Identity</span><strong>{identity.label}</strong><code>{identity.principal.provider}/{identity.principal.subject}</code></div>
							<div><span class="field-label">Owner</span><code>{identity.owner.provider}/{identity.owner.subject}</code></div>
							<div><span class="field-label">Grants</span><code>{identity.grants.length} grants</code></div>
							<div><span class:allowed={identity.enabled} class="automation-status">{identity.enabled ? 'enabled' : 'disabled'}</span></div>
						</div>
					{/each}
				</div>
			{/if}
		</section>
	{/if}
</section>

<style>
	.automation-section { display: grid; gap: 9px; margin-bottom: 18px; }
	.automation-section h2 { margin: 0; font-size: 14px; }
	.automation-table { border: 1px solid #dfe3dc; border-radius: 6px; background: #fff; overflow: hidden; }
	.automation-header, .automation-record { display: grid; gap: 12px; align-items: center; min-height: 48px; padding: 0 10px; border-bottom: 1px solid #edf0ea; }
	.job-row { grid-template-columns: minmax(210px, 1.3fr) minmax(170px, 0.9fr) minmax(150px, 0.8fr) 88px 42px; }
	.identity-row { grid-template-columns: minmax(170px, 1fr) minmax(130px, 0.7fr) minmax(90px, 0.5fr) 88px; }
	.automation-header { min-height: 34px; color: #73786f; background: #f3f5f1; font-size: 10px; font-weight: 700; text-transform: uppercase; }
	.automation-record { font-size: 12px; }
	.automation-record > div { min-width: 0; display: grid; gap: 4px; }
	.automation-record code { overflow-wrap: anywhere; word-break: break-word; font-size: 11px; }
	.automation-record strong { overflow-wrap: anywhere; }
	.micro { display: block; color: #73786f; font-size: 11px; }
	.automation-status { width: max-content; border-radius: 4px; padding: 3px 6px; background: #f1e6d5; color: #865a1c; font-size: 11px; font-weight: 700; }
	.automation-status.allowed { background: #e0eee5; color: #276344; }
	.automation-actions { justify-items: end; }
	.empty { padding: 48px 20px; border: 1px solid #dfe3dc; border-radius: 6px; background: #fff; color: #777d75; text-align: center; font-size: 13px; }
	@media (max-width: 760px) {
		.automation-page { padding-left: 0; padding-right: 0; }
		.automation-page .page-heading, .automation-page :global(.notice) { margin-left: 16px; margin-right: 16px; }
		.automation-table { border-left: 0; border-right: 0; border-radius: 0; }
		.automation-header { display: none; }
		.automation-section h2 { margin-left: 12px; }
		.job-row, .identity-row { grid-template-columns: minmax(0, 1fr) 40px; gap: 8px; min-height: 0; padding: 10px 12px; }
		.identity-row { grid-template-columns: minmax(0, 1fr); }
		.automation-record > div:nth-child(1), .automation-record > div:nth-child(2), .automation-record > div:nth-child(3), .automation-record > div:nth-child(4) { grid-column: 1; }
		.automation-actions { grid-column: 2; grid-row: 1 / span 4; align-self: center; }
	}
</style>
