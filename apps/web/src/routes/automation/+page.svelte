<script lang="ts">
	import { onMount } from 'svelte';
	import Pause from '@lucide/svelte/icons/pause';
	import Play from '@lucide/svelte/icons/play';
	import RefreshCw from '@lucide/svelte/icons/refresh-cw';
	import { ApiClient, ApiError, type JobReview, type ServiceIdentity } from '$lib/api';
	import { connection, connectionState } from '$lib/connection';

	let identities = $state<ServiceIdentity[]>([]);
	let jobs = $state<JobReview[]>([]);
	let loadState = $state<'loading' | 'success' | 'error'>('loading');
	let loadError = $state('');
	let lastLoadedAt = $state('');
	let loadedWorkspace = $state('');
	let busyJobIds = $state<string[]>([]);
	let pendingJobIds = $state<string[]>([]);
	let terminalJobIds = $state<string[]>([]);
	const pendingRuns = new Map<string, { runId: string; after: number }>();
	const watchingRuns = new Map<string, { runId: string; controller: AbortController }>();
	let terminalGeneration = 0;
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
			let observedTerminal = terminalGeneration;
			const [loadedIdentities, initialJobs] = await Promise.all([client.listServiceIdentities(), client.listJobs()]);
			let loadedJobs = initialJobs;
			for (const id of pendingJobIds) {
				const run = pendingRuns.get(id);
				if (!run) continue;
				const status = await client.getRunStatus(run.runId);
				if (status.run_id !== run.runId) throw new Error('Run status does not match the requested run.');
				if (['completed', 'failed', 'cancelled'].includes(status.state) && !terminalJobIds.includes(id)) {
					terminalJobIds = [...terminalJobIds, id];
					terminalGeneration++;
				}
			}
			while (observedTerminal !== terminalGeneration) {
				observedTerminal = terminalGeneration;
				loadedJobs = await client.listJobs();
			}
			if (loadedWorkspace && loadedWorkspace !== $connection.workspaceId) {
				pendingJobIds = [];
				terminalJobIds = [];
				pendingRuns.clear();
				for (const watcher of watchingRuns.values()) watcher.controller.abort();
				watchingRuns.clear();
			} else if (terminalJobIds.length) {
				pendingJobIds = pendingJobIds.filter((id) => !terminalJobIds.includes(id));
				for (const id of terminalJobIds) {
					pendingRuns.delete(id);
					watchingRuns.get(id)?.controller.abort();
					watchingRuns.delete(id);
				}
				terminalJobIds = [];
			}
			identities = loadedIdentities;
			jobs = loadedJobs;
			loadError = '';
			error = '';
			lastLoadedAt = new Date().toLocaleString();
			loadedWorkspace = $connection.workspaceId;
			loadState = 'success';
			for (const id of pendingJobIds) {
				const run = pendingRuns.get(id);
				if (run && !watchingRuns.has(id)) watchJobRun(id, run.runId);
			}
		} catch (cause) {
			loadError = cause instanceof ApiError ? cause.message : 'Automation controls could not be loaded.';
			loadState = 'error';
		}
	}

	async function setJobEnabled(job: JobReview, enabled: boolean) {
		if (busyJobIds.includes(job.job_id) || pendingJobIds.includes(job.job_id)) return;
		busyJobIds = [...busyJobIds, job.job_id];
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
			notice = `Approval requested: ${result.run_id}`;
			pendingJobIds = [...pendingJobIds, job.job_id];
			pendingRuns.set(job.job_id, { runId: result.run_id, after: 0 });
			watchJobRun(job.job_id, result.run_id);
			error = '';
		} catch (cause) {
			error = cause instanceof ApiError ? cause.message : 'Scheduled job update failed.';
		} finally { busyJobIds = busyJobIds.filter((id) => id !== job.job_id); }
	}

	function watchJobRun(jobId: string, runId: string) {
		const run = pendingRuns.get(jobId);
		if (!run || run.runId !== runId || watchingRuns.has(jobId)) return;
		const controller = new AbortController();
		watchingRuns.set(jobId, { runId, controller });
		let terminal = false;
		void new ApiClient($connection).streamRunEvents(runId, run.after, (event) => {
			if (pendingRuns.get(jobId)?.runId !== runId) return;
			run.after = event.id;
			if (['run.completed', 'run.failed', 'run.cancelled', 'run.timed_out'].includes(event.event)) {
				terminal = true;
				terminalJobIds = [...terminalJobIds, jobId];
				terminalGeneration++;
				if (loadState !== 'loading') void load();
			}
		}, controller.signal).then(() => {
			if (!terminal && pendingRuns.get(jobId)?.runId === runId && !controller.signal.aborted)
				error = 'Run status stream ended before a final state. Refresh to retry after reviewing the run.';
		}).catch(() => {
			if (pendingRuns.get(jobId)?.runId === runId && !controller.signal.aborted)
				error = 'Run status is unavailable. Refresh to retry after reviewing the run.';
		}).finally(() => {
			if (watchingRuns.get(jobId)?.runId === runId) watchingRuns.delete(jobId);
		});
	}

	function scheduleText(job: JobReview): string {
		return job.schedule.kind === 'once'
			? `Once at ${formatTimestamp(job.schedule.run_at)}`
			: `Every ${formatDuration(job.schedule.interval_millis)} from ${formatTimestamp(job.schedule.start_at)}`;
	}

	function scheduleRaw(job: JobReview): string {
		return job.schedule.kind === 'once'
			? `run_at=${job.schedule.run_at}`
			: `start_at=${job.schedule.start_at} interval_millis=${job.schedule.interval_millis}`;
	}

	function jobState(job: JobReview): string {
		if (pendingJobIds.includes(job.job_id)) return `Change pending approval; persisted state: ${job.enabled ? 'enabled' : 'paused'}`;
		if (!job.enabled) return 'Paused';
		if (job.last_run_state === 'failed') return 'Failed';
		if (job.last_run_state === 'cancelled') return 'Cancelled';
		if (job.last_run_state === 'unknown') return 'Outcome unknown; reconciliation required';
		if (job.last_run_state === 'running') return 'Running';
		if (job.last_run_state === 'claimed') return 'Pending execution';
		if (job.next_due_at != null) return `Next ${formatTimestamp(job.next_due_at)}`;
		if (job.last_run_state === 'succeeded') return 'Completed';
		return 'No next occurrence';
	}

	function formatTimestamp(timestamp: number): string {
		return new Date(timestamp).toLocaleString(undefined, { timeZoneName: 'short' });
	}

	function formatDuration(milliseconds: number): string {
		if (milliseconds % 86_400_000 === 0) return `${milliseconds / 86_400_000}d`;
		if (milliseconds % 3_600_000 === 0) return `${milliseconds / 3_600_000}h`;
		if (milliseconds % 60_000 === 0) return `${milliseconds / 60_000}m`;
		if (milliseconds % 1_000 === 0) return `${milliseconds / 1_000}s`;
		return `${milliseconds}ms`;
	}
</script>

<section class="page automation-page">
	<header class="page-heading">
		<div><h1>Automation</h1><p>{lastLoadedAt ? `${jobs.length} jobs, ${identities.length} service identities${loadState === 'error' ? ' (stale)' : ''}` : 'Counts unavailable'}</p></div>
		<button class="icon-button" type="button" aria-label="Refresh automation controls" title="Refresh" onclick={load} disabled={loadState === 'loading'}><RefreshCw size={17} /></button>
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
		<div class="empty">Loading automation controls...</div>
	{:else if loadState === 'error' && !lastLoadedAt}
		<div class="empty">Automation data is unavailable.</div>
	{:else}
		<section class="automation-section">
			<h2>Jobs</h2>
			{#if jobs.length === 0}
				<div class="subtle-empty">{loadState === 'error' ? 'The previously loaded job list was empty.' : 'No scheduled jobs.'}</div>
			{:else}
				<div class="automation-table" role="table" aria-label="Scheduled jobs">
					<div class="automation-header job-row" role="row"><span role="columnheader">Prompt</span><span role="columnheader">Schedule</span><span role="columnheader">Service</span><span role="columnheader">Status</span><span role="columnheader" aria-label="Actions"></span></div>
					{#each jobs as job (job.job_id)}
						<div class="automation-record job-row" role="row">
							<div role="cell"><span class="field-label">Prompt</span><strong>{job.prompt}</strong><code>{job.job_id}</code></div>
							<div role="cell"><span class="field-label">Schedule</span><strong>{scheduleText(job)}</strong><code>{scheduleRaw(job)}</code><span class="micro">{jobState(job)} · revision {job.revision}</span></div>
							<div role="cell"><span class="field-label">Service</span><code>{job.service.provider}/{job.service.subject}</code><span class="micro">{job.data_class} · {job.max_actions} actions</span></div>
							<div role="cell"><span class:allowed={job.enabled} class="automation-status">{job.enabled ? 'enabled' : 'paused'}</span></div>
							<div class="automation-actions" role="cell">
								{#if job.enabled}
									<button class="icon-button" type="button" aria-label={`Pause job ${job.job_id}`} title="Pause job" onclick={() => setJobEnabled(job, false)} disabled={busyJobIds.includes(job.job_id) || pendingJobIds.includes(job.job_id)}><Pause size={17} /></button>
								{:else}
									<button class="icon-button" type="button" aria-label={`Resume job ${job.job_id}`} title="Resume job" onclick={() => setJobEnabled(job, true)} disabled={busyJobIds.includes(job.job_id) || pendingJobIds.includes(job.job_id)}><Play size={17} /></button>
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
				<div class="subtle-empty">{loadState === 'error' ? 'The previously loaded service identity list was empty.' : 'No service identities.'}</div>
			{:else}
				<div class="automation-table" role="table" aria-label="Service identities">
					<div class="automation-header identity-row" role="row"><span role="columnheader">Identity</span><span role="columnheader">Owner</span><span role="columnheader">Grants</span><span role="columnheader">Status</span></div>
					{#each identities as identity (`${identity.principal.provider}:${identity.principal.subject}`)}
						<div class="automation-record identity-row" role="row">
							<div role="cell"><span class="field-label">Identity</span><strong>{identity.label}</strong><code>{identity.principal.provider}/{identity.principal.subject}</code></div>
							<div role="cell"><span class="field-label">Owner</span><code>{identity.owner.provider}/{identity.owner.subject}</code></div>
							<div role="cell"><span class="field-label">Grants</span><code>{identity.grants.length} grants</code></div>
							<div role="cell"><span class:allowed={identity.enabled} class="automation-status">{identity.enabled ? 'enabled' : 'disabled'}</span></div>
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
	.automation-record .field-label { display: none; }
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
		.automation-record .field-label { display: inline; }
		.automation-actions { grid-column: 2; grid-row: 1 / span 4; align-self: center; }
	}
</style>
