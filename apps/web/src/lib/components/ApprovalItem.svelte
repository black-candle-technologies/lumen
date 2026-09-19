<script lang="ts">
	import Check from '@lucide/svelte/icons/check';
	import BookOpenCheck from '@lucide/svelte/icons/book-open-check';
	import FilePenLine from '@lucide/svelte/icons/file-pen-line';
	import KeyRound from '@lucide/svelte/icons/key-round';
	import RefreshCw from '@lucide/svelte/icons/refresh-cw';
	import Terminal from '@lucide/svelte/icons/terminal';
	import Timer from '@lucide/svelte/icons/timer';
	import X from '@lucide/svelte/icons/x';

	import type { Approval, JsonValue } from '$lib/api';

	type JsonObject = { [key: string]: JsonValue };
	type FileState = { content: string; sha256: string; bytes: number };
	type FilePreview = {
		path: string;
		before: ({ exists: true } & FileState) | { exists: false };
		after: FileState;
	};
	type SecretBinding = { id: string; label: string; environment: string };
	type ProcessPreview = {
		program: string;
		args: string[];
		environment: Array<[string, string]>;
		secrets: SecretBinding[];
	};
	type JobSchedule =
		| { kind: 'once'; runAt: number }
		| { kind: 'interval'; startAt: number; intervalMillis: number };
	type JobPreview = {
		kind: 'schedule.job.create' | 'schedule.job.update' | 'schedule.job.enable';
		jobId: string;
		service: string;
		owner: string;
		schedule: JobSchedule;
		prompt: string;
		dataClass: string;
		maxModelTurns: number;
		maxActions: number;
		enabled: boolean;
		nextDueAt: number | null;
		idempotent: boolean;
		previousRevision: number | null;
		previousEnabled: boolean | null;
		targetRevision: number;
	};
	type SkillPreview = {
		draftId: string;
		skillId: string;
		version: string;
		name: string;
		description: string;
		sourceDigest: string;
		sourceRunId: string;
	};

	let {
		approval,
		now = 0,
		onDecision,
		onRenew = () => {},
		busy = false
	}: {
		approval: Approval;
		now?: number;
		onDecision: (id: string, decision: 'grant' | 'reject') => void;
		onRenew?: (id: string) => void;
		busy?: boolean;
	} = $props();

	let filePreview = $derived(readFilePreview(approval));
	let processPreview = $derived(readProcessPreview(approval));
	let jobPreview = $derived(readJobPreview(approval));
	let skillPreview = $derived(readSkillPreview(approval));
	let remainingSeconds = $derived(Math.max(0, Math.ceil((approval.expires_at - now) / 1000)));
	let expired = $derived(remainingSeconds === 0);
	let expiryLabel = $derived(expired
		? 'Expired'
		: `Expires in ${Math.floor(remainingSeconds / 60)}m ${remainingSeconds % 60}s`);

	function object(value: JsonValue | undefined): JsonObject | undefined {
		return value !== null && typeof value === 'object' && !Array.isArray(value) ? value : undefined;
	}

	function string(value: JsonValue | undefined): string | undefined {
		return typeof value === 'string' ? value : undefined;
	}

	function number(value: JsonValue | undefined): number | undefined {
		return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : undefined;
	}

	function integer(value: JsonValue | undefined, minimum = 0): number | undefined {
		const parsed = number(value);
		return parsed !== undefined && Number.isSafeInteger(parsed) && parsed >= minimum
			? parsed
			: undefined;
	}

	function timestamp(value: JsonValue | undefined): number | undefined {
		const parsed = integer(value);
		return parsed !== undefined && !Number.isNaN(new Date(parsed).getTime()) ? parsed : undefined;
	}

	function boolean(value: JsonValue | undefined): boolean | undefined {
		return typeof value === 'boolean' ? value : undefined;
	}

	function uuid(value: JsonValue | undefined): string | undefined {
		const parsed = string(value);
		return parsed && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(parsed)
			? parsed
			: undefined;
	}

	function readState(value: JsonValue | undefined): FileState | undefined {
		const state = object(value);
		const content = string(state?.content);
		const sha256 = string(state?.sha256);
		const bytes = number(state?.bytes);
		return content !== undefined && sha256 !== undefined && bytes !== undefined
			? { content, sha256, bytes }
			: undefined;
	}

	function readFilePreview(value: Approval): FilePreview | undefined {
		if (value.kind !== 'filesystem.write') return undefined;
		const arguments_ = object(value.arguments);
		const path = string(arguments_?.path);
		const before = object(arguments_?.before);
		const after = readState(arguments_?.after);
		if (!path || !before || !after) return undefined;
		if (before.exists === false) return { path, before: { exists: false }, after };
		const prior = readState(before);
		return before.exists === true && prior
			? { path, before: { exists: true, ...prior }, after }
			: undefined;
	}

	function readStringMap(value: JsonValue | undefined): Array<[string, string]> | undefined {
		const map = object(value);
		if (!map) return undefined;
		const entries = Object.entries(map);
		return entries.every((entry): entry is [string, string] => typeof entry[1] === 'string')
			? entries
			: undefined;
	}

	function readProcessPreview(value: Approval): ProcessPreview | undefined {
		if (value.kind !== 'process.spawn') return undefined;
		const arguments_ = object(value.arguments);
		const program = string(arguments_?.program);
		const args = arguments_?.args;
		const environment = readStringMap(arguments_?.environment) ?? [];
		const secretEnvironment = readStringMap(arguments_?.secret_environment) ?? [];
		if (!program || !Array.isArray(args) || !args.every((argument) => typeof argument === 'string')) {
			return undefined;
		}
		const secrets = secretEnvironment.map(([environmentName, id]) => {
			const metadata = value.secret_references?.find(
				(reference) => reference.id === id && reference.environment === environmentName
			);
			return { id, environment: environmentName, label: metadata?.label ?? 'Secret reference' };
		});
		return { program, args, environment, secrets };
	}

	function readJobSchedule(value: JsonValue | undefined): JobSchedule | undefined {
		const schedule = object(value);
		if (schedule?.kind === 'once') {
			const runAt = timestamp(schedule.run_at);
			return runAt !== undefined && schedule.start_at === undefined && schedule.interval_millis === undefined
				? { kind: 'once', runAt }
				: undefined;
		}
		if (schedule?.kind === 'interval') {
			const startAt = timestamp(schedule.start_at);
			const intervalMillis = integer(schedule.interval_millis, 1);
			return startAt !== undefined && intervalMillis !== undefined && schedule.run_at === undefined
				? { kind: 'interval', startAt, intervalMillis }
				: undefined;
		}
		return undefined;
	}

	function readJobPreview(value: Approval): JobPreview | undefined {
		if (!['schedule.job.create', 'schedule.job.update', 'schedule.job.enable'].includes(value.kind)) return undefined;
		const arguments_ = object(value.arguments);
		const jobId = uuid(arguments_?.job_id);
		const serviceProvider = string(arguments_?.service_provider);
		const serviceSubject = string(arguments_?.service_subject);
		const ownerProvider = string(arguments_?.owner_provider);
		const ownerSubject = string(arguments_?.owner_subject);
		const schedule = readJobSchedule(arguments_?.schedule);
		const prompt = string(arguments_?.prompt);
		const dataClass = string(arguments_?.data_class);
		const maxModelTurns = integer(arguments_?.max_model_turns, 1);
		const maxActions = integer(arguments_?.max_actions, 1);
		const enabled = boolean(arguments_?.enabled);
		const idempotent = boolean(arguments_?.idempotent);
		const nextDueAt = arguments_?.next_due_at === null ? null : timestamp(arguments_?.next_due_at);
		const previousRevision = arguments_?.previous_revision === null ? null : integer(arguments_?.previous_revision, 1);
		const previousEnabled = arguments_?.previous_enabled === null ? null : boolean(arguments_?.previous_enabled);
		const targetRevision = integer(arguments_?.target_revision, 1);
		if (!jobId || !serviceProvider || !serviceSubject || !ownerProvider || !ownerSubject || !schedule
			|| !prompt || !dataClass || !['public', 'workspace', 'sensitive'].includes(dataClass)
			|| maxModelTurns === undefined || maxActions === undefined || enabled === undefined
			|| idempotent === undefined || nextDueAt === undefined || previousRevision === undefined
			|| previousEnabled === undefined || targetRevision === undefined) return undefined;
		if (value.kind === 'schedule.job.create') {
			if (previousRevision !== null || previousEnabled !== null || targetRevision !== 1) return undefined;
		} else if (previousRevision === null || previousEnabled === null || targetRevision !== previousRevision + 1) {
			return undefined;
		}
		return {
			kind: value.kind as JobPreview['kind'], jobId,
			service: `${serviceProvider}/${serviceSubject}`,
			owner: `${ownerProvider}/${ownerSubject}`,
			schedule, prompt, dataClass, maxModelTurns, maxActions, enabled, nextDueAt, idempotent,
			previousRevision, previousEnabled, targetRevision
		};
	}

	function readSkillPreview(value: Approval): SkillPreview | undefined {
		if (value.kind !== 'skill.publish') return undefined;
		const arguments_ = object(value.arguments);
		const draftId = uuid(arguments_?.draft_id);
		const skillId = uuid(arguments_?.skill_id);
		const version = string(arguments_?.version);
		const name = string(arguments_?.name);
		const description = string(arguments_?.description);
		const sourceDigest = string(arguments_?.source_digest);
		const sourceRunId = uuid(arguments_?.source_run_id);
		return draftId && skillId && version && name && description && sourceRunId
			&& arguments_?.source_format === 'markdown'
			&& sourceDigest && /^sha256:[0-9a-f]{64}$/.test(sourceDigest)
			? { draftId, skillId, version, name, description, sourceDigest, sourceRunId }
			: undefined;
	}

	function formatTimestamp(timestamp: number): string {
		const date = new Date(timestamp);
		return Number.isNaN(date.getTime())
			? 'Invalid timestamp'
			: date.toLocaleString(undefined, { timeZoneName: 'short' });
	}

	function formatDuration(milliseconds: number): string {
		for (const [unit, label] of [[86_400_000, 'day'], [3_600_000, 'hour'], [60_000, 'minute'], [1_000, 'second']] as const) {
			if (milliseconds % unit === 0) {
				const count = milliseconds / unit;
				return `${count} ${label}${count === 1 ? '' : 's'}`;
			}
		}
		return `${milliseconds} ms`;
	}

	function scheduleDescription(schedule: JobSchedule): string {
		return schedule.kind === 'once'
			? `Once at ${formatTimestamp(schedule.runAt)}`
			: `Every ${formatDuration(schedule.intervalMillis)} from ${formatTimestamp(schedule.startAt)}`;
	}

	function nextOccurrence(preview: JobPreview): string {
		if (!preview.enabled) return 'No next occurrence while paused';
		return preview.nextDueAt === null
			? 'No next occurrence'
			: formatTimestamp(preview.nextDueAt);
	}

	function enabledLabel(enabled: boolean): string {
		return enabled ? 'Enabled' : 'Paused';
	}

	function formatBytes(bytes: number): string {
		return `${new Intl.NumberFormat().format(bytes)} ${bytes === 1 ? 'byte' : 'bytes'}`;
	}
</script>

<article class="approval-item">
	<header class="approval-header">
		<div class="action-heading">
			<div class="action-icon" aria-hidden="true">
				{#if filePreview}<FilePenLine size={17} />
				{:else if jobPreview}<Timer size={17} />
				{:else if skillPreview}<BookOpenCheck size={17} />
				{:else}<Terminal size={17} />{/if}
			</div>
			<div>
				<span class="risk-marker">Approval required</span>
				<h2>{approval.kind}</h2>
			</div>
		</div>
		<time datetime={new Date(approval.expires_at).toISOString()}>{expiryLabel}</time>
	</header>

	{#if filePreview}
		<div class="semantic-preview">
			<section class="action-summary">
				<div>
					<span class="field-label">Workspace path</span>
					<code class="path">{filePreview.path}</code>
				</div>
				<span class:created={!filePreview.before.exists} class="state-badge">
					{filePreview.before.exists ? 'Replace file' : 'New file'}
				</span>
			</section>

			<div class="comparison">
				<section class="file-state">
					<h3>Before</h3>
					{#if filePreview.before.exists}
						<pre>{filePreview.before.content}</pre>
						<dl>
							<div><dt>Size</dt><dd>{formatBytes(filePreview.before.bytes)}</dd></div>
							<div><dt>SHA-256</dt><dd><code>{filePreview.before.sha256}</code></dd></div>
						</dl>
					{:else}
						<div class="missing-state">File does not exist</div>
					{/if}
				</section>
				<section class="file-state after-state">
					<h3>After</h3>
					<pre>{filePreview.after.content}</pre>
					<dl>
						<div><dt>Size</dt><dd>{formatBytes(filePreview.after.bytes)}</dd></div>
						<div><dt>SHA-256</dt><dd><code>{filePreview.after.sha256}</code></dd></div>
					</dl>
				</section>
			</div>
		</div>
	{:else if processPreview}
		<div class="semantic-preview process-preview">
			<section class="command-section">
				<span class="field-label">Executable</span>
				<code class="path">{processPreview.program}</code>
			</section>
			<section class="command-section">
				<h3>Arguments</h3>
				{#if processPreview.args.length > 0}
					<div class="argument-list">
						{#each processPreview.args as argument}<code>{argument}</code>{/each}
					</div>
				{:else}<span class="empty-value">No arguments</span>{/if}
			</section>
			{#if processPreview.environment.length > 0}
				<section class="command-section">
					<h3>Environment</h3>
					<dl class="binding-list">
						{#each processPreview.environment as [name, value]}
							<div><dt><code>{name}</code></dt><dd><code>{value}</code></dd></div>
						{/each}
					</dl>
				</section>
			{/if}
			{#if processPreview.secrets.length > 0}
				<section class="command-section secret-section">
					<h3><KeyRound size={14} /> Secret bindings</h3>
					<div class="secret-list">
						{#each processPreview.secrets as secret}
							<div class="secret-binding">
								<strong>{secret.label}</strong>
								<span>Inject into <code>{secret.environment}</code></span>
								<code class="reference-id">{secret.id}</code>
							</div>
						{/each}
					</div>
				</section>
			{/if}
		</div>
	{:else if jobPreview}
		<div class="semantic-preview administration-preview">
			<section class="action-summary">
				<div>
					<span class="field-label">Scheduled job</span>
					<code class="path">{jobPreview.jobId}</code>
				</div>
				<span class="state-badge">Pending approval</span>
			</section>
			<div class="preview-grid">
				<section>
					<h3>Prompt</h3>
					<p class="prompt-preview">{jobPreview.prompt}</p>
				</section>
				<section>
					<h3>Schedule</h3>
					<strong>{scheduleDescription(jobPreview.schedule)}</strong>
					<span>Next: {nextOccurrence(jobPreview)}</span>
				</section>
				<section>
					<h3>Identity</h3>
					<span>Service <code>{jobPreview.service}</code></span>
					<span>Owner <code>{jobPreview.owner}</code></span>
				</section>
				<section>
					<h3>Limits</h3>
					<span>Data class: <strong>{jobPreview.dataClass}</strong></span>
					<span>{jobPreview.maxModelTurns} model turns · {jobPreview.maxActions} actions</span>
					<span>{jobPreview.idempotent ? 'Idempotent retry allowed' : 'No automatic retry after unknown outcome'}</span>
				</section>
			</div>
			<section class="state-change" aria-label="Scheduled job state change">
				<div>
					<span class="field-label">Before</span>
					<strong>{jobPreview.previousRevision === null ? 'Not created' : `${enabledLabel(jobPreview.previousEnabled ?? false)} · revision ${jobPreview.previousRevision}`}</strong>
				</div>
				<span aria-hidden="true">→</span>
				<div>
					<span class="field-label">After approval</span>
					<strong>{enabledLabel(jobPreview.enabled)} · revision {jobPreview.targetRevision}</strong>
				</div>
			</section>
		</div>
	{:else if skillPreview}
		<div class="semantic-preview administration-preview">
			<section class="action-summary">
				<div>
					<span class="field-label">Skill publication</span>
					<strong>{skillPreview.name}</strong>
					<code class="path">{skillPreview.skillId}@{skillPreview.version}</code>
				</div>
				<span class="state-badge">Pending approval</span>
			</section>
			<div class="preview-grid">
				<section>
					<h3>Description</h3>
					<p class="prompt-preview">{skillPreview.description}</p>
				</section>
				<section>
					<h3>Draft source</h3>
					<span>Draft <code>{skillPreview.draftId}</code></span>
					<span>Run declared in draft <code>{skillPreview.sourceRunId}</code></span>
					<code class="digest">{skillPreview.sourceDigest}</code>
				</section>
			</div>
			<p class="consequence">Approval publishes this pinned Markdown version as reviewed and enabled. It does not grant capabilities or expose the protected draft body.</p>
		</div>
	{:else}
		<div class="generic-preview">
			<span class="field-label">No action-specific preview is available</span>
		</div>
	{/if}

	<details class="normalized-action">
		<summary>Normalized action</summary>
		<div class="raw-grid">
			<section>
				<h3>Arguments</h3>
				<pre>{JSON.stringify(approval.arguments, null, 2)}</pre>
			</section>
			<section>
				<h3>Capabilities</h3>
				<pre>{JSON.stringify(approval.capabilities, null, 2)}</pre>
			</section>
		</div>
	</details>

	<div class="fingerprint">
		<span>Fingerprint</span>
		<code>{approval.fingerprint}</code>
	</div>

	<footer>
		<button
			class="secondary danger"
			type="button"
			disabled={busy || expired}
			onclick={() => onDecision(approval.approval_id, 'reject')}
			aria-label="Reject approval"
		>
			<X size={16} /> Reject
		</button>
		<button
			class="primary"
			type="button"
			disabled={busy || expired}
			onclick={() => onDecision(approval.approval_id, 'grant')}
			aria-label="Grant approval"
		>
			<Check size={16} /> Grant
		</button>
		{#if expired}
			<button class="primary" type="button" disabled={busy} onclick={() => onRenew(approval.approval_id)} aria-label="Renew approval">
				<RefreshCw size={16} /> Renew approval
			</button>
		{/if}
	</footer>
</article>

<style>
	.approval-item { min-width: 0; overflow: hidden; border: 1px solid #d9ddd6; border-radius: 8px; background: #fff; }
	.approval-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 20px; padding: 17px 18px; border-bottom: 1px solid #e4e7e1; }
	.action-heading { display: flex; min-width: 0; align-items: center; gap: 11px; }
	.action-icon { display: grid; width: 34px; height: 34px; flex: 0 0 34px; place-items: center; border: 1px solid #d9ddd6; border-radius: 6px; color: #385c4b; background: #f5f7f3; }
	h2 { margin: 4px 0 0; font-size: 16px; overflow-wrap: anywhere; }
	time { flex: 0 0 auto; color: #777d75; font-size: 11px; }
	.risk-marker { color: #98621a; font-size: 11px; font-weight: 700; text-transform: uppercase; }
	.semantic-preview { min-width: 0; }
	.action-summary { display: flex; min-width: 0; align-items: center; justify-content: space-between; gap: 18px; padding: 14px 18px; background: #f8f9f6; }
	.action-summary > div { display: grid; min-width: 0; gap: 5px; }
	.field-label, h3 { color: #6b7069; font-size: 11px; font-weight: 700; text-transform: uppercase; }
	.path { display: block; min-width: 0; color: #252925; font-size: 12px; overflow-wrap: anywhere; word-break: break-word; }
	.state-badge { flex: 0 0 auto; padding: 4px 7px; border: 1px solid #d4bbb0; border-radius: 4px; color: #834735; background: #fff8f5; font-size: 11px; font-weight: 700; }
	.state-badge.created { border-color: #bed3c4; color: #37624a; background: #f3faf5; }
	.comparison { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); border-top: 1px solid #e4e7e1; }
	.file-state { min-width: 0; padding: 15px 18px 17px; }
	.file-state + .file-state { border-left: 1px solid #e4e7e1; }
	h3 { display: flex; align-items: center; gap: 6px; margin: 0 0 9px; }
	.file-state pre { box-sizing: border-box; width: 100%; min-height: 108px; max-height: 320px; margin: 0; padding: 11px 12px; overflow: auto; border: 1px solid #e1e4de; border-radius: 5px; color: #252925; background: #fafbf9; font-size: 12px; line-height: 1.55; white-space: pre-wrap; overflow-wrap: anywhere; }
	.after-state pre { border-color: #ccddd1; background: #f6faf7; }
	dl { margin: 11px 0 0; }
	dl > div { display: grid; grid-template-columns: 58px minmax(0, 1fr); gap: 10px; padding: 4px 0; }
	dt { color: #777d75; font-size: 10px; text-transform: uppercase; }
	dd { min-width: 0; margin: 0; color: #454a44; font-size: 11px; text-align: right; }
	dd code { overflow-wrap: anywhere; word-break: break-word; }
	.missing-state { display: grid; min-height: 108px; place-items: center; border: 1px dashed #d9ddd6; border-radius: 5px; color: #777d75; background: #fafbf9; font-size: 12px; }
	.process-preview { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); }
	.command-section { min-width: 0; padding: 15px 18px; border-bottom: 1px solid #e4e7e1; }
	.command-section:nth-child(even) { border-left: 1px solid #e4e7e1; }
	.argument-list { display: flex; min-width: 0; flex-wrap: wrap; gap: 6px; }
	.argument-list code { max-width: 100%; padding: 4px 6px; overflow-wrap: anywhere; border: 1px solid #e1e4de; border-radius: 4px; background: #f8f9f6; font-size: 11px; }
	.empty-value { color: #777d75; font-size: 12px; }
	.binding-list { margin: 0; }
	.binding-list > div { grid-template-columns: minmax(90px, auto) minmax(0, 1fr); border-top: 1px solid #eef0ec; }
	.binding-list > div:first-child { border-top: 0; }
	.binding-list dt { min-width: 0; text-transform: none; overflow-wrap: anywhere; }
	.binding-list dd { overflow-wrap: anywhere; }
	.secret-section { grid-column: 1 / -1; border-left: 0 !important; }
	.secret-list { display: grid; gap: 8px; }
	.secret-binding { display: grid; grid-template-columns: minmax(140px, 1fr) minmax(130px, auto) minmax(0, 1fr); align-items: center; gap: 12px; padding: 9px 10px; border-left: 3px solid #b88b3e; background: #fbf8f1; font-size: 11px; }
	.secret-binding strong { overflow-wrap: anywhere; }
	.secret-binding span { color: #666b65; }
	.reference-id { min-width: 0; color: #666b65; text-align: right; overflow-wrap: anywhere; }
	.administration-preview { display: grid; }
	.preview-grid { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); border-top: 1px solid #e4e7e1; }
	.preview-grid section { min-width: 0; display: grid; align-content: start; gap: 7px; padding: 15px 18px; border-bottom: 1px solid #e4e7e1; font-size: 12px; }
	.preview-grid section:nth-child(even) { border-left: 1px solid #e4e7e1; }
	.preview-grid h3 { margin-bottom: 1px; }
	.preview-grid code, .digest { overflow-wrap: anywhere; word-break: break-word; }
	.prompt-preview { margin: 0; white-space: pre-wrap; overflow-wrap: anywhere; line-height: 1.5; }
	.state-change { display: grid; grid-template-columns: minmax(0, 1fr) auto minmax(0, 1fr); align-items: center; gap: 14px; padding: 14px 18px; background: #f8f9f6; }
	.state-change div { display: grid; gap: 5px; }
	.state-change div:last-child { text-align: right; }
	.consequence { margin: 0; padding: 13px 18px; color: #555b54; background: #f8f9f6; font-size: 12px; line-height: 1.5; }
	.generic-preview { padding: 15px 18px; }
	.normalized-action { border-top: 1px solid #e4e7e1; }
	.normalized-action summary { padding: 11px 18px; color: #555b54; background: #f8f9f6; cursor: pointer; font-size: 11px; font-weight: 700; }
	.raw-grid { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); border-top: 1px solid #e4e7e1; }
	.raw-grid section { min-width: 0; padding: 15px 18px; }
	.raw-grid section + section { border-left: 1px solid #e4e7e1; }
	.raw-grid pre { max-height: 220px; margin: 0; overflow: auto; color: #343833; font-size: 12px; line-height: 1.55; white-space: pre-wrap; overflow-wrap: anywhere; }
	.fingerprint { display: grid; gap: 5px; padding: 11px 18px; border-top: 1px solid #e4e7e1; background: #f8f9f6; }
	.fingerprint span { color: #777d75; font-size: 10px; text-transform: uppercase; }
	.fingerprint code { min-width: 0; font-size: 11px; overflow-wrap: anywhere; word-break: break-word; }
	footer { display: flex; justify-content: flex-end; gap: 8px; padding: 13px 18px; border-top: 1px solid #e4e7e1; }
	@media (max-width: 720px) {
		.approval-header { align-items: flex-start; gap: 10px; }
		time { max-width: 76px; text-align: right; }
		.action-summary { align-items: flex-start; flex-direction: column; gap: 10px; }
		.comparison, .process-preview, .preview-grid, .raw-grid { grid-template-columns: minmax(0, 1fr); }
		.file-state + .file-state, .raw-grid section + section { border-top: 1px solid #e4e7e1; border-left: 0; }
		.command-section:nth-child(even) { border-left: 0; }
		.preview-grid section:nth-child(even) { border-left: 0; }
		.state-change { grid-template-columns: minmax(0, 1fr); }
		.state-change > span { transform: rotate(90deg); justify-self: center; }
		.state-change div:last-child { text-align: left; }
		.secret-binding { grid-template-columns: minmax(0, 1fr); gap: 5px; }
		.reference-id { text-align: left; }
		footer button { min-width: 0; flex: 1 1 0; justify-content: center; }
	}
</style>
