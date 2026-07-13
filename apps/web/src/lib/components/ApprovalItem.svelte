<script lang="ts">
	import Check from '@lucide/svelte/icons/check';
	import FilePenLine from '@lucide/svelte/icons/file-pen-line';
	import KeyRound from '@lucide/svelte/icons/key-round';
	import Terminal from '@lucide/svelte/icons/terminal';
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

	let {
		approval,
		onDecision,
		busy = false
	}: {
		approval: Approval;
		onDecision: (id: string, decision: 'grant' | 'reject') => void;
		busy?: boolean;
	} = $props();

	let filePreview = $derived(readFilePreview(approval));
	let processPreview = $derived(readProcessPreview(approval));

	function object(value: JsonValue | undefined): JsonObject | undefined {
		return value !== null && typeof value === 'object' && !Array.isArray(value) ? value : undefined;
	}

	function string(value: JsonValue | undefined): string | undefined {
		return typeof value === 'string' ? value : undefined;
	}

	function number(value: JsonValue | undefined): number | undefined {
		return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : undefined;
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

	function formatBytes(bytes: number): string {
		return `${new Intl.NumberFormat().format(bytes)} ${bytes === 1 ? 'byte' : 'bytes'}`;
	}
</script>

<article class="approval-item">
	<header class="approval-header">
		<div class="action-heading">
			<div class="action-icon" aria-hidden="true">
				{#if filePreview}<FilePenLine size={17} />{:else}<Terminal size={17} />{/if}
			</div>
			<div>
				<span class="risk-marker">Approval required</span>
				<h2>{approval.kind}</h2>
			</div>
		</div>
		<time datetime={new Date(approval.expires_at).toISOString()}>
			Expires {new Date(approval.expires_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
		</time>
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
			disabled={busy}
			onclick={() => onDecision(approval.approval_id, 'reject')}
			aria-label="Reject approval"
		>
			<X size={16} /> Reject
		</button>
		<button
			class="primary"
			type="button"
			disabled={busy}
			onclick={() => onDecision(approval.approval_id, 'grant')}
			aria-label="Grant approval"
		>
			<Check size={16} /> Grant
		</button>
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
		.comparison, .process-preview, .raw-grid { grid-template-columns: minmax(0, 1fr); }
		.file-state + .file-state, .raw-grid section + section { border-top: 1px solid #e4e7e1; border-left: 0; }
		.command-section:nth-child(even) { border-left: 0; }
		.secret-binding { grid-template-columns: minmax(0, 1fr); gap: 5px; }
		.reference-id { text-align: left; }
		footer button { min-width: 0; flex: 1 1 0; justify-content: center; }
	}
</style>
