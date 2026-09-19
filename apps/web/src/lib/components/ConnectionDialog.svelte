<script lang="ts">
	import X from '@lucide/svelte/icons/x';
	import type { ConnectionSettings } from '$lib/api';
	import type { ConnectionState } from '$lib/connection';

	let {
		settings,
		onSave,
		onDisconnect,
		onClose
	}: {
		settings: ConnectionSettings;
		onSave: (settings: ConnectionSettings) => Promise<ConnectionState>;
		onDisconnect: () => void;
		onClose: () => void;
	} = $props();

	let baseUrl = $state('');
	let workspaceId = $state('');
	let token = $state('');
	let busy = $state(false);
	let error = $state('');

	$effect(() => {
		baseUrl = settings.baseUrl;
		workspaceId = settings.workspaceId;
		token = settings.token;
	});

	async function submit(event: SubmitEvent) {
		event.preventDefault();
		busy = true;
		error = '';
		const state = await onSave({ baseUrl: baseUrl.trim(), workspaceId: workspaceId.trim(), token: token.trim() });
		busy = false;
		if (state.kind !== 'connected') error = state.message;
	}
</script>

<div class="dialog-backdrop" role="presentation" onclick={(event) => event.target === event.currentTarget && onClose()}>
	<div class="dialog" role="dialog" aria-modal="true" aria-labelledby="connection-title">
		<header>
			<h2 id="connection-title">Runtime connection</h2>
			<button class="icon-button" type="button" aria-label="Close connection settings" title="Close" onclick={onClose}>
				<X size={18} />
			</button>
		</header>
		<form onsubmit={submit}>
			{#if error}<div class="notice error">{error}</div>{/if}
			<label>
				<span>Runtime URL</span>
				<input bind:value={baseUrl} type="url" required />
			</label>
			<label>
				<span>Workspace ID</span>
				<input bind:value={workspaceId} required autocomplete="off" />
			</label>
			<label>
				<span>Bearer token</span>
				<input bind:value={token} type="password" required autocomplete="off" />
			</label>
			<footer>
				<button type="button" onclick={onDisconnect} disabled={busy}>Disconnect</button>
				<button class="primary" type="submit" disabled={busy}>{busy ? 'Connecting…' : 'Connect'}</button>
			</footer>
		</form>
	</div>
</div>
