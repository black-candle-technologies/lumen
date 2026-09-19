<script lang="ts">
	import { onMount } from 'svelte';
	import RefreshCw from '@lucide/svelte/icons/refresh-cw';
	import { ApiClient, ApiError, type Approval } from '$lib/api';
	import ApprovalItem from '$lib/components/ApprovalItem.svelte';
	import { connection, connectionState } from '$lib/connection';

	let approvals = $state<Approval[]>([]);
	let loadState = $state<'loading' | 'success' | 'error'>('loading');
	let loadError = $state('');
	let lastLoadedAt = $state('');
	let loadedWorkspace = $state('');
	let busyId = $state('');
	let error = $state('');
	let serverNow = $state(0);
	let pendingCount = $derived(approvals.filter((approval) => approval.expires_at > serverNow).length);

	onMount(() => {
		load();
		const timer = setInterval(() => serverNow += 1000, 1000);
		return () => clearInterval(timer);
	});

	async function load() {
		if ($connectionState.kind !== 'connected') {
			loadState = 'error';
			loadError = 'Runtime connection is not verified. Open connection settings.';
			return;
		}
		loadState = 'loading';
		try {
			const response = await new ApiClient($connection).listApprovals();
			approvals = response.approvals;
			serverNow = response.server_time;
			loadError = '';
			error = '';
			lastLoadedAt = new Date().toLocaleString();
			loadedWorkspace = $connection.workspaceId;
			loadState = 'success';
		} catch (cause) {
			loadError = cause instanceof ApiError ? cause.message : 'Approval requests could not be loaded.';
			loadState = 'error';
		}
	}

	async function decide(id: string, decision: 'grant' | 'reject') {
		busyId = id;
		try {
			await new ApiClient($connection).decideApproval(id, decision);
			approvals = approvals.filter((approval) => approval.approval_id !== id);
			error = '';
		} catch (cause) {
			if (cause instanceof ApiError && cause.status === 409) {
				if (cause.code !== 'approval_expired') await load();
				error = conflictMessage(cause);
			} else error = cause instanceof ApiError ? cause.message : 'Approval decision failed.';
		} finally { busyId = ''; }
	}

	async function renew(id: string) {
		busyId = id;
		try {
			await new ApiClient($connection).renewApproval(id);
			await load();
		} catch (cause) {
			error = cause instanceof ApiError ? cause.message : 'Approval renewal failed.';
		} finally { busyId = ''; }
	}

	function conflictMessage(cause: ApiError): string {
		switch (cause.code) {
			case 'approval_expired': return 'This approval expired before the decision completed. Renew it to review a new request.';
			case 'approval_stale': return 'This approval is stale. Refresh and review the current request.';
			case 'approval_already_decided': return 'This approval was already decided.';
			case 'approval_consumed': return 'This approval was already used.';
			case 'approval_action_changed': return 'The action changed. Refresh and review it again.';
			default: return cause.message;
		}
	}
</script>

<section class="page">
	<header class="page-heading">
		<div><h1>Approvals</h1><p>{lastLoadedAt ? `${pendingCount} pending${loadState === 'error' ? ' (stale)' : ''}` : 'Pending count unavailable'}</p></div>
		<button class="icon-button" type="button" aria-label="Refresh approvals" title="Refresh" onclick={load} disabled={loadState === 'loading'}><RefreshCw size={17} /></button>
	</header>
	{#if loadError}
		<div class="notice error" role="alert">{loadError} <button type="button" onclick={load}>Retry</button></div>
	{/if}
	{#if loadState === 'error' && lastLoadedAt}
		<div class="notice" role="status">Showing stale data for workspace {loadedWorkspace} from {lastLoadedAt}.</div>
	{/if}
	{#if error}<div class="notice error">{error}</div>{/if}
	{#if loadState === 'loading' && !lastLoadedAt}
		<div class="empty">Loading approvals…</div>
	{:else if loadState === 'error' && !lastLoadedAt}
		<div class="empty">Approval data is unavailable.</div>
	{:else if approvals.length === 0}
		<div class="empty">{loadState === 'error' ? 'The previously loaded approval queue was empty.' : 'No actions are waiting for approval.'}</div>
	{:else}
		<div class="approval-list">
			{#each approvals as approval (approval.approval_id)}
				<ApprovalItem {approval} now={serverNow} onDecision={decide} onRenew={renew} busy={busyId === approval.approval_id} />
			{/each}
		</div>
	{/if}
</section>

<style>
	.approval-list { display: grid; gap: 16px; }
	.empty { padding: 50px 0; border-top: 1px solid #dfe2dc; color: #777d75; text-align: center; font-size: 13px; }
</style>
