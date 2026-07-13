<script lang="ts">
	import { onMount } from 'svelte';
	import RefreshCw from '@lucide/svelte/icons/refresh-cw';
	import { ApiClient, ApiError, type Approval } from '$lib/api';
	import ApprovalItem from '$lib/components/ApprovalItem.svelte';
	import { connection, isConfigured } from '$lib/connection';

	let approvals = $state<Approval[]>([]);
	let loading = $state(true);
	let busyId = $state('');
	let error = $state('');

	onMount(load);

	async function load() {
		if (!isConfigured($connection)) { loading = false; return; }
		loading = true;
		try {
			approvals = await new ApiClient($connection).listApprovals();
			error = '';
		} catch (cause) {
			error = cause instanceof ApiError ? cause.message : 'Approval requests could not be loaded.';
		} finally { loading = false; }
	}

	async function decide(id: string, decision: 'grant' | 'reject') {
		busyId = id;
		try {
			await new ApiClient($connection).decideApproval(id, decision);
			approvals = approvals.filter((approval) => approval.approval_id !== id);
			error = '';
		} catch (cause) {
			if (cause instanceof ApiError && cause.status === 409) {
				await load();
				error = 'Action changed. Review the refreshed request.';
			} else error = cause instanceof ApiError ? cause.message : 'Approval decision failed.';
		} finally { busyId = ''; }
	}
</script>

<section class="page">
	<header class="page-heading">
		<div><h1>Approvals</h1><p>{approvals.length} pending</p></div>
		<button class="icon-button" type="button" aria-label="Refresh approvals" title="Refresh" onclick={load} disabled={loading}><RefreshCw size={17} /></button>
	</header>
	{#if error}<div class="notice error">{error}</div>{/if}
	{#if loading}
		<div class="empty">Loading approvals…</div>
	{:else if approvals.length === 0}
		<div class="empty">No actions are waiting for approval.</div>
	{:else}
		<div class="approval-list">
			{#each approvals as approval (approval.approval_id)}
				<ApprovalItem {approval} onDecision={decide} busy={busyId === approval.approval_id} />
			{/each}
		</div>
	{/if}
</section>

<style>
	.approval-list { display: grid; gap: 16px; }
	.empty { padding: 50px 0; border-top: 1px solid #dfe2dc; color: #777d75; text-align: center; font-size: 13px; }
</style>
