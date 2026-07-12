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
	:global(.approval-item) { border: 1px solid #d9ddd6; border-radius: 8px; background: #fff; overflow: hidden; }
	:global(.approval-item > header) { display: flex; justify-content: space-between; gap: 20px; padding: 17px 18px; border-bottom: 1px solid #e4e7e1; }
	:global(.approval-item h2) { margin: 5px 0 0; font-size: 16px; }
	:global(.approval-item time) { color: #777d75; font-size: 11px; }
	:global(.risk-marker) { color: #98621a; font-size: 11px; font-weight: 700; text-transform: uppercase; }
	:global(.preview-grid) { display: grid; grid-template-columns: 1fr 1fr; }
	:global(.preview-grid section) { min-width: 0; padding: 15px 18px; }
	:global(.preview-grid section + section) { border-left: 1px solid #e4e7e1; }
	:global(.preview-grid h3) { margin: 0 0 8px; color: #6b7069; font-size: 11px; text-transform: uppercase; }
	:global(.preview-grid pre) { margin: 0; max-height: 220px; overflow: auto; color: #343833; font-size: 12px; line-height: 1.55; white-space: pre-wrap; overflow-wrap: anywhere; }
	:global(.fingerprint) { display: grid; gap: 5px; padding: 11px 18px; border-top: 1px solid #e4e7e1; background: #f8f9f6; }
	:global(.fingerprint span) { color: #777d75; font-size: 10px; text-transform: uppercase; }
	:global(.fingerprint code) { font-size: 11px; overflow-wrap: anywhere; }
	:global(.approval-item footer) { display: flex; justify-content: flex-end; gap: 8px; padding: 13px 18px; border-top: 1px solid #e4e7e1; }
	@media (max-width: 720px) { :global(.preview-grid) { grid-template-columns: 1fr; } :global(.preview-grid section + section) { border-left: 0; border-top: 1px solid #e4e7e1; } }
</style>
