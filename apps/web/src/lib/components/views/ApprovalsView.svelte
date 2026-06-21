<script lang="ts">
	import type { Approval } from '$lib/mock';

	let { approvals, onDecision } = $props<{
		approvals: Approval[];
		onDecision: (id: string, state: 'approved' | 'denied') => void;
	}>();

	const pendingCount = $derived(
		approvals.filter((approval: Approval) => approval.state === 'pending').length
	);
</script>

<section class="panel">
	<div class="panel-head">
		<div>
			<h2>Safe by default</h2>
			<p class="muted compact">
				Risky actions pause here for human review before they touch local systems.
			</p>
		</div>
		<span class="badge neutral">{pendingCount} pending</span>
	</div>

	<div class="approval-list">
		{#each approvals as approval}
			<article class="approval-row">
				<div class="approval-copy">
					<div class="row-title">
						<span class="risk {approval.risk}">Risk: {approval.risk}</span>
						<span class="badge {approval.state}">State: {approval.state}</span>
					</div>
					<h3>{approval.action}</h3>
					<p>{approval.riskReason}</p>
					<dl class="inline-fields">
						<dt>Requester</dt><dd>{approval.requester}</dd>
						<dt>Target</dt><dd>{approval.target}</dd>
						<dt>Requested</dt><dd>{approval.timestamp}</dd>
					</dl>
				</div>
				<div class="actions">
					{#if approval.state === 'pending'}
						<button type="button" onclick={() => onDecision(approval.id, 'approved')}>
							Approve
						</button>
						<button type="button" class="ghost" onclick={() => onDecision(approval.id, 'denied')}>
							Deny
						</button>
					{:else}
						<span class="muted">Decision recorded.</span>
					{/if}
				</div>
			</article>
		{:else}
			<p class="empty">No approvals pending.</p>
		{/each}
	</div>
</section>
