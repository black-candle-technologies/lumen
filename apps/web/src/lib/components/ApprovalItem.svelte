<script lang="ts">
	import Check from '@lucide/svelte/icons/check';
	import X from '@lucide/svelte/icons/x';

	import type { Approval } from '$lib/api';

	let {
		approval,
		onDecision,
		busy = false
	}: {
		approval: Approval;
		onDecision: (id: string, decision: 'grant' | 'reject') => void;
		busy?: boolean;
	} = $props();
</script>

<article class="approval-item">
	<header>
		<div>
			<span class="risk-marker">Approval required</span>
			<h2>{approval.kind}</h2>
		</div>
		<time datetime={new Date(approval.expires_at).toISOString()}>
			Expires {new Date(approval.expires_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
		</time>
	</header>

	<div class="preview-grid">
		<section>
			<h3>Arguments</h3>
			<pre>{JSON.stringify(approval.arguments, null, 2)}</pre>
		</section>
		<section>
			<h3>Capabilities</h3>
			<pre>{JSON.stringify(approval.capabilities, null, 2)}</pre>
		</section>
	</div>

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
