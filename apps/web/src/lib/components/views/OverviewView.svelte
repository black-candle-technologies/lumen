<script lang="ts">
	import { activity, auditEvents, jobs, models, plugins, runtime } from '$lib/mock';

	let { pendingCount } = $props<{ pendingCount: number }>();

	const metrics = $derived([
		{ label: 'Runtime', value: runtime.status, detail: `${runtime.host} / ${runtime.mode}` },
		{ label: 'Pending approvals', value: pendingCount, detail: 'human review required' },
		{ label: 'Audit events', value: auditEvents.length, detail: 'event stream' },
		{
			label: 'Active jobs',
			value: jobs.filter((job) => job.status === 'enabled').length,
			detail: 'scheduled locally'
		},
		{ label: 'Plugins', value: plugins.length, detail: 'permission scoped' },
		{ label: 'Models', value: models.length, detail: 'local and compatible providers' }
	]);
</script>

<div class="overview-grid">
	<section class="panel hero-panel">
		<span class="eyebrow">Local-first agent runtime</span>
		<h2>Agents, tools, model providers, approvals, and audit trails in one local control plane.</h2>
		<p>
			Lumen runs local execution first, with explicit permissions, approval gates for risky
			actions, and readable audit history.
		</p>
	</section>

	{#each metrics as metric}
		<section class="panel metric-card">
			<span>{metric.label}</span>
			<strong>{metric.value}</strong>
			<small>{metric.detail}</small>
		</section>
	{/each}

	<section class="panel activity-panel">
		<div class="panel-head">
			<h2>Recent activity</h2>
		</div>
		{#if activity.length}
			<ul class="activity-list">
				{#each activity as item}
					<li>{item}</li>
				{/each}
			</ul>
		{:else}
			<p class="empty">No activity yet.</p>
		{/if}
	</section>
</div>
