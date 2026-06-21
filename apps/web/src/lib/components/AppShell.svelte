<script lang="ts">
	import ApprovalsView from '$lib/components/views/ApprovalsView.svelte';
	import AuditLogView from '$lib/components/views/AuditLogView.svelte';
	import ChatView from '$lib/components/views/ChatView.svelte';
	import JobsView from '$lib/components/views/JobsView.svelte';
	import ModelsView from '$lib/components/views/ModelsView.svelte';
	import OverviewView from '$lib/components/views/OverviewView.svelte';
	import PluginsView from '$lib/components/views/PluginsView.svelte';
	import SettingsView from '$lib/components/views/SettingsView.svelte';
	import {
		approvals as initialApprovals,
		auditEvents,
		runtime,
		type Approval,
		type AuditFilter,
		type Risk
	} from '$lib/mockData';

	type View = 'overview' | 'chat' | 'jobs' | 'approvals' | 'audit' | 'plugins' | 'models' | 'settings';

	const nav: { id: View; label: string }[] = [
		{ id: 'overview', label: 'Overview' },
		{ id: 'chat', label: 'Chat' },
		{ id: 'jobs', label: 'Scheduled Jobs' },
		{ id: 'approvals', label: 'Approvals' },
		{ id: 'audit', label: 'Audit Log' },
		{ id: 'plugins', label: 'Plugins' },
		{ id: 'models', label: 'Models' },
		{ id: 'settings', label: 'Settings' }
	];

	let activeView = $state<View>('overview');
	let approvals = $state<Approval[]>(initialApprovals.map((approval) => ({ ...approval })));
	let auditFilter = $state<AuditFilter>('all');
	let selectedAuditId = $state(auditEvents[0]?.id ?? '');

	const activeTitle = $derived(nav.find((item) => item.id === activeView)?.label ?? 'Overview');
	const pendingApprovals = $derived(approvals.filter((approval) => approval.state === 'pending'));
	const filteredAudit = $derived(
		auditFilter === 'all' ? auditEvents : auditEvents.filter((event) => event.risk === auditFilter)
	);
	const selectedAudit = $derived(
		filteredAudit.find((event) => event.id === selectedAuditId) ?? filteredAudit[0]
	);

	$effect(() => {
		if (filteredAudit.length && !filteredAudit.some((event) => event.id === selectedAuditId)) {
			selectedAuditId = filteredAudit[0].id;
		}
	});

	function decideApproval(id: string, state: 'approved' | 'denied') {
		approvals = approvals.map((approval) =>
			approval.id === id && approval.state === 'pending' ? { ...approval, state } : approval
		);
	}

	function setAuditFilter(nextFilter: AuditFilter) {
		auditFilter = nextFilter;
	}

	function selectAuditEvent(id: string) {
		selectedAuditId = id;
	}

	function setView(view: View) {
		activeView = view;
	}
</script>

<div class="lumen-app">
	<aside class="sidebar">
		<div class="brand" aria-label="Lumen">
			<div class="logo" aria-hidden="true">L</div>
			<div>
				<strong>Lumen</strong>
				<span>local runtime</span>
			</div>
		</div>

		<nav class="nav" aria-label="Primary">
			{#each nav as item}
				<button
					type="button"
					class:active={activeView === item.id}
					aria-current={activeView === item.id ? 'page' : undefined}
					onclick={() => setView(item.id)}
				>
					{item.label}
				</button>
			{/each}
		</nav>

		<div class="runtime-card">
			<span class="eyebrow">Mock runtime</span>
			<strong>{runtime.status}</strong>
			<small>{runtime.host}</small>
			<small>{runtime.mode} / uptime {runtime.uptime}</small>
		</div>
	</aside>

	<main class="main">
		<header class="topbar">
			<div>
				<span class="eyebrow">Control surface / mock data</span>
				<h1>{activeTitle}</h1>
			</div>
			<div class="status-strip" aria-label="Runtime status">
				<span class="status-dot" aria-hidden="true"></span>
				<span>Local only</span>
				<span>{runtime.model}</span>
				<span>{pendingApprovals.length} pending approvals</span>
			</div>
		</header>

		<section class="content" aria-label={activeTitle}>
			{#if activeView === 'overview'}
				<OverviewView pendingCount={pendingApprovals.length} />
			{:else if activeView === 'chat'}
				<ChatView />
			{:else if activeView === 'jobs'}
				<JobsView />
			{:else if activeView === 'approvals'}
				<ApprovalsView {approvals} onDecision={decideApproval} />
			{:else if activeView === 'audit'}
				<AuditLogView
					{auditFilter}
					{filteredAudit}
					{selectedAudit}
					onFilter={setAuditFilter}
					onSelect={selectAuditEvent}
				/>
			{:else if activeView === 'plugins'}
				<PluginsView />
			{:else if activeView === 'models'}
				<ModelsView />
			{:else if activeView === 'settings'}
				<SettingsView />
			{/if}
		</section>
	</main>
</div>
