<script lang="ts">
	import {
		activity,
		approvals as initialApprovals,
		auditEvents,
		jobs,
		messages,
		models,
		plugins,
		runtime,
		type Approval,
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
	let auditFilter = $state<'all' | Risk>('all');
	let selectedAuditId = $state(auditEvents[0]?.id ?? '');

	const pendingApprovals = $derived(approvals.filter((approval) => approval.state === 'pending'));
	const filteredAudit = $derived(
		auditFilter === 'all' ? auditEvents : auditEvents.filter((event) => event.risk === auditFilter)
	);
	const selectedAudit = $derived(
		auditEvents.find((event) => event.id === selectedAuditId) ?? auditEvents[0]
	);

	function decideApproval(id: string, state: 'approved' | 'denied') {
		approvals = approvals.map((approval) => (approval.id === id ? { ...approval, state } : approval));
	}
</script>

<svelte:head>
	<title>Lumen Control Surface</title>
</svelte:head>

<div class="app">
	<aside class="sidebar">
		<div class="brand">
			<div class="logo">L</div>
			<div>
				<strong>Lumen</strong>
				<span>local runtime</span>
			</div>
		</div>

		<nav aria-label="Primary">
			{#each nav as item}
				<button class:active={activeView === item.id} onclick={() => (activeView = item.id)}>
					{item.label}
				</button>
			{/each}
		</nav>

		<div class="runtime-card">
			<span class="eyebrow">Runtime</span>
			<strong>{runtime.status}</strong>
			<small>{runtime.host}</small>
			<small>{runtime.mode} / {runtime.uptime}</small>
		</div>
	</aside>

	<main class="main">
		<header class="topbar">
			<div>
				<span class="eyebrow">Control surface</span>
				<h1>{nav.find((item) => item.id === activeView)?.label}</h1>
			</div>
			<div class="status-strip">
				<span class="dot"></span>
				<span>{runtime.model}</span>
				<span>{pendingApprovals.length} approvals</span>
			</div>
		</header>

		<section class="content">
			{#if activeView === 'overview'}
				<div class="overview-grid">
					<div class="hero panel">
						<span class="eyebrow">Local-first agent runtime</span>
						<h2>Run agents close to your files, models, tools, and approval gates.</h2>
						<p>
							This base UI is mock data only. It shows the control model Lumen is moving toward:
							local execution, explicit permissions, audited actions, and human approval for risky
							operations.
						</p>
					</div>
					{#each [
						['Runtime', runtime.status, runtime.host],
						['Pending approvals', pendingApprovals.length, runtime.queue],
						['Audit events', auditEvents.length, 'latest 24h'],
						['Active jobs', jobs.filter((job) => job.status === 'enabled').length, 'scheduled'],
						['Plugins', plugins.length, 'installed'],
						['Models', models.length, 'configured']
					] as card}
						<div class="metric panel">
							<span>{card[0]}</span>
							<strong>{card[1]}</strong>
							<small>{card[2]}</small>
						</div>
					{/each}
					<div class="panel activity">
						<h2>Recent activity</h2>
						{#if activity.length}
							<ul>
								{#each activity as item}
									<li>{item}</li>
								{/each}
							</ul>
						{:else}
							<p class="empty">No activity yet.</p>
						{/if}
					</div>
				</div>
			{:else if activeView === 'chat'}
				<div class="two-column">
					<div class="panel chat-panel">
						<div class="panel-head">
							<h2>Mock conversation</h2>
							<select aria-label="Model selector" disabled>
								<option>{runtime.model}</option>
								<option>openai-compatible-placeholder</option>
							</select>
						</div>
						<div class="messages">
							{#each messages as message}
								<div class="message {message.role}">
									<span>{message.role}</span>
									<p>{message.body}</p>
								</div>
							{:else}
								<p class="empty">No messages yet.</p>
							{/each}
						</div>
						<form class="composer" onsubmit={(event) => event.preventDefault()}>
							<input disabled value="Chat is a placeholder; runtime wiring comes later." />
							<button disabled>Send</button>
						</form>
					</div>
					<div class="panel">
						<h2>Runtime boundary</h2>
						<p class="muted">
							This screen does not call a model or tool. It exists to stabilize the shell and
							interaction patterns before runtime integration.
						</p>
					</div>
				</div>
			{:else if activeView === 'jobs'}
				<div class="panel">
					<div class="panel-head">
						<h2>Scheduled jobs</h2>
						<button disabled>Create job</button>
					</div>
					<div class="table">
						<div class="row header">
							<span>Name</span><span>Schedule</span><span>Owner</span><span>Status</span><span>Last</span
							><span>Next</span>
						</div>
						{#each jobs as job}
							<div class:disabled={job.status === 'disabled'} class="row">
								<span>{job.name}</span><span>{job.schedule}</span><span>{job.owner}</span>
								<span><b class="badge {job.status}">{job.status}</b></span><span>{job.lastRun}</span
								><span>{job.nextRun}</span>
							</div>
						{:else}
							<p class="empty">No scheduled jobs.</p>
						{/each}
					</div>
				</div>
			{:else if activeView === 'approvals'}
				<div class="panel">
					<div class="panel-head">
						<div>
							<h2>Safe by default</h2>
							<p class="muted">Risky actions pause here until a human decides.</p>
						</div>
					</div>
					<div class="approval-list">
						{#each approvals as approval}
							<article class="approval">
								<div>
									<span class="risk {approval.risk}">{approval.risk}</span>
									<h3>{approval.action}</h3>
									<p>{approval.requester} -> {approval.target} / {approval.time}</p>
								</div>
								<div class="actions">
									{#if approval.state === 'pending'}
										<button onclick={() => decideApproval(approval.id, 'approved')}>Approve</button>
										<button class="ghost" onclick={() => decideApproval(approval.id, 'denied')}>Deny</button>
									{:else}
										<span class="badge {approval.state}">{approval.state}</span>
									{/if}
								</div>
							</article>
						{:else}
							<p class="empty">No approvals pending.</p>
						{/each}
					</div>
				</div>
			{:else if activeView === 'audit'}
				<div class="audit-layout">
					<div class="panel">
						<div class="panel-head">
							<h2>Events</h2>
							<select bind:value={auditFilter} aria-label="Filter audit risk">
								<option value="all">All risks</option>
								<option value="low">Low</option>
								<option value="medium">Medium</option>
								<option value="high">High</option>
								<option value="critical">Critical</option>
							</select>
						</div>
						<div class="audit-list">
							{#each filteredAudit as event}
								<button
									class:active={selectedAudit?.id === event.id}
									onclick={() => (selectedAuditId = event.id)}
								>
									<span>{event.time}</span>
									<strong>{event.action}</strong>
									<small>{event.actor} / {event.target}</small>
									<small>{event.tool} / {event.status} / {event.approval}</small>
									<em class="risk {event.risk}">{event.risk}</em>
								</button>
							{:else}
								<p class="empty">No audit events match this filter.</p>
							{/each}
						</div>
					</div>
					<div class="panel detail">
						{#if selectedAudit}
							<h2>{selectedAudit.id}</h2>
							<dl>
								<dt>Timestamp</dt><dd>{selectedAudit.time}</dd>
								<dt>Actor</dt><dd>{selectedAudit.actor}</dd>
								<dt>Source channel</dt><dd>{selectedAudit.source}</dd>
								<dt>Action attempted</dt><dd>{selectedAudit.action}</dd>
								<dt>Permission checked</dt><dd>{selectedAudit.permission}</dd>
								<dt>Plugin/tool ID</dt><dd>{selectedAudit.tool}</dd>
								<dt>Plugin hash/version</dt><dd>{selectedAudit.version}</dd>
								<dt>Systems touched</dt><dd>{selectedAudit.systems.join(', ')}</dd>
								<dt>Approval status</dt><dd>{selectedAudit.approval}</dd>
								<dt>Result</dt><dd>{selectedAudit.result}</dd>
							</dl>
							<pre>{JSON.stringify(selectedAudit.raw, null, 2)}</pre>
						{:else}
							<p class="empty">Select an audit event.</p>
						{/if}
					</div>
				</div>
			{:else if activeView === 'plugins'}
				<div class="panel">
					<div class="notice">Plugins are permissioned, scoped, and audited before touching local systems.</div>
					<div class="cards">
						{#each plugins as plugin}
							<article class="item-card">
								<div class="panel-head">
									<h2>{plugin.name}</h2>
									<span class="badge {plugin.enabled ? 'enabled' : 'disabled'}">
										{plugin.enabled ? 'enabled' : 'disabled'}
									</span>
								</div>
								<p>{plugin.permissions.join(', ')}</p>
								<small>{plugin.version} / {plugin.hash} / {plugin.scope}</small>
								<button disabled>{plugin.enabled ? 'Disable' : 'Install'}</button>
							</article>
						{:else}
							<p class="empty">No plugins installed.</p>
						{/each}
					</div>
				</div>
			{:else if activeView === 'models'}
				<div class="cards">
					{#each models as model}
						<article class="panel item-card">
							<div class="panel-head">
								<h2>{model.provider}</h2>
								<span class="badge {model.status}">{model.status}</span>
							</div>
							<dl>
								<dt>Model</dt><dd>{model.model}</dd>
								<dt>Endpoint</dt><dd>{model.endpoint}</dd>
								<dt>Streaming</dt><dd>{model.streaming ? 'yes' : 'no'}</dd>
								<dt>Role</dt><dd>{model.role}</dd>
							</dl>
						</article>
					{:else}
						<p class="empty">No model providers configured.</p>
					{/each}
				</div>
			{:else if activeView === 'settings'}
				<div class="settings-grid">
					{#each [
						['Runtime', ['Workspace root', 'Local API port', 'Startup mode']],
						['Local Model Runner', ['Provider path', 'Default model', 'Context window']],
						['Security & Approvals', ['Risk threshold', 'Approval timeout', 'Deny by default']],
						['User/Channel Allowlist', ['Local user', 'Trusted channels', 'Blocked channels']],
						['Secrets', ['Vault path', 'Key source', 'Rotation policy']]
					] as group}
						<section class="panel">
							<h2>{group[0]}</h2>
							{#each group[1] as field}
								<label>
									<span>{field}</span>
									<input disabled value="Not wired yet" />
								</label>
							{/each}
						</section>
					{/each}
				</div>
			{/if}
		</section>
	</main>
</div>

<style>
	:global(*) {
		box-sizing: border-box;
	}

	:global(body) {
		margin: 0;
		background: #080b0f;
		color: #e6edf3;
		font-family:
			Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
	}

	button,
	input,
	select {
		font: inherit;
	}

	button {
		border: 1px solid #2c3948;
		background: #16202b;
		color: #eef6ff;
		border-radius: 8px;
		padding: 0.6rem 0.8rem;
		cursor: pointer;
	}

	button:disabled,
	input:disabled,
	select:disabled {
		cursor: not-allowed;
		opacity: 0.62;
	}

	.app {
		display: grid;
		grid-template-columns: 248px minmax(0, 1fr);
		min-height: 100vh;
		background:
			linear-gradient(180deg, rgba(55, 80, 108, 0.16), transparent 38%),
			#080b0f;
	}

	.sidebar {
		display: flex;
		flex-direction: column;
		gap: 1rem;
		border-right: 1px solid #1d2834;
		background: #0c1117;
		padding: 1rem;
	}

	.brand {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		padding: 0.25rem 0.25rem 1rem;
		border-bottom: 1px solid #1d2834;
	}

	.logo {
		display: grid;
		width: 2.25rem;
		height: 2.25rem;
		place-items: center;
		border: 1px solid #6fb7ff;
		border-radius: 8px;
		background: #102033;
		color: #8fd0ff;
		font-weight: 800;
	}

	.brand strong,
	.brand span,
	.runtime-card small {
		display: block;
	}

	.brand span,
	.eyebrow,
	.muted,
	small {
		color: #93a4b7;
	}

	nav {
		display: grid;
		gap: 0.35rem;
	}

	nav button {
		width: 100%;
		text-align: left;
		background: transparent;
		border-color: transparent;
	}

	nav button.active,
	nav button:hover,
	.audit-list button.active {
		background: #152131;
		border-color: #2d4156;
	}

	.runtime-card,
	.panel {
		border: 1px solid #223041;
		border-radius: 8px;
		background: rgba(13, 19, 27, 0.94);
	}

	.runtime-card {
		margin-top: auto;
		padding: 0.9rem;
	}

	.main {
		min-width: 0;
	}

	.topbar {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 1rem;
		min-height: 78px;
		border-bottom: 1px solid #1d2834;
		padding: 0.85rem 1.25rem;
	}

	h1,
	h2,
	h3,
	p {
		margin: 0;
	}

	h1 {
		font-size: 1.45rem;
	}

	h2 {
		font-size: 1rem;
	}

	h3 {
		font-size: 0.98rem;
	}

	.status-strip {
		display: flex;
		align-items: center;
		gap: 0.7rem;
		flex-wrap: wrap;
		color: #b7c6d8;
		font-size: 0.9rem;
	}

	.dot {
		width: 0.6rem;
		height: 0.6rem;
		border-radius: 999px;
		background: #39d98a;
		box-shadow: 0 0 16px rgba(57, 217, 138, 0.55);
	}

	.content {
		padding: 1rem;
	}

	.overview-grid,
	.settings-grid,
	.cards {
		display: grid;
		grid-template-columns: repeat(3, minmax(0, 1fr));
		gap: 0.85rem;
	}

	.hero {
		grid-column: span 2;
	}

	.panel {
		padding: 1rem;
	}

	.hero h2 {
		max-width: 46rem;
		margin-top: 0.45rem;
		font-size: 1.65rem;
		line-height: 1.2;
	}

	.hero p,
	.muted {
		margin-top: 0.6rem;
		line-height: 1.55;
	}

	.metric {
		display: grid;
		gap: 0.4rem;
		min-height: 118px;
	}

	.metric strong {
		font-size: 1.8rem;
	}

	.activity {
		grid-column: span 3;
	}

	ul {
		display: grid;
		gap: 0.55rem;
		margin: 0.8rem 0 0;
		padding-left: 1.1rem;
	}

	.two-column,
	.audit-layout {
		display: grid;
		grid-template-columns: minmax(0, 1.5fr) minmax(300px, 0.85fr);
		gap: 0.85rem;
	}

	.panel-head {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 0.75rem;
		margin-bottom: 0.85rem;
	}

	select,
	input {
		width: 100%;
		border: 1px solid #2c3948;
		border-radius: 8px;
		background: #0b1118;
		color: #dbe7f5;
		padding: 0.6rem 0.7rem;
	}

	.messages,
	.approval-list,
	.audit-list {
		display: grid;
		gap: 0.7rem;
	}

	.message,
	.approval,
	.item-card {
		border: 1px solid #243243;
		border-radius: 8px;
		background: #0f1721;
		padding: 0.85rem;
	}

	.message {
		max-width: 72ch;
	}

	.message span {
		display: block;
		margin-bottom: 0.35rem;
		color: #8fd0ff;
		font-size: 0.76rem;
		text-transform: uppercase;
	}

	.message.user {
		margin-left: auto;
		background: #142236;
	}

	.composer {
		display: grid;
		grid-template-columns: minmax(0, 1fr) auto;
		gap: 0.6rem;
		margin-top: 0.85rem;
	}

	.table {
		overflow-x: auto;
	}

	.row {
		display: grid;
		grid-template-columns: 1.25fr 1fr 1fr 0.7fr 0.7fr 0.8fr;
		gap: 0.75rem;
		min-width: 760px;
		padding: 0.75rem 0;
		border-top: 1px solid #1d2834;
		align-items: center;
	}

	.row.header {
		border-top: 0;
		color: #93a4b7;
		font-size: 0.8rem;
		text-transform: uppercase;
	}

	.row.disabled {
		opacity: 0.66;
	}

	.badge,
	.risk {
		display: inline-flex;
		width: fit-content;
		border-radius: 999px;
		padding: 0.18rem 0.5rem;
		font-size: 0.76rem;
		font-style: normal;
		text-transform: uppercase;
	}

	.badge {
		background: #1a2735;
		color: #bcd0e6;
	}

	.enabled,
	.ok,
	.approved {
		background: rgba(57, 217, 138, 0.16);
		color: #7df0ae;
	}

	.pending,
	.running {
		background: rgba(255, 199, 95, 0.16);
		color: #ffd27a;
	}

	.disabled,
	.denied,
	.blocked {
		background: rgba(255, 108, 108, 0.13);
		color: #ff9b9b;
	}

	.risk.low {
		background: rgba(57, 217, 138, 0.16);
		color: #7df0ae;
	}

	.risk.medium {
		background: rgba(255, 199, 95, 0.16);
		color: #ffd27a;
	}

	.risk.high {
		background: rgba(255, 145, 84, 0.18);
		color: #ffb084;
	}

	.risk.critical {
		background: rgba(255, 86, 119, 0.18);
		color: #ff8ea5;
	}

	.approval {
		display: flex;
		justify-content: space-between;
		gap: 1rem;
	}

	.approval h3 {
		margin: 0.5rem 0 0.25rem;
	}

	.actions {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		flex-wrap: wrap;
		justify-content: flex-end;
	}

	.ghost {
		background: transparent;
	}

	.audit-list button {
		display: grid;
		gap: 0.2rem;
		width: 100%;
		text-align: left;
		background: #0f1721;
	}

	.detail dl,
	.item-card dl {
		display: grid;
		grid-template-columns: 150px minmax(0, 1fr);
		gap: 0.55rem 0.75rem;
		margin: 0.9rem 0;
	}

	dt {
		color: #93a4b7;
	}

	dd {
		min-width: 0;
		margin: 0;
		overflow-wrap: anywhere;
	}

	pre {
		overflow: auto;
		border: 1px solid #223041;
		border-radius: 8px;
		background: #080d13;
		padding: 0.8rem;
		color: #b7c6d8;
	}

	.notice {
		margin-bottom: 0.85rem;
		border: 1px solid #384d63;
		border-radius: 8px;
		background: #101b27;
		padding: 0.8rem;
		color: #c7d7e9;
	}

	.item-card {
		display: grid;
		gap: 0.7rem;
	}

	.settings-grid label {
		display: grid;
		gap: 0.35rem;
		margin-top: 0.75rem;
	}

	.empty {
		color: #93a4b7;
	}

	@media (max-width: 900px) {
		.app {
			grid-template-columns: 1fr;
		}

		.sidebar {
			position: static;
		}

		nav {
			grid-template-columns: repeat(4, minmax(0, 1fr));
		}

		nav button {
			text-align: center;
		}

		.runtime-card {
			margin-top: 0;
		}

		.overview-grid,
		.settings-grid,
		.cards,
		.two-column,
		.audit-layout {
			grid-template-columns: 1fr;
		}

		.hero,
		.activity {
			grid-column: span 1;
		}
	}

	@media (max-width: 560px) {
		.topbar,
		.approval,
		.panel-head {
			align-items: stretch;
			flex-direction: column;
		}

		nav {
			grid-template-columns: repeat(2, minmax(0, 1fr));
		}

		.composer {
			grid-template-columns: 1fr;
		}

		.table {
			overflow-x: visible;
		}

		.row {
			grid-template-columns: 1fr 1fr;
			min-width: 0;
		}

		.row.header {
			display: none;
		}
	}
</style>
