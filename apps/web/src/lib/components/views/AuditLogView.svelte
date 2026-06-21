<script lang="ts">
	import type { AuditEvent, AuditFilter } from '$lib/mock';

	let { auditFilter, filteredAudit, selectedAudit, onFilter, onSelect } = $props<{
		auditFilter: AuditFilter;
		filteredAudit: AuditEvent[];
		selectedAudit: AuditEvent | undefined;
		onFilter: (risk: AuditFilter) => void;
		onSelect: (id: string) => void;
	}>();

	function handleFilter(event: Event) {
		onFilter((event.currentTarget as HTMLSelectElement).value as AuditFilter);
	}
</script>

<div class="audit-layout">
	<section class="panel">
		<div class="panel-head">
			<div>
				<h2>Events</h2>
				<p class="muted compact">Review runtime actions, permissions, and approval outcomes.</p>
			</div>
			<label class="select-label">
				<span>Risk</span>
				<select value={auditFilter} aria-label="Filter audit risk" onchange={handleFilter}>
					<option value="all">All risks</option>
					<option value="low">Low</option>
					<option value="medium">Medium</option>
					<option value="high">High</option>
					<option value="critical">Critical</option>
				</select>
			</label>
		</div>

		<div class="audit-list">
			{#each filteredAudit as event}
				<button
					type="button"
					class:active={selectedAudit?.id === event.id}
					aria-pressed={selectedAudit?.id === event.id}
					onclick={() => onSelect(event.id)}
				>
					<span>{event.timestamp}</span>
					<strong>{event.action}</strong>
					<small>{event.actor} / {event.target}</small>
					<small>{event.tool} / status {event.status} / approval {event.approval}</small>
					<em class="risk {event.risk}">Risk: {event.risk}</em>
				</button>
			{:else}
				<p class="empty">No audit events match this filter.</p>
			{/each}
		</div>
	</section>

	<section class="panel detail-panel">
		{#if selectedAudit}
			<div class="panel-head">
				<div>
					<h2>{selectedAudit.id}</h2>
					<p class="muted compact">{selectedAudit.result}</p>
				</div>
				<span class="badge {selectedAudit.status}">Status: {selectedAudit.status}</span>
			</div>
			<dl class="detail-list">
				<dt>Timestamp</dt><dd>{selectedAudit.timestamp}</dd>
				<dt>Actor</dt><dd>{selectedAudit.actor}</dd>
				<dt>Source/channel</dt><dd>{selectedAudit.source}</dd>
				<dt>Action</dt><dd>{selectedAudit.action}</dd>
				<dt>Permission checked</dt><dd>{selectedAudit.permission}</dd>
				<dt>Plugin/tool/model</dt><dd>{selectedAudit.tool}</dd>
				<dt>Hash/version</dt><dd>{selectedAudit.version}</dd>
				<dt>Systems touched</dt><dd>{selectedAudit.systems.join(', ')}</dd>
				<dt>Approval status</dt><dd>{selectedAudit.approval}</dd>
				<dt>Result</dt><dd>{selectedAudit.result}</dd>
			</dl>
			<pre>{JSON.stringify(selectedAudit.raw, null, 2)}</pre>
		{:else}
			<p class="empty">Select an audit event.</p>
		{/if}
	</section>
</div>
