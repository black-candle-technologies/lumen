<script lang="ts">
	import { jobs } from '$lib/mockData';
</script>

<section class="panel">
	<div class="panel-head">
		<div>
			<h2>Scheduled jobs</h2>
			<p class="muted compact">Mock schedules only. No jobs are created or executed.</p>
		</div>
		<button type="button" disabled>Create job mock</button>
	</div>

	<div class="job-table" role="table" aria-label="Scheduled jobs">
		<div class="job-row table-head" role="row">
			<span role="columnheader">Name</span>
			<span role="columnheader">Schedule</span>
			<span role="columnheader">Owner</span>
			<span role="columnheader">Status</span>
			<span role="columnheader">Last run</span>
			<span role="columnheader">Next run</span>
		</div>
		{#each jobs as job}
			<div class:dimmed={job.status === 'disabled'} class="job-row" role="row">
				<span role="cell" data-label="Name">{job.name}</span>
				<span role="cell" data-label="Schedule">{job.schedule}</span>
				<span role="cell" data-label="Owner">{job.owner}</span>
				<span role="cell" data-label="Status"><b class="badge {job.status}">{job.status}</b></span>
				<span role="cell" data-label="Last run">{job.lastRun}</span>
				<span role="cell" data-label="Next run">{job.nextRun}</span>
			</div>
		{:else}
			<p class="empty">No scheduled jobs.</p>
		{/each}
	</div>
</section>
