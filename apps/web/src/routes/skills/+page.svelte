<script lang="ts">
	import { onMount } from 'svelte';
	import RefreshCw from '@lucide/svelte/icons/refresh-cw';
	import Upload from '@lucide/svelte/icons/upload';
	import { ApiClient, ApiError, type SkillReview, type WorkflowCaptureDraft } from '$lib/api';
	import { connection, isConfigured } from '$lib/connection';

	let skills = $state<SkillReview[]>([]);
	let drafts = $state<WorkflowCaptureDraft[]>([]);
	let loading = $state(true);
	let busyKey = $state('');
	let error = $state('');
	let notice = $state('');

	onMount(load);

	async function load() {
		if (!isConfigured($connection)) { loading = false; return; }
		loading = true;
		try {
			const client = new ApiClient($connection);
			[skills, drafts] = await Promise.all([client.listSkills(), client.listCaptureDrafts()]);
			error = '';
		} catch (cause) {
			error = cause instanceof ApiError ? cause.message : 'Skill controls could not be loaded.';
		} finally { loading = false; }
	}

	async function publishDraft(draft: WorkflowCaptureDraft) {
		busyKey = draft.draft_id;
		try {
			const result = await new ApiClient($connection).publishCaptureDraft(draft.draft_id, {
				skill_id: crypto.randomUUID(),
				version: '1.0.0',
				name: draft.title,
				description: `Captured from ${draft.created_by.provider}/${draft.created_by.subject}`
			});
			notice = `Approval requested: ${result.run_id}`;
			error = '';
		} catch (cause) {
			error = cause instanceof ApiError ? cause.message : 'Skill publish request failed.';
		} finally { busyKey = ''; }
	}
</script>

<section class="page skills-page">
	<header class="page-heading">
		<div><h1>Skills</h1><p>{skills.length} versions, {drafts.length} capture drafts</p></div>
		<button class="icon-button" type="button" aria-label="Refresh skills" title="Refresh" onclick={load} disabled={loading}><RefreshCw size={17} /></button>
	</header>
	{#if error}<div class="notice error">{error}</div>{/if}
	{#if notice}<div class="notice">{notice}</div>{/if}

	{#if loading}
		<div class="empty">Loading skills...</div>
	{:else}
		<section class="skills-section">
			<h2>Reviewed Versions</h2>
			{#if skills.length === 0}
				<div class="subtle-empty">No reviewed skill versions.</div>
			{:else}
				<div class="skills-table" role="table" aria-label="Reviewed skills">
					<div class="skills-header skill-row" role="row"><span>Skill</span><span>Digest</span><span>Review</span><span>Status</span></div>
					{#each skills as skill (`${skill.skill_id}:${skill.version}`)}
						<div class="skills-record skill-row" role="row">
							<div><span class="field-label">Skill</span><strong>{skill.name}</strong><code>{skill.skill_id} · {skill.version}</code><span class="micro">{skill.description}</span></div>
							<div><span class="field-label">Digest</span><code>{skill.source_digest}</code><span class="micro">{skill.source_format}</span></div>
							<div><span class="field-label">Review</span><code>{skill.reviewed_by ? `${skill.reviewed_by.provider}/${skill.reviewed_by.subject}` : 'unreviewed'}</code><span class="micro">{skill.reviewed_at ?? skill.created_at}</span></div>
							<div><span class:allowed={skill.enabled} class="skills-status">{skill.enabled ? 'enabled' : 'disabled'}</span></div>
						</div>
					{/each}
				</div>
			{/if}
		</section>

		<section class="skills-section">
			<h2>Capture Drafts</h2>
			{#if drafts.length === 0}
				<div class="subtle-empty">No capture drafts.</div>
			{:else}
				<div class="draft-list" aria-label="Workflow capture drafts">
					{#each drafts as draft (draft.draft_id)}
						<article>
							<header>
								<div><h3>{draft.title}</h3><p>{draft.created_by.provider}/{draft.created_by.subject} · {draft.created_at}</p></div>
								<button class="icon-button" type="button" aria-label={`Publish capture draft ${draft.title}`} title="Publish draft" onclick={() => publishDraft(draft)} disabled={busyKey === draft.draft_id}><Upload size={17} /></button>
							</header>
							<pre>{draft.body}</pre>
						</article>
					{/each}
				</div>
			{/if}
		</section>
	{/if}
</section>

<style>
	.skills-section { display: grid; gap: 9px; margin-bottom: 18px; }
	.skills-section h2 { margin: 0; font-size: 14px; }
	.skills-table { border: 1px solid #dfe3dc; border-radius: 6px; background: #fff; overflow: hidden; }
	.skills-header, .skills-record { display: grid; grid-template-columns: minmax(210px, 1.1fr) minmax(210px, 1fr) minmax(130px, 0.7fr) 88px; gap: 12px; align-items: center; min-height: 48px; padding: 0 10px; border-bottom: 1px solid #edf0ea; }
	.skills-header { min-height: 34px; color: #73786f; background: #f3f5f1; font-size: 10px; font-weight: 700; text-transform: uppercase; }
	.skills-record { font-size: 12px; }
	.skills-record > div { min-width: 0; display: grid; gap: 4px; }
	.skills-record code, .draft-list pre { overflow-wrap: anywhere; word-break: break-word; font-size: 11px; }
	.skills-record strong { overflow-wrap: anywhere; }
	.micro { display: block; color: #73786f; font-size: 11px; }
	.skills-status { width: max-content; border-radius: 4px; padding: 3px 6px; background: #f1e6d5; color: #865a1c; font-size: 11px; font-weight: 700; }
	.skills-status.allowed { background: #e0eee5; color: #276344; }
	.draft-list { display: grid; gap: 10px; }
	.draft-list article { border: 1px solid #dfe3dc; border-radius: 6px; background: #fff; overflow: hidden; }
	.draft-list header { display: flex; justify-content: space-between; gap: 12px; padding: 10px 12px; border-bottom: 1px solid #edf0ea; }
	.draft-list h3 { margin: 0; font-size: 14px; }
	.draft-list p { margin: 3px 0 0; color: #73786f; font-size: 11px; }
	.draft-list pre { max-height: 280px; margin: 0; padding: 12px; overflow: auto; white-space: pre-wrap; background: #fbfcfa; }
	.empty { padding: 48px 20px; border: 1px solid #dfe3dc; border-radius: 6px; background: #fff; color: #777d75; text-align: center; font-size: 13px; }
	@media (max-width: 760px) {
		.skills-page { padding-left: 0; padding-right: 0; }
		.skills-page .page-heading, .skills-page :global(.notice) { margin-left: 16px; margin-right: 16px; }
		.skills-table { border-left: 0; border-right: 0; border-radius: 0; }
		.skills-header { display: none; }
		.skills-section h2 { margin-left: 12px; }
		.skills-record { grid-template-columns: 1fr; gap: 8px; min-height: 0; padding: 10px 12px; }
		.draft-list { padding: 0 12px; }
	}
</style>
