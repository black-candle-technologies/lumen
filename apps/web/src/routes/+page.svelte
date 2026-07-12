<script lang="ts">
	import Bot from '@lucide/svelte/icons/bot';
	import Send from '@lucide/svelte/icons/send';
	import Square from '@lucide/svelte/icons/square';
	import User from '@lucide/svelte/icons/user';
	import { ApiClient, ApiError, type JsonValue, type RunEvent } from '$lib/api';
	import { connection, isConfigured } from '$lib/connection';

	type Message = { role: 'user' | 'assistant'; text: string };

	let prompt = $state('');
	let messages = $state<Message[]>([]);
	let running = $state(false);
	let stopping = $state(false);
	let runId = $state<string | null>(null);
	let error = $state('');

	async function send() {
		const text = prompt.trim();
		if (!text || running || !isConfigured($connection)) return;
		messages = [...messages, { role: 'user', text }];
		prompt = '';
		running = true;
		stopping = false;
		error = '';
		try {
			const client = new ApiClient($connection);
			const created = await client.createRun(text);
			runId = created.run_id;
			await client.streamRunEvents(created.run_id, 0, receiveEvent);
		} catch (cause) {
			error = cause instanceof ApiError ? cause.message : 'The local runtime could not complete this run.';
		} finally {
			running = false;
			stopping = false;
		}
	}

	function receiveEvent(event: RunEvent) {
		if (event.event === 'run.completed') {
			const data = event.data as { text?: JsonValue };
			messages = [...messages, { role: 'assistant', text: String(data.text ?? '') }];
		}
		if (event.event === 'run.failed') error = String(event.data);
		if (event.event === 'run.cancelled') error = 'Run cancelled.';
	}

	async function stop() {
		if (!runId || stopping) return;
		stopping = true;
		try {
			await new ApiClient($connection).cancelRun(runId);
		} catch (cause) {
			error = cause instanceof ApiError ? cause.message : 'Cancellation request failed.';
			stopping = false;
		}
	}

	function keydown(event: KeyboardEvent) {
		if (event.key === 'Enter' && !event.shiftKey) {
			event.preventDefault();
			void send();
		}
	}
</script>

<section class="chat-view">
	<div class="transcript" aria-live="polite">
		{#if messages.length === 0}
			<div class="empty-state">
				<div class="empty-mark"><Bot size={28} /></div>
				<h1>What should we work on?</h1>
			</div>
		{:else}
			{#each messages as message}
				<article class:assistant={message.role === 'assistant'} class="message">
					<div class="avatar">
						{#if message.role === 'assistant'}<Bot size={16} />{:else}<User size={16} />{/if}
					</div>
					<div>
						<strong>{message.role === 'assistant' ? 'Lumen' : 'You'}</strong>
						<p>{message.text}</p>
					</div>
				</article>
			{/each}
		{/if}
		{#if running}
			<div class="run-state"><span></span>{stopping ? 'Stopping' : 'Working locally'}</div>
		{/if}
		{#if error}<div class="notice error">{error}</div>{/if}
	</div>

	<div class="composer-wrap">
		<div class="composer">
			<textarea bind:value={prompt} onkeydown={keydown} placeholder="Message Lumen" rows="1" disabled={running}></textarea>
			{#if running}
				<button class="stop-button" type="button" aria-label="Stop run" title="Stop run" onclick={stop} disabled={stopping}>
					<Square size={15} fill="currentColor" />
				</button>
			{:else}
				<button class="send-button" type="button" aria-label="Send message" title="Send" onclick={send} disabled={!prompt.trim() || !isConfigured($connection)}>
					<Send size={17} />
				</button>
			{/if}
		</div>
	</div>
</section>

<style>
	.chat-view { height: calc(100vh - 56px); display: grid; grid-template-rows: minmax(0, 1fr) auto; }
	.transcript { width: min(820px, 100%); margin: 0 auto; padding: 34px 28px 22px; overflow-y: auto; }
	.empty-state { min-height: 55vh; display: grid; place-content: center; justify-items: center; gap: 13px; }
	.empty-mark { width: 52px; height: 52px; display: grid; place-items: center; border: 1px solid #d8dcd5; border-radius: 8px; color: #285f45; background: #fff; }
	.empty-state h1 { margin: 0; font-size: 21px; font-weight: 650; letter-spacing: 0; }
	.message { display: grid; grid-template-columns: 30px minmax(0, 1fr); gap: 11px; margin: 0 0 26px; }
	.avatar { width: 30px; height: 30px; display: grid; place-items: center; border: 1px solid #d8dcd5; border-radius: 6px; background: #fff; color: #61665f; }
	.message.assistant .avatar { color: #285f45; background: #edf3ee; border-color: #cedbd1; }
	.message strong { display: block; margin: 1px 0 6px; font-size: 12px; }
	.message p { margin: 0; color: #343833; font-size: 14px; line-height: 1.65; white-space: pre-wrap; overflow-wrap: anywhere; }
	.run-state { display: inline-flex; align-items: center; gap: 8px; color: #686d66; font-size: 12px; margin-left: 41px; }
	.run-state span { width: 7px; height: 7px; border-radius: 50%; background: #c18a34; animation: pulse 1.1s ease-in-out infinite; }
	.composer-wrap { padding: 10px 24px 24px; background: linear-gradient(to bottom, rgba(245, 246, 243, 0), #f5f6f3 24%); }
	.composer { width: min(820px, 100%); min-height: 58px; margin: 0 auto; display: grid; grid-template-columns: minmax(0, 1fr) 38px; align-items: end; gap: 8px; padding: 9px 9px 9px 14px; border: 1px solid #cfd4cc; border-radius: 8px; background: #fff; box-shadow: 0 4px 18px rgba(37, 43, 36, 0.07); }
	.composer textarea { width: 100%; max-height: 150px; min-height: 38px; resize: none; border: 0; padding: 9px 0 5px; background: transparent; color: #242823; font-size: 14px; line-height: 1.4; }
	.composer textarea:focus { outline: 0; }
	.send-button, .stop-button { width: 38px; height: 38px; display: grid; place-items: center; border-radius: 6px; padding: 0; }
	.send-button { border: 1px solid #285f45; background: #285f45; color: #fff; }
	.stop-button { border: 1px solid #d7c5c2; background: #fff5f4; color: #9b403a; }
	@keyframes pulse { 50% { opacity: 0.35; } }
	@media (max-width: 720px) {
		.chat-view { height: calc(100vh - 112px); }
		.transcript { padding: 24px 16px 16px; }
		.empty-state { min-height: 48vh; }
		.empty-state h1 { font-size: 18px; }
		.composer-wrap { padding: 8px 12px 14px; }
	}
</style>
