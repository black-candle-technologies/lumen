<script lang="ts">
	import { messages, runtime } from '$lib/mockData';
</script>

<div class="two-column">
	<section class="panel chat-panel">
		<div class="panel-head">
			<div>
				<h2>Mock conversation</h2>
				<p class="muted compact">No messages are sent to a model or tool from this screen.</p>
			</div>
			<label class="select-label">
				<span>Model</span>
				<select aria-label="Model selector" disabled>
					<option>{runtime.model}</option>
					<option>openai-compatible-placeholder</option>
				</select>
			</label>
		</div>

		<div class="messages">
			{#each messages as message}
				<article class="message {message.role}">
					<span>{message.role}</span>
					<p>{message.body}</p>
				</article>
			{:else}
				<p class="empty">No messages yet.</p>
			{/each}
		</div>

		<form class="composer" onsubmit={(event) => event.preventDefault()}>
			<label class="sr-only" for="chat-placeholder">Chat input</label>
			<input id="chat-placeholder" disabled value="Runtime chat is not wired yet." />
			<button type="submit" disabled>Send mock</button>
		</form>
	</section>

	<aside class="panel side-panel">
		<h2>Runtime boundary</h2>
		<p class="muted">
			The chat view is a placeholder for interaction design only. Tool calls, model streaming, and
			approval handoffs are intentionally not connected on this branch.
		</p>
	</aside>
</div>
