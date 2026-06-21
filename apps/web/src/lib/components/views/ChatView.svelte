<script lang="ts">
	import { messages, runtime } from '$lib/mock';
</script>

<div class="two-column">
	<section class="panel">
		<div class="panel-head">
			<div>
				<h2>Conversation</h2>
				<p class="muted compact">Chat with the local agent runtime and review tool handoffs.</p>
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
			<input id="chat-placeholder" disabled value="Ask Lumen to inspect, plan, or run a local task." />
			<button type="submit" disabled>Send</button>
		</form>
	</section>

	<aside class="panel">
		<h2>Runtime boundary</h2>
		<p class="muted">
			Model responses, tool calls, and approval handoffs stay visible so local actions can be
			reviewed before execution.
		</p>
	</aside>
</div>
