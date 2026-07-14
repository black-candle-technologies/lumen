<script lang="ts">
	import '../app.css';
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import Bot from '@lucide/svelte/icons/bot';
	import CheckSquare from '@lucide/svelte/icons/square-check';
	import FileClock from '@lucide/svelte/icons/file-clock';
	import Puzzle from '@lucide/svelte/icons/puzzle';
	import Settings from '@lucide/svelte/icons/settings';
	import favicon from '$lib/assets/favicon.svg';
	import ConnectionDialog from '$lib/components/ConnectionDialog.svelte';
	import { connection, isConfigured, loadConnection, saveConnection } from '$lib/connection';

	let { children } = $props();
	let showSettings = $state(false);

	onMount(() => {
		loadConnection();
		if (!isConfigured($connection)) showSettings = true;
	});

	const navigation = [
		{ href: '/', label: 'Chat', icon: Bot },
		{ href: '/approvals', label: 'Approvals', icon: CheckSquare },
		{ href: '/plugins', label: 'Plugins', icon: Puzzle },
		{ href: '/audit', label: 'Audit', icon: FileClock }
	];
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
	<title>Lumen</title>
	<meta name="theme-color" content="#f5f6f3" />
</svelte:head>

<div class="app-shell">
	<header class="topbar">
		<a class="brand" href="/" aria-label="Lumen chat">
			<img src={favicon} alt="" />
			<strong>Lumen</strong>
		</a>
		<div class="connection-state" class:connected={isConfigured($connection)}>
			<span></span>{isConfigured($connection) ? 'Local runtime' : 'Not connected'}
		</div>
		<button class="icon-button" type="button" aria-label="Open connection settings" title="Connection settings" onclick={() => (showSettings = true)}>
			<Settings size={18} />
		</button>
	</header>

	<aside class="sidebar" aria-label="Primary navigation">
		<nav>
			{#each navigation as item}
				<a href={item.href} class:active={page.url.pathname === item.href} aria-current={page.url.pathname === item.href ? 'page' : undefined}>
					<item.icon size={18} />
					<span>{item.label}</span>
				</a>
			{/each}
		</nav>
	</aside>

	<main>{@render children()}</main>

	<nav class="mobile-nav" aria-label="Primary navigation">
		{#each navigation as item}
			<a href={item.href} class:active={page.url.pathname === item.href} aria-current={page.url.pathname === item.href ? 'page' : undefined}>
				<item.icon size={19} />
				<span>{item.label}</span>
			</a>
		{/each}
	</nav>
</div>

{#if showSettings}
	<ConnectionDialog
		settings={$connection}
		onSave={(settings) => {
			saveConnection(settings);
			showSettings = false;
		}}
		onClose={() => (showSettings = false)}
	/>
{/if}
