import { browser } from '$app/environment';
import { writable } from 'svelte/store';

import type { ConnectionSettings } from './api';

const empty: ConnectionSettings = { baseUrl: 'http://127.0.0.1:3210', workspaceId: '', token: '' };

function storedConnection(): ConnectionSettings {
	if (!browser) return empty;
	return {
		baseUrl: localStorage.getItem('lumen.baseUrl') ?? empty.baseUrl,
		workspaceId: localStorage.getItem('lumen.workspaceId') ?? '',
		token: sessionStorage.getItem('lumen.token') ?? ''
	};
}

export const connection = writable<ConnectionSettings>(storedConnection());

export function loadConnection(): void {
	if (!browser) return;
	connection.set(storedConnection());
}

export function saveConnection(settings: ConnectionSettings): void {
	if (browser) {
		localStorage.setItem('lumen.baseUrl', settings.baseUrl);
		localStorage.setItem('lumen.workspaceId', settings.workspaceId);
		sessionStorage.setItem('lumen.token', settings.token);
	}
	connection.set(settings);
}

export function isConfigured(settings: ConnectionSettings): boolean {
	return Boolean(settings.baseUrl && settings.workspaceId && settings.token);
}
