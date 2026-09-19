import { browser } from '$app/environment';
import { get, writable } from 'svelte/store';

import {
	ApiClient,
	ApiError,
	setDefaultRequestSignal,
	type ConnectionSettings
} from './api';

export type ConnectionKind =
	| 'disconnected'
	| 'configured'
	| 'connecting'
	| 'connected'
	| 'authentication_failed'
	| 'workspace_denied'
	| 'invalid'
	| 'unreachable';

export type ConnectionState = {
	kind: ConnectionKind;
	generation: number;
	message: string;
};

const empty: ConnectionSettings = { baseUrl: 'http://127.0.0.1:3210', workspaceId: '', token: '' };
let generation = 0;
let controller = new AbortController();
setDefaultRequestSignal(controller.signal);

function storedConnection(): ConnectionSettings {
	if (!browser) return empty;
	return {
		baseUrl: localStorage.getItem('lumen.baseUrl') ?? empty.baseUrl,
		workspaceId: localStorage.getItem('lumen.workspaceId') ?? '',
		token: sessionStorage.getItem('lumen.token') ?? ''
	};
}

export const connection = writable<ConnectionSettings>(storedConnection());
export const connectionState = writable<ConnectionState>({
	kind: isConfigured(get(connection)) ? 'configured' : 'disconnected',
	generation,
	message: ''
});

export async function loadConnection(fetcher: typeof fetch = fetch): Promise<ConnectionState> {
	return connect(storedConnection(), false, fetcher);
}

export async function saveConnection(
	settings: ConnectionSettings,
	fetcher: typeof fetch = fetch
): Promise<ConnectionState> {
	return connect(settings, true, fetcher);
}

export function disconnectConnection(): void {
	controller.abort();
	controller = new AbortController();
	setDefaultRequestSignal(controller.signal);
	generation += 1;
	const settings = { ...empty };
	if (browser) {
		localStorage.removeItem('lumen.workspaceId');
		sessionStorage.removeItem('lumen.token');
	}
	connectionState.set({ kind: 'disconnected', generation, message: 'Not connected.' });
	connection.set(settings);
}

export function isConfigured(settings: ConnectionSettings): boolean {
	return Boolean(settings.baseUrl && settings.workspaceId && settings.token);
}

export function connectionSettingsError(settings: ConnectionSettings): string | null {
	if (!isConfigured(settings)) return 'Runtime URL, workspace ID, and bearer token are required.';
	if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(settings.workspaceId)) {
		return 'Workspace ID must be a canonical UUID.';
	}
	try {
		const url = new URL(settings.baseUrl);
		if (!['http:', 'https:'].includes(url.protocol)) return 'Runtime URL must use HTTP or HTTPS.';
		if (url.username || url.password) return 'Runtime URL must not contain credentials.';
		if (url.search || url.hash) return 'Runtime URL must not contain a query or fragment.';
	} catch {
		return 'Runtime URL is invalid.';
	}
	return null;
}

async function connect(
	settings: ConnectionSettings,
	persist: boolean,
	fetcher: typeof fetch
): Promise<ConnectionState> {
	controller.abort();
	controller = new AbortController();
	setDefaultRequestSignal(controller.signal);
	generation += 1;
	const currentGeneration = generation;
	const invalid = connectionSettingsError(settings);
	if (invalid) {
		const state: ConnectionState = {
			kind: isConfigured(settings) ? 'invalid' : 'disconnected',
			generation,
			message: invalid
		};
		connectionState.set(state);
		connection.set(settings);
		return state;
	}
	connectionState.set({ kind: 'configured', generation, message: 'Connection configured.' });
	connection.set(settings);
	if (persist && browser) {
		localStorage.setItem('lumen.baseUrl', settings.baseUrl);
		localStorage.setItem('lumen.workspaceId', settings.workspaceId);
		sessionStorage.setItem('lumen.token', settings.token);
	}
	connectionState.set({ kind: 'connecting', generation, message: 'Checking local runtime…' });
	try {
		await new ApiClient(settings, fetcher, controller.signal).verifyConnection();
		if (currentGeneration !== generation) return get(connectionState);
		const state: ConnectionState = {
			kind: 'connected',
			generation,
			message: 'Authenticated workspace connection verified.'
		};
		connectionState.set(state);
		return state;
	} catch (cause) {
		if (currentGeneration !== generation) return get(connectionState);
		const state = classifyConnectionFailure(cause, generation);
		connectionState.set(state);
		return state;
	}
}

function classifyConnectionFailure(cause: unknown, currentGeneration: number): ConnectionState {
	if (cause instanceof ApiError && cause.status === 401) {
		return {
			kind: 'authentication_failed',
			generation: currentGeneration,
			message: 'Bearer token was rejected. Check it in connection settings.'
		};
	}
	if (cause instanceof ApiError && cause.status === 403) {
		return {
			kind: 'workspace_denied',
			generation: currentGeneration,
			message: 'Workspace is not allowed by this runtime. Select the current workspace in connection settings.'
		};
	}
	if (cause instanceof ApiError && cause.status === 400) {
		return {
			kind: 'invalid',
			generation: currentGeneration,
			message: 'Runtime rejected the workspace identifier. Check connection settings.'
		};
	}
	return {
		kind: 'unreachable',
		generation: currentGeneration,
		message: 'Local runtime could not be reached. Start it or update connection settings.'
	};
}
