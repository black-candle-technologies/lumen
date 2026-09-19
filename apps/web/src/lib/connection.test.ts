import { get } from 'svelte/store';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { ConnectionSettings } from './api';
import {
	connection,
	connectionSettingsError,
	connectionState,
	disconnectConnection,
	loadConnection,
	saveConnection
} from './connection';

const valid: ConnectionSettings = {
	baseUrl: 'http://127.0.0.1:3210',
	workspaceId: '26db5a31-94f0-4e92-a9c9-4cdf19d71c31',
	token: 'test-token'
};

const ok = vi.fn(async () => new Response('{"sandbox":{}}', { status: 200 }));

describe('runtime connection session', () => {
	beforeEach(() => {
		localStorage.clear();
		sessionStorage.clear();
		disconnectConnection();
		ok.mockClear();
	});

	it('rejects malformed settings without sending credentials', async () => {
		const fetcher = vi.fn();
		const malformed = { ...valid, workspaceId: 'not-a-uuid' };
		expect(connectionSettingsError(malformed)).toContain('canonical UUID');
		const state = await saveConnection(malformed, fetcher as typeof fetch);
		expect(state.kind).toBe('invalid');
		expect(fetcher).not.toHaveBeenCalled();
		expect(JSON.stringify(state)).not.toContain(valid.token);
		expect(connectionSettingsError({ ...valid, baseUrl: 'http://user:pass@127.0.0.1' })).toContain(
			'must not contain credentials'
		);
	});

	it.each([
		[401, 'authentication_failed', 'Bearer token was rejected'],
		[403, 'workspace_denied', 'Workspace is not allowed']
	])('classifies HTTP %i as %s', async (status, kind, message) => {
		const fetcher = vi.fn(async () =>
			new Response(JSON.stringify({ error: { code: 'test', message: 'server detail' } }), {
				status,
				headers: { 'content-type': 'application/json' }
			})
		);
		const state = await saveConnection(valid, fetcher as typeof fetch);
		expect(state.kind).toBe(kind);
		expect(state.message).toContain(message);
	});

	it('distinguishes an unreachable runtime from a verified connection', async () => {
		const stopped = await saveConnection(
			valid,
			vi.fn(async () => {
				throw new TypeError('connection refused');
			}) as typeof fetch
		);
		expect(stopped.kind).toBe('unreachable');

		const connected = await saveConnection(valid, ok as typeof fetch);
		expect(connected.kind).toBe('connected');
		expect(ok).toHaveBeenCalledWith(
			`${valid.baseUrl}/api/v1/workspaces/${valid.workspaceId}/runtime/capabilities`,
			expect.objectContaining({
				headers: expect.any(Headers),
				signal: expect.any(AbortSignal)
			})
		);
	});

	it('aborts an old generation and ignores its late result', async () => {
		let oldSignal: AbortSignal | undefined;
		const oldFetch = vi.fn(
			(_input: RequestInfo | URL, init?: RequestInit) =>
				new Promise<Response>((_resolve, reject) => {
					oldSignal = init?.signal ?? undefined;
					oldSignal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
				})
		);
		const oldAttempt = saveConnection(valid, oldFetch as typeof fetch);
		await Promise.resolve();
		const current = { ...valid, workspaceId: '36db5a31-94f0-4e92-a9c9-4cdf19d71c31' };
		const currentState = await saveConnection(current, ok as typeof fetch);
		const oldState = await oldAttempt;

		expect(oldSignal?.aborted).toBe(true);
		expect(currentState.kind).toBe('connected');
		expect(oldState.generation).toBe(currentState.generation);
		expect(get(connection).workspaceId).toBe(current.workspaceId);
		expect(get(connectionState).generation).toBe(currentState.generation);
	});

	it('disconnects, reconnects, and verifies persisted settings on reload', async () => {
		expect((await saveConnection(valid, ok as typeof fetch)).kind).toBe('connected');
		disconnectConnection();
		expect(get(connectionState).kind).toBe('disconnected');
		expect(get(connection).token).toBe('');

		expect((await saveConnection(valid, ok as typeof fetch)).kind).toBe('connected');
		expect((await loadConnection(ok as typeof fetch)).kind).toBe('connected');
		expect(get(connection).workspaceId).toBe(valid.workspaceId);
	});
});
