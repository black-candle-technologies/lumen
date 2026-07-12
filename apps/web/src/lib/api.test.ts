import { describe, expect, it, vi } from 'vitest';

import { ApiClient, type ConnectionSettings } from './api';

const settings: ConnectionSettings = {
	baseUrl: 'http://127.0.0.1:3210',
	workspaceId: '26db5a31-94f0-4e92-a9c9-4cdf19d71c31',
	token: 'local-test-token'
};

describe('ApiClient', () => {
	it('parses authenticated SSE frames and resumes from the last event ID', async () => {
		const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
			expect(new Headers(init?.headers).get('Authorization')).toBe('Bearer local-test-token');
			expect(new Headers(init?.headers).get('Last-Event-ID')).toBe('4');
			return new Response(
				'id: 5\nevent: run.completed\ndata: {"text":"local answer"}\n\n',
				{ status: 200, headers: { 'content-type': 'text/event-stream' } }
			);
		});
		const client = new ApiClient(settings, fetchMock as typeof fetch);
		const events: Array<{ id: number; event: string; data: unknown }> = [];

		await client.streamRunEvents('run-1', 4, (event) => events.push(event));

		expect(events).toEqual([
			{ id: 5, event: 'run.completed', data: { text: 'local answer' } }
		]);
	});

	it('sends cancellation through the workspace-scoped runtime endpoint', async () => {
		const fetchMock = vi.fn(async () =>
			new Response('{"run_id":"run-1","state":"cancellation_requested"}', {
				status: 202,
				headers: { 'content-type': 'application/json' }
			})
		);
		const client = new ApiClient(settings, fetchMock as typeof fetch);

		await client.cancelRun('run-1');

		expect(fetchMock).toHaveBeenCalledWith(
			'http://127.0.0.1:3210/api/v1/workspaces/26db5a31-94f0-4e92-a9c9-4cdf19d71c31/runs/run-1/cancel',
			expect.objectContaining({ method: 'POST' })
		);
	});
});
