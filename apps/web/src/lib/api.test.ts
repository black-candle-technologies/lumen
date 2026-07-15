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

	it('loads plugin review and detail records with exact hashes', async () => {
		const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
			const url = String(input);
			if (url.endsWith('/plugins/staged?after=0&limit=20')) {
				return new Response(
					JSON.stringify({
						packages: [
							{
								stage_id: 'stage-1',
								plugin_id: 'com.example.review',
								version: '1.0.0',
								runtime: 'subprocess',
								package_digest: 'a'.repeat(64),
								manifest_digest: 'b'.repeat(64),
								artifact_digest: 'c'.repeat(64),
								file_hashes: { 'lumen-plugin.toml': 'b'.repeat(64) },
								requested_by: { provider: 'local', subject: 'operator' },
								created_at: 10
							}
						]
					}),
					{ status: 200, headers: { 'content-type': 'application/json' } }
				);
			}
			return new Response(
				JSON.stringify({
					plugin_id: 'com.example.review',
					version: '1.0.0',
					state: 'enabled',
					package_digest: 'a'.repeat(64),
					manifest_digest: 'b'.repeat(64),
					artifact_digest: 'c'.repeat(64),
					components: [
						{
							id: 'summarize',
							kind: 'tool',
							requested_capabilities: [{ name: 'filesystem.read', scope: 'workspace' }],
							effective_grants: [{ name: 'filesystem.read', scope: { path: 'docs' } }],
							grant_revision: 4,
							grant_set_digest: 'd'.repeat(64)
						}
					],
					settings: [],
					failures: []
				}),
				{ status: 200, headers: { 'content-type': 'application/json' } }
			);
		});
		const client = new ApiClient(settings, fetchMock as typeof fetch);

		const staged = await client.listStagedPlugins(20);
		const detail = await client.getPluginVersion('com.example.review', '1.0.0');

		expect(staged[0].package_digest).toBe('a'.repeat(64));
		expect(detail.components[0].grant_set_digest).toBe('d'.repeat(64));
		expect(fetchMock).toHaveBeenCalledWith(
			'http://127.0.0.1:3210/api/v1/workspaces/26db5a31-94f0-4e92-a9c9-4cdf19d71c31/plugins/com.example.review/versions/1.0.0',
			expect.any(Object)
		);
	});

	it('requests plugin lifecycle actions through approval-bound runtime actions', async () => {
		const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
			expect(init?.method).toBe('POST');
			expect(JSON.parse(String(init?.body))).toEqual({
				kind: 'plugin.enable',
				plugin_id: 'com.example.review',
				plugin_version: '1.0.0',
				expected_digest: 'a'.repeat(64)
			});
			return new Response('{"run_id":"run-plugin","state":"approval_requested"}', {
				status: 202,
				headers: { 'content-type': 'application/json' }
			});
		});
		const client = new ApiClient(settings, fetchMock as typeof fetch);

		const result = await client.requestPluginAction({
			kind: 'plugin.enable',
			plugin_id: 'com.example.review',
			plugin_version: '1.0.0',
			expected_digest: 'a'.repeat(64)
		});

		expect(result.state).toBe('approval_requested');
	});

	it('lists and updates channel egress mappings through workspace-scoped endpoints', async () => {
		const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = String(input);
			if (init?.method === 'POST') {
				expect(url).toBe(
					'http://127.0.0.1:3210/api/v1/workspaces/26db5a31-94f0-4e92-a9c9-4cdf19d71c31/egress/channels'
				);
				expect(JSON.parse(String(init.body))).toEqual({
					provider: 'slack',
					external_workspace_id: 'T123',
					channel_id: 'C456',
					external_user_id: 'U789',
					lumen_provider: 'local',
					lumen_subject: 'alice',
					allowed: true
				});
				return new Response(
					JSON.stringify({
						provider: 'slack',
						external_workspace_id: 'T123',
						channel_id: 'C456',
						external_user_id: 'U789',
						lumen_identity: { provider: 'local', subject: 'alice' },
						workspace_id: settings.workspaceId,
						allowed: true,
						created_at: 10,
						updated_at: 20
					}),
					{ status: 200, headers: { 'content-type': 'application/json' } }
				);
			}
			expect(url).toBe(
				'http://127.0.0.1:3210/api/v1/workspaces/26db5a31-94f0-4e92-a9c9-4cdf19d71c31/egress/channels'
			);
			return new Response(
				JSON.stringify({
					mappings: [
						{
							provider: 'slack',
							external_workspace_id: 'T123',
							channel_id: 'C456',
							external_user_id: 'U789',
							lumen_identity: { provider: 'local', subject: 'alice' },
							workspace_id: settings.workspaceId,
							allowed: false,
							created_at: 10,
							updated_at: 20
						}
					]
				}),
				{ status: 200, headers: { 'content-type': 'application/json' } }
			);
		});
		const client = new ApiClient(settings, fetchMock as typeof fetch);

		const mappings = await client.listChannelMappings();
		const updated = await client.updateChannelMapping({
			provider: 'slack',
			external_workspace_id: 'T123',
			channel_id: 'C456',
			external_user_id: 'U789',
			lumen_provider: 'local',
			lumen_subject: 'alice',
			allowed: true
		});

		expect(mappings[0].allowed).toBe(false);
		expect(updated.allowed).toBe(true);
		expect(fetchMock).toHaveBeenCalledTimes(2);
	});

	it('lists and updates destination egress policies through workspace-scoped endpoints', async () => {
		const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = String(input);
			if (init?.method === 'POST') {
				expect(url).toBe(
					'http://127.0.0.1:3210/api/v1/workspaces/26db5a31-94f0-4e92-a9c9-4cdf19d71c31/egress/destinations'
				);
				expect(JSON.parse(String(init.body))).toEqual({
					destination: 'https://api.example.com/v1',
					enabled: false,
					allowed_data_classes: ['public', 'workspace']
				});
				return new Response(
					JSON.stringify({
						destination: 'https://api.example.com/v1',
						revision: 2,
						enabled: false,
						allowed_data_classes: ['public', 'workspace'],
						created_at: 30
					}),
					{ status: 200, headers: { 'content-type': 'application/json' } }
				);
			}
			expect(url).toBe(
				'http://127.0.0.1:3210/api/v1/workspaces/26db5a31-94f0-4e92-a9c9-4cdf19d71c31/egress/destinations'
			);
			return new Response(
				JSON.stringify({
					destinations: [
						{
							destination: 'https://api.example.com/v1',
							revision: 1,
							enabled: true,
							allowed_data_classes: ['public', 'workspace'],
							created_at: 10
						}
					]
				}),
				{ status: 200, headers: { 'content-type': 'application/json' } }
			);
		});
		const client = new ApiClient(settings, fetchMock as typeof fetch);

		const destinations = await client.listDestinationPolicies();
		const updated = await client.updateDestinationPolicy({
			destination: 'https://api.example.com/v1',
			enabled: false,
			allowed_data_classes: ['public', 'workspace']
		});

		expect(destinations[0].enabled).toBe(true);
		expect(updated.enabled).toBe(false);
		expect(updated.revision).toBe(2);
		expect(fetchMock).toHaveBeenCalledTimes(2);
	});

	it('lists and updates provider egress policies without exposing secret references', async () => {
		const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = String(input);
			if (init?.method === 'POST') {
				expect(url).toBe(
					'http://127.0.0.1:3210/api/v1/workspaces/26db5a31-94f0-4e92-a9c9-4cdf19d71c31/egress/providers'
				);
				expect(JSON.parse(String(init.body))).toEqual({
					provider_id: 'openai-compatible',
					enabled: false,
					workspace_allowed_data_classes: ['public']
				});
				return new Response(
					JSON.stringify({
						provider_id: 'openai-compatible',
						revision: 3,
						endpoint_class: 'remote',
						endpoint: 'https://api.openai.example/v1',
						model: 'gpt-test',
						enabled: false,
						priority: 20,
						credential_configured: true,
						allowed_data_classes: ['public', 'workspace'],
						workspace_policy: {
							revision: 2,
							allowed_data_classes: ['public'],
							created_at: 30
						},
						created_at: 30
					}),
					{ status: 200, headers: { 'content-type': 'application/json' } }
				);
			}
			expect(url).toBe(
				'http://127.0.0.1:3210/api/v1/workspaces/26db5a31-94f0-4e92-a9c9-4cdf19d71c31/egress/providers'
			);
			return new Response(
				JSON.stringify({
					providers: [
						{
							provider_id: 'openai-compatible',
							revision: 2,
							endpoint_class: 'remote',
							endpoint: 'https://api.openai.example/v1',
							model: 'gpt-test',
							enabled: true,
							priority: 20,
							credential_configured: true,
							allowed_data_classes: ['public', 'workspace'],
							workspace_policy: {
								revision: 1,
								allowed_data_classes: ['public', 'workspace'],
								created_at: 10
							},
							created_at: 10
						}
					]
				}),
				{ status: 200, headers: { 'content-type': 'application/json' } }
			);
		});
		const client = new ApiClient(settings, fetchMock as typeof fetch);

		const providers = await client.listProviderPolicies();
		const updated = await client.updateProviderPolicy({
			provider_id: 'openai-compatible',
			enabled: false,
			workspace_allowed_data_classes: ['public']
		});

		expect(providers[0].credential_configured).toBe(true);
		expect('credential_secret_ref' in providers[0]).toBe(false);
		expect(updated.enabled).toBe(false);
		expect(updated.workspace_policy?.allowed_data_classes).toEqual(['public']);
		expect(fetchMock).toHaveBeenCalledTimes(2);
	});
});
