import { expect, test, type Page } from '@playwright/test';

const workspaceId = '26db5a31-94f0-4e92-a9c9-4cdf19d71c31';
const longPath = `notes/${'quarterly-review-'.repeat(8)}.md`;

async function configure(page: Page) {
	await page.addInitScript(
		({ workspaceId }) => {
			localStorage.setItem('lumen.baseUrl', 'http://127.0.0.1:3210');
			localStorage.setItem('lumen.workspaceId', workspaceId);
			sessionStorage.setItem('lumen.token', 'local-test-token');
		},
		{ workspaceId }
	);
}

test.beforeEach(async ({ page }) => {
	await configure(page);
	await page.route('**/api/v1/workspaces/*/runtime/capabilities', async (route) => {
		await route.fulfill({ json: { sandbox: { platform: 'test', strength: 'kernel_enforced' } } });
	});
	await page.route('**/api/v1/workspaces/*/approvals', async (route) => {
		await route.fulfill({
			json: {
				server_time: 1000,
				approvals: [
					{
						approval_id: 'approval-write',
						run_id: 'run-write',
						kind: 'filesystem.write',
						arguments: {
							path: longPath,
							before: {
								exists: true,
								content: 'Status: draft\nOwner: local operator',
								sha256: 'b'.repeat(64),
								bytes: 35
							},
							after: {
								content: `Status: approved\n${'Reviewed locally. '.repeat(80)}`,
								sha256: 'c'.repeat(64),
								bytes: 1457
							}
						},
						capabilities: [{ name: 'fs.write', scope: { path: longPath } }],
						fingerprint: 'f'.repeat(64),
						created_at: 10,
						expires_at: 9999999999999
					},
					{
						approval_id: 'approval-1',
						run_id: 'run-approval',
						kind: 'process.spawn',
						arguments: {
							program: '/bin/echo',
							args: ['hello'],
							environment: {},
							secret_environment: { API_TOKEN: '5f7cc8b4-e848-4cb4-91ef-27c5983c41a5' }
						},
						secret_references: [
							{
								id: '5f7cc8b4-e848-4cb4-91ef-27c5983c41a5',
								label: 'Example API token',
								environment: 'API_TOKEN',
								value: 'browser-secret-must-not-render'
							}
						],
						capabilities: [{ name: 'process.spawn', scope: { executable: '/bin/echo' } }],
						fingerprint: 'a'.repeat(64),
						created_at: 10,
						expires_at: 9999999999999
					}
				]
			}
		});
	});
	await page.route('**/api/v1/workspaces/*/audit*', async (route) => {
		await route.fulfill({
			json: {
				events: [
					{
						sequence: 7,
						event_id: 'event-7',
						timestamp: 42,
						kind: 'execution_succeeded',
						outcome: 'success',
						workspace_id: workspaceId,
						payload: { run_id: 'run-1', actor: 'operator' }
					}
				]
			}
		});
	});
	await page.route('**/api/v1/workspaces/*/plugins/staged*', async (route) => {
		await route.fulfill({
			json: {
				packages: [
					{
						stage_id: 'stage-plugin',
						plugin_id: `com.example.${'very-long-plugin-id-'.repeat(5)}review`,
						version: '1.0.0',
						runtime: 'subprocess',
						package_digest: 'a'.repeat(64),
						manifest_digest: 'b'.repeat(64),
						artifact_digest: 'c'.repeat(64),
						file_hashes: {
							'lumen-plugin.toml': 'b'.repeat(64),
							'bin/plugin': 'c'.repeat(64)
						},
						requested_by: { provider: 'local', subject: 'operator' },
						created_at: 10
					}
				]
			}
		});
	});
	await page.route('**/api/v1/workspaces/*/plugins/*/versions/*', async (route) => {
		await route.fulfill({
			json: {
				plugin_id: `com.example.${'very-long-plugin-id-'.repeat(5)}review`,
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
						effective_grants: [{ name: 'filesystem.read', scope: { path: longPath } }],
						grant_revision: 4,
						grant_set_digest: 'd'.repeat(64)
					}
				],
				settings: [
					{
						scope_type: 'workspace',
						scope_id: workspaceId,
						config_version: 2,
						config: { api_key: '[redacted]', mode: 'local' },
						schema_digest: 'e'.repeat(64),
						settings_digest: 'f'.repeat(64)
					}
				],
				failures: [
					{
						class: 'host_fault',
						count: 2,
						diagnostic: '[redacted]',
						diagnostic_digest: '0'.repeat(64),
						last_seen_at: 42
					}
				]
			}
		});
	});
	await page.route('**/api/v1/workspaces/*/egress/channels', async (route) => {
		if (route.request().method() === 'POST') {
			expect(route.request().postDataJSON()).toMatchObject({
				provider: 'slack',
				external_workspace_id: 'T123',
				channel_id: 'C456',
				external_user_id: 'U789',
				lumen_provider: 'local',
				lumen_subject: 'operator',
				allowed: false
			});
			await route.fulfill({
				json: {
					provider: 'slack',
					external_workspace_id: 'T123',
					channel_id: 'C456',
					external_user_id: 'U789',
					lumen_identity: { provider: 'local', subject: 'operator' },
					workspace_id: workspaceId,
					allowed: false,
					created_at: 10,
					updated_at: 30
				}
			});
			return;
		}
		await route.fulfill({
			json: {
				mappings: [
					{
						provider: 'slack',
						external_workspace_id: 'T123',
						channel_id: 'C456',
						external_user_id: 'U789',
						lumen_identity: { provider: 'local', subject: 'operator' },
						workspace_id: workspaceId,
						allowed: true,
						created_at: 10,
						updated_at: 20
					},
					{
						provider: 'discord',
						external_workspace_id: 'guild-1',
						channel_id: 'ops',
						external_user_id: 'user-2',
						lumen_identity: { provider: 'local', subject: 'observer' },
						workspace_id: workspaceId,
						allowed: false,
						created_at: 11,
						updated_at: 21
					}
				]
			}
		});
	});
	await page.route('**/api/v1/workspaces/*/egress/destinations', async (route) => {
		if (route.request().method() === 'POST') {
			expect(route.request().postDataJSON()).toMatchObject({
				destination: 'https://api.example.com/v1',
				enabled: false,
				allowed_data_classes: ['public', 'workspace']
			});
			await route.fulfill({
				json: {
					destination: 'https://api.example.com/v1',
					revision: 2,
					enabled: false,
					allowed_data_classes: ['public', 'workspace'],
					created_at: 31
				}
			});
			return;
		}
		await route.fulfill({
			json: {
				destinations: [
					{
						destination: 'https://api.example.com/v1',
						revision: 1,
						enabled: true,
						allowed_data_classes: ['public', 'workspace'],
						created_at: 30
					},
					{
						destination: 'https://hooks.example.com/',
						revision: 4,
						enabled: false,
						allowed_data_classes: ['public'],
						created_at: 28
					}
				]
			}
		});
	});
	await page.route('**/api/v1/workspaces/*/egress/providers', async (route) => {
		if (route.request().method() === 'POST') {
			expect(route.request().postDataJSON()).toMatchObject({
				provider_id: 'openai-compatible',
				enabled: false,
				workspace_allowed_data_classes: ['public', 'workspace']
			});
			await route.fulfill({
				json: {
					provider_id: 'openai-compatible',
					revision: 3,
					endpoint_class: 'remote',
					endpoint: 'https://api.openai.example/v1',
					model: 'gpt-test',
					enabled: false,
					priority: 20,
					credential_configured: true,
					allowed_data_classes: ['public', 'workspace', 'sensitive'],
					workspace_policy: {
						revision: 2,
						allowed_data_classes: ['public', 'workspace'],
						created_at: 32
					},
					created_at: 32
				}
			});
			return;
		}
		await route.fulfill({
			json: {
				providers: [
					{
						provider_id: 'local-llama',
						revision: 1,
						endpoint_class: 'local',
						endpoint: 'https://localhost:8080/v1',
						model: 'llama-local',
						enabled: true,
						priority: 0,
						credential_configured: false,
						allowed_data_classes: ['public', 'workspace', 'sensitive'],
						workspace_policy: null,
						created_at: 20
					},
					{
						provider_id: 'openai-compatible',
						revision: 2,
						endpoint_class: 'remote',
						endpoint: 'https://api.openai.example/v1',
						model: 'gpt-test',
						enabled: true,
						priority: 20,
						credential_configured: true,
						allowed_data_classes: ['public', 'workspace', 'sensitive'],
						workspace_policy: {
							revision: 1,
							allowed_data_classes: ['public', 'workspace'],
							created_at: 30
						},
						created_at: 30
					}
				]
			}
		});
	});
	await page.route('**/api/v1/workspaces/*/automation/service-identities', async (route) => {
		await route.fulfill({
			json: {
				service_identities: [
					{
						principal: { provider: 'service', subject: 'nightly' },
						workspace_id: workspaceId,
						owner: { provider: 'local', subject: 'operator' },
						label: 'Nightly reviewer',
						enabled: true,
						grants: [{ name: 'model.prompt', scope: 'workspace' }],
						created_at: 10,
						updated_at: 20
					}
				]
			}
		});
	});
	await page.route('**/api/v1/workspaces/*/automation/jobs', async (route) => {
		await route.fulfill({
			json: {
				jobs: [
					{
						job_id: '05e0bb38-b491-4532-b9b6-0ac57ec4f357',
						revision: 2,
						workspace_id: workspaceId,
						service: { provider: 'service', subject: 'nightly' },
						owner: { provider: 'local', subject: 'operator' },
						schedule: { kind: 'interval', start_at: 1000, interval_millis: 60000 },
						prompt: `Summarize ${'open issue queues '.repeat(10)}`,
						data_class: 'workspace',
						max_model_turns: 4,
						max_actions: 8,
						enabled: true,
						next_due_at: 2000,
						idempotent: true,
						created_at: 10
					}
				]
			}
		});
	});
	await page.route('**/api/v1/workspaces/*/automation/jobs/*', async (route) => {
		expect(route.request().postDataJSON()).toMatchObject({
			service_subject: 'nightly',
			enabled: false,
			data_class: 'workspace'
		});
		await route.fulfill({ status: 202, json: { run_id: 'run-job', state: 'approval_requested' } });
	});
	await page.route('**/api/v1/workspaces/*/skills/capture-drafts/*/publish', async (route) => {
		expect(route.request().postDataJSON()).toMatchObject({
			version: '1.0.0',
			name: 'Captured triage workflow'
		});
		await route.fulfill({ status: 202, json: { run_id: 'run-skill', state: 'approval_requested' } });
	});
	await page.route('**/api/v1/workspaces/*/skills/capture-drafts', async (route) => {
		await route.fulfill({
			json: {
				drafts: [
					{
						draft_id: '00000000-0000-0000-0000-000000000000',
						workspace_id: workspaceId,
						title: 'Captured triage workflow',
						body: `Source run: run-1\nAction: process.spawn\nSecret: [redacted]\n${'Expected output retained. '.repeat(30)}`,
						created_by: { provider: 'local', subject: 'operator' },
						created_at: 30
					}
				]
			}
		});
	});
	await page.route('**/api/v1/workspaces/*/skills', async (route) => {
		await route.fulfill({
			json: {
				skills: [
					{
						skill_id: '7f2d9ac7-2e61-46d4-9c1e-6adf6b2bd763',
						version: '1.0.0',
						workspace_id: workspaceId,
						name: 'Issue triage',
						description: 'Summarize and route issue queues',
						source_format: 'markdown',
						source_digest: 'a'.repeat(64),
						reviewed: true,
						enabled: true,
						required: false,
						load_status: 'loaded',
						exclusion_reason: null,
						created_by: { provider: 'local', subject: 'operator' },
						reviewed_by: { provider: 'local', subject: 'reviewer' },
						created_at: 10,
						reviewed_at: 20
					}
				]
			}
		});
	});
});

test('verifies connection identity and supports disconnect, reconnect, and refresh', async ({ page }) => {
	await page.unroute('**/api/v1/workspaces/*/runtime/capabilities');
	await page.route('**/api/v1/workspaces/*/runtime/capabilities', async (route) => {
		const authorization = route.request().headers()['authorization'];
		if (authorization !== 'Bearer local-test-token') {
			await route.fulfill({
				status: 401,
				json: { error: { code: 'unauthorized', message: 'local authentication failed' } }
			});
			return;
		}
		if (!route.request().url().includes(workspaceId)) {
			await route.fulfill({
				status: 403,
				json: { error: { code: 'workspace_forbidden', message: 'workspace is not allowlisted' } }
			});
			return;
		}
		await route.fulfill({ json: { sandbox: { platform: 'test', strength: 'kernel_enforced' } } });
	});
	await page.goto('/');
	await expect(page.getByRole('button', { name: 'Local runtime' })).toBeVisible();

	await page.getByRole('button', { name: 'Open connection settings' }).click();
	await page.getByLabel('Bearer token').fill('wrong-token');
	await page.getByRole('button', { name: 'Connect', exact: true }).click();
	await expect(page.getByText('Bearer token was rejected. Check it in connection settings.')).toBeVisible();

	await page.getByLabel('Bearer token').fill('local-test-token');
	await page.getByLabel('Workspace ID').fill('36db5a31-94f0-4e92-a9c9-4cdf19d71c31');
	await page.getByRole('button', { name: 'Connect', exact: true }).click();
	await expect(page.getByText('Workspace is not allowed by this runtime. Select the current workspace in connection settings.')).toBeVisible();

	await page.getByLabel('Workspace ID').fill('not-a-uuid');
	await page.getByRole('button', { name: 'Connect', exact: true }).click();
	await expect(page.getByText('Workspace ID must be a canonical UUID.')).toBeVisible();

	await page.getByLabel('Workspace ID').fill(workspaceId);
	await page.getByRole('button', { name: 'Connect', exact: true }).click();
	await expect(page.getByRole('button', { name: 'Local runtime' })).toBeVisible();
	await page.reload();
	await expect(page.getByRole('button', { name: 'Local runtime' })).toBeVisible();

	await page.getByRole('button', { name: 'Open connection settings' }).click();
	await page.getByRole('button', { name: 'Disconnect' }).click();
	await expect(page.getByRole('button', { name: 'Not connected' })).toBeVisible();
	await page.getByRole('button', { name: 'Open connection settings' }).click();
	await page.getByLabel('Workspace ID').fill(workspaceId);
	await page.getByLabel('Bearer token').fill('local-test-token');
	await page.getByRole('button', { name: 'Connect', exact: true }).click();
	await expect(page.getByRole('button', { name: 'Local runtime' })).toBeVisible();
});

test('drops a late response from the previous workspace generation', async ({ page }) => {
	const nextWorkspace = '36db5a31-94f0-4e92-a9c9-4cdf19d71c31';
	let markOldRequest = () => {};
	const oldRequest = new Promise<void>((resolve) => (markOldRequest = resolve));
	await page.unroute('**/api/v1/workspaces/*/skills');
	await page.route('**/api/v1/workspaces/*/skills', async (route) => {
		const old = route.request().url().includes(workspaceId);
		if (old) {
			markOldRequest();
			await new Promise((resolve) => setTimeout(resolve, 500));
		}
		await route.fulfill({
			json: {
				skills: [
					{
						skill_id: old ? '7f2d9ac7-2e61-46d4-9c1e-6adf6b2bd763' : '8f2d9ac7-2e61-46d4-9c1e-6adf6b2bd763',
						version: '1.0.0',
						workspace_id: old ? workspaceId : nextWorkspace,
						name: old ? 'Stale workspace skill' : 'Current workspace skill',
						description: 'generation test',
						source_format: 'markdown',
						source_digest: 'a'.repeat(64),
						reviewed: true,
						enabled: true,
						required: false,
						load_status: 'loaded',
						exclusion_reason: null,
						created_by: { provider: 'local', subject: 'operator' },
						reviewed_by: { provider: 'local', subject: 'reviewer' },
						created_at: 10,
						reviewed_at: 20
					}
				]
			}
		});
	});
	await page.goto('/skills');
	await oldRequest;
	await page.getByRole('button', { name: 'Open connection settings' }).click();
	await page.getByLabel('Workspace ID').fill(nextWorkspace);
	await page.getByRole('button', { name: 'Connect', exact: true }).click();
	await expect(page.getByText('Current workspace skill')).toBeVisible();
	await page.waitForTimeout(600);
	await expect(page.getByText('Stale workspace skill')).toHaveCount(0);
});

test('streams a local chat result and can request cancellation', async ({ page }, testInfo) => {
	let cancelled = false;
	await page.route('**/api/v1/workspaces/*/runs', async (route) => {
		expect(route.request().headers()['authorization']).toBe('Bearer local-test-token');
		await route.fulfill({ status: 202, json: { run_id: 'run-1' } });
	});
	await page.route('**/runs/run-1/events', async (route) => {
		await new Promise((resolve) => setTimeout(resolve, 300));
		await route.fulfill({
			contentType: 'text/event-stream',
			body: 'id: 1\nevent: run.completed\ndata: {"text":"Local model answer"}\n\n'
		});
	});
	await page.route('**/runs/run-1/cancel', async (route) => {
		cancelled = true;
		await route.fulfill({ status: 202, json: { run_id: 'run-1', state: 'cancellation_requested' } });
	});
	await page.goto('/');

	await page.getByPlaceholder('Message Lumen').fill('Summarize my notes');
	await page.getByRole('button', { name: 'Send message' }).click();
	await page.getByRole('button', { name: 'Stop run' }).click();
	expect(cancelled).toBe(true);
	await expect(page.getByText('Local model answer')).toBeVisible();
	await page.screenshot({ path: testInfo.outputPath('chat.png') });
});

test('shows exact approval details and handles a changed action conflict', async ({ page }, testInfo) => {
	await page.route('**/approvals/approval-write/decision', async (route) => {
		await route.fulfill({
			status: 409,
			json: { error: { code: 'approval_action_changed', message: 'action fingerprint changed' } }
		});
	});
	await page.goto('/approvals');

	const fileApproval = page.locator('article').filter({ has: page.getByRole('heading', { name: 'filesystem.write' }) });
	await expect(fileApproval.locator('.action-summary code')).toHaveText(longPath);
	await expect(fileApproval.getByRole('heading', { name: 'Before' })).toBeVisible();
	await expect(fileApproval.getByRole('heading', { name: 'After' })).toBeVisible();
	await expect(fileApproval.locator('.file-state').nth(0).locator('pre')).toContainText('Status: draft');
	await expect(fileApproval.locator('.file-state').nth(1).locator('pre')).toContainText('Status: approved');
	await expect(fileApproval.getByText('35 bytes')).toBeVisible();
	await expect(fileApproval.getByText('1,457 bytes')).toBeVisible();
	await expect(fileApproval.locator('.file-state').nth(0).locator('dl code')).toHaveText('b'.repeat(64));
	await expect(fileApproval.locator('.file-state').nth(1).locator('dl code')).toHaveText('c'.repeat(64));

	const secretApproval = page.locator('article').filter({ has: page.getByRole('heading', { name: 'process.spawn' }) });
	await expect(secretApproval.getByText('Example API token')).toBeVisible();
	await expect(secretApproval.locator('.secret-binding code').first()).toHaveText('API_TOKEN');
	await expect(page.getByText('browser-secret-must-not-render')).toHaveCount(0);
	expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
	for (const card of await page.locator('.approval-item').all()) {
		expect(await card.evaluate((element) => element.scrollWidth <= element.clientWidth)).toBe(true);
	}

	await fileApproval.getByRole('button', { name: 'Grant approval' }).click();
	await expect(page.getByText('The action changed. Refresh and review it again.')).toBeVisible();
	await page.screenshot({ path: testInfo.outputPath('approval.png') });
	const controls = fileApproval.locator('footer');
	await controls.scrollIntoViewIfNeeded();
	await expect(controls.getByRole('button', { name: 'Reject approval' })).toBeVisible();
	await expect(controls.getByRole('button', { name: 'Grant approval' })).toBeVisible();
	expect(await controls.evaluate((element) => element.scrollWidth <= element.clientWidth)).toBe(true);
	await page.screenshot({ path: testInfo.outputPath('approval-controls.png') });
});

test('expires an in-flight approval and renews it with disabled stale controls', async ({ page }) => {
	let renewed = false;
	await page.unroute('**/api/v1/workspaces/*/approvals');
	await page.route('**/api/v1/workspaces/*/approvals', async (route) => {
		await route.fulfill({
			json: {
				server_time: renewed ? 2100 : 1001,
				approvals: [
					{
						approval_id: renewed ? 'approval-new' : 'approval-expiring',
						run_id: 'run-expiring',
						kind: 'process.spawn',
						arguments: { program: '/bin/echo', args: ['hello'], environment: {} },
						capabilities: [],
						fingerprint: 'e'.repeat(64),
						created_at: 1,
						expires_at: renewed ? 62100 : 2000
					}
				]
			}
		});
	});
	await page.route('**/approvals/approval-expiring/decision', async (route) => {
		await route.fulfill({
			status: 409,
			json: { error: { code: 'approval_expired', message: 'approval expired' } }
		});
	});
	await page.route('**/approvals/approval-expiring/renew', async (route) => {
		renewed = true;
		await route.fulfill({
			json: {
				previous_approval_id: 'approval-expiring',
				approval_id: 'approval-new',
				run_id: 'run-expiring',
				state: 'pending'
			}
		});
	});

	await page.goto('/approvals');
	await page.getByRole('button', { name: 'Grant approval' }).click();
	await expect(page.getByText('This approval expired before the decision completed. Renew it to review a new request.')).toBeVisible();
	await expect(page.getByText('Expired')).toBeVisible();
	await expect(page.getByRole('button', { name: 'Grant approval' })).toBeDisabled();
	await expect(page.getByRole('button', { name: 'Reject approval' })).toBeDisabled();
	await expect(page.getByText('0 pending')).toBeVisible();
	await page.getByRole('button', { name: 'Renew approval' }).click();
	await expect(page.getByText('1 pending')).toBeVisible();
	await expect(page.getByText('Expires in 1m 0s')).toBeVisible();
	await expect(page.getByRole('button', { name: 'Grant approval' })).toBeEnabled();
});

test('opens audit event details without losing the list', async ({ page }, testInfo) => {
	await page.goto('/audit');

	await expect(page.getByText('execution_succeeded')).toBeVisible();
	await page.getByRole('button', { name: 'Inspect audit event 7' }).click();
	await expect(page.getByText('run-1')).toBeVisible();
	await expect(page.getByText('operator')).toBeVisible();
	await page.screenshot({ path: testInfo.outputPath('audit.png') });
});

test('shows plugin review controls without rendering secret values or overflowing', async ({ page }, testInfo) => {
	let requested = false;
	await page.route('**/api/v1/workspaces/*/plugins/actions', async (route) => {
		requested = true;
		expect(route.request().postDataJSON()).toMatchObject({
			kind: 'plugin.enable',
			plugin_version: '1.0.0',
			expected_digest: 'a'.repeat(64)
		});
		await route.fulfill({ status: 202, json: { run_id: 'run-plugin', state: 'approval_requested' } });
	});
	await page.goto('/plugins');

	await expect(page.getByRole('heading', { name: 'Plugins' })).toBeVisible();
	await expect(page.getByText('subprocess')).toBeVisible();
	await expect(page.getByText('a'.repeat(64)).first()).toBeVisible();
	await expect(page.getByText('filesystem.read').first()).toBeVisible();
	await expect(page.getByText('[redacted]')).toBeVisible();
	await expect(page.getByText('host_fault')).toBeVisible();
	await expect(page.getByText('actual-secret-must-not-render')).toHaveCount(0);
	expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
	await page.getByRole('button', { name: 'Enable' }).click();
	expect(requested).toBe(true);
	await expect(page.getByText('approval_requested: run-plugin')).toBeVisible();
	await page.screenshot({ path: testInfo.outputPath('plugins.png') });
});

test('shows egress channel controls and updates allowlisting', async ({ page }, testInfo) => {
	await page.goto('/egress');

	await expect(page.getByRole('heading', { name: 'Egress' })).toBeVisible();
	await expect(page.getByText('openai-compatible')).toBeVisible();
	await expect(page.getByText('remote')).toBeVisible();
	await expect(page.getByText('gpt-test')).toBeVisible();
	await expect(page.getByText('credential configured')).toBeVisible();
	await expect(page.getByText('local-llama')).toBeVisible();
	await expect(page.getByText('https://api.example.com/v1')).toBeVisible();
	await expect(page.getByLabel('Destination egress policies').getByText('public, workspace')).toBeVisible();
	await expect(page.getByText('https://hooks.example.com/')).toBeVisible();
	await expect(page.getByText('slack:T123:C456')).toBeVisible();
	await expect(page.getByText('local/operator')).toBeVisible();
	await expect(page.getByText('discord:guild-1:ops')).toBeVisible();
	await expect(page.getByText('browser-secret-must-not-render')).toHaveCount(0);
	await expect(page.getByText('secret-ref-openai')).toHaveCount(0);
	expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
	await page.getByRole('button', { name: 'Disable provider openai-compatible' }).click();
	await expect(page.getByText('Disabled provider openai-compatible')).toBeVisible();
	await page.getByRole('button', { name: 'Disable destination https://api.example.com/v1' }).click();
	await expect(page.getByText('Disabled https://api.example.com/v1')).toBeVisible();
	await page.getByRole('button', { name: 'Disable slack T123 C456' }).click();
	await expect(page.getByText('Disabled slack:T123:C456')).toBeVisible();
	await page.screenshot({ path: testInfo.outputPath('egress.png') });
});

test('shows automation controls and pauses scheduled jobs through approval requests', async ({ page }, testInfo) => {
	await page.goto('/automation');

	await expect(page.getByRole('heading', { name: 'Automation' })).toBeVisible();
	await expect(page.getByText('Nightly reviewer')).toBeVisible();
	await expect(page.getByText('service/nightly').first()).toBeVisible();
	await expect(page.getByText('every 60000 ms from 1000')).toBeVisible();
	await expect(page.getByText('model.prompt')).toHaveCount(0);
	await expect(page.getByText('browser-secret-must-not-render')).toHaveCount(0);
	expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
	await page.getByRole('button', { name: /Pause job/ }).click();
	await expect(page.getByText('Approval requested: run-job')).toBeVisible();
	await expect(page.getByRole('button', { name: /Pause job/ })).toBeVisible();
	await page.screenshot({ path: testInfo.outputPath('automation.png') });
});

test('shows skill reviews and publishes capture drafts without revealing secrets', async ({ page }, testInfo) => {
	await page.goto('/skills');

	await expect(page.getByRole('heading', { name: 'Skills' })).toBeVisible();
	await expect(page.getByText('Issue triage')).toBeVisible();
	await expect(page.getByText('a'.repeat(64))).toBeVisible();
	await expect(page.getByText('Captured triage workflow')).toBeVisible();
	await expect(page.getByText('[redacted]')).toBeVisible();
	await expect(page.getByText('browser-secret-must-not-render')).toHaveCount(0);
	expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
	await page.getByRole('button', { name: 'Request publication approval for Captured triage workflow' }).click();
	await expect(page.getByText('Publication approval requested: run-skill')).toBeVisible();
	await page.screenshot({ path: testInfo.outputPath('skills.png') });
});
