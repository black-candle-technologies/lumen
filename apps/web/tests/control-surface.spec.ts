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
	await page.route('**/api/v1/workspaces/*/approvals', async (route) => {
		await route.fulfill({
			json: {
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
			json: { error: { code: 'conflict', message: 'action fingerprint changed' } }
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
	await expect(page.getByText('Action changed. Review the refreshed request.')).toBeVisible();
	await page.screenshot({ path: testInfo.outputPath('approval.png') });
	const controls = fileApproval.locator('footer');
	await controls.scrollIntoViewIfNeeded();
	await expect(controls.getByRole('button', { name: 'Reject approval' })).toBeVisible();
	await expect(controls.getByRole('button', { name: 'Grant approval' })).toBeVisible();
	expect(await controls.evaluate((element) => element.scrollWidth <= element.clientWidth)).toBe(true);
	await page.screenshot({ path: testInfo.outputPath('approval-controls.png') });
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
	await expect(page.getByText('https://api.example.com/v1')).toBeVisible();
	await expect(page.getByText('public, workspace')).toBeVisible();
	await expect(page.getByText('https://hooks.example.com/')).toBeVisible();
	await expect(page.getByText('slack:T123:C456')).toBeVisible();
	await expect(page.getByText('local/operator')).toBeVisible();
	await expect(page.getByText('discord:guild-1:ops')).toBeVisible();
	await expect(page.getByText('browser-secret-must-not-render')).toHaveCount(0);
	expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
	await page.getByRole('button', { name: 'Disable destination https://api.example.com/v1' }).click();
	await expect(page.getByText('Disabled https://api.example.com/v1')).toBeVisible();
	await page.getByRole('button', { name: 'Disable slack T123 C456' }).click();
	await expect(page.getByText('Disabled slack:T123:C456')).toBeVisible();
	await page.screenshot({ path: testInfo.outputPath('egress.png') });
});
