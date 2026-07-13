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
