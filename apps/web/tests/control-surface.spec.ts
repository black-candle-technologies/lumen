import { expect, test, type Page } from '@playwright/test';

const workspaceId = '26db5a31-94f0-4e92-a9c9-4cdf19d71c31';

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
						approval_id: 'approval-1',
						run_id: 'run-approval',
						kind: 'process.spawn',
						arguments: { program: '/bin/echo', args: ['hello'], environment: {} },
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
	await page.route('**/approvals/approval-1/decision', async (route) => {
		await route.fulfill({
			status: 409,
			json: { error: { code: 'conflict', message: 'action fingerprint changed' } }
		});
	});
	await page.goto('/approvals');

	await expect(page.getByRole('heading', { name: 'process.spawn' })).toBeVisible();
	await expect(page.locator('pre').filter({ hasText: '/bin/echo' }).first()).toBeVisible();
	await expect(page.getByText('a'.repeat(64), { exact: false })).toBeVisible();
	await page.getByRole('button', { name: 'Grant approval' }).click();
	await expect(page.getByText('Action changed. Review the refreshed request.')).toBeVisible();
	await page.screenshot({ path: testInfo.outputPath('approval.png') });
});

test('opens audit event details without losing the list', async ({ page }, testInfo) => {
	await page.goto('/audit');

	await expect(page.getByText('execution_succeeded')).toBeVisible();
	await page.getByRole('button', { name: 'Inspect audit event 7' }).click();
	await expect(page.getByText('run-1')).toBeVisible();
	await expect(page.getByText('operator')).toBeVisible();
	await page.screenshot({ path: testInfo.outputPath('audit.png') });
});
