import { fireEvent, render, screen } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';

import type { Approval } from '$lib/api';
import ApprovalItem from './ApprovalItem.svelte';

describe('ApprovalItem', () => {
	it('shows the immutable action preview and sends explicit decisions', async () => {
		const onDecision = vi.fn();
		render(ApprovalItem, {
			approval: {
				approval_id: 'approval-1',
				run_id: 'run-1',
				kind: 'process.spawn',
				arguments: { program: '/bin/echo', args: ['hello'], environment: { LANG: 'C' } },
				capabilities: [{ name: 'process.spawn', scope: { executable: '/bin/echo' } }],
				fingerprint: 'a'.repeat(64),
				created_at: 10,
				expires_at: 20
			},
			onDecision
		});

		expect(screen.getByText('process.spawn')).toBeInTheDocument();
		expect(screen.getAllByText('/bin/echo', { exact: false })).toHaveLength(3);
		expect(screen.getByText('a'.repeat(64), { exact: false })).toBeInTheDocument();

		await fireEvent.click(screen.getByRole('button', { name: 'Grant approval' }));
		expect(onDecision).toHaveBeenCalledWith('approval-1', 'grant');
	});

	it('shows exact before and after file content, hashes, and byte counts', () => {
		render(ApprovalItem, {
			approval: {
				approval_id: 'approval-write',
				run_id: 'run-write',
				kind: 'filesystem.write',
				arguments: {
					path: 'notes/today.md',
					before: { exists: true, content: 'before', sha256: 'b'.repeat(64), bytes: 6 },
					after: { content: 'after', sha256: 'a'.repeat(64), bytes: 5 }
				},
				capabilities: [],
				fingerprint: 'f'.repeat(64),
				created_at: 10,
				expires_at: 20
			},
			onDecision: vi.fn()
		});

		expect(screen.getByRole('heading', { name: 'Before' })).toBeInTheDocument();
		expect(screen.getByRole('heading', { name: 'After' })).toBeInTheDocument();
		expect(screen.getByText('notes/today.md')).toBeInTheDocument();
		expect(screen.getByText('before')).toBeInTheDocument();
		expect(screen.getByText('after')).toBeInTheDocument();
		expect(screen.getByText('6 bytes')).toBeInTheDocument();
		expect(screen.getByText('5 bytes')).toBeInTheDocument();
		expect(screen.getByText('b'.repeat(64))).toBeInTheDocument();
		expect(screen.getByText('a'.repeat(64))).toBeInTheDocument();
	});

	it('calls out a new file instead of inventing prior content', () => {
		render(ApprovalItem, {
			approval: {
				approval_id: 'approval-new',
				run_id: 'run-new',
				kind: 'filesystem.write',
				arguments: {
					path: 'notes/new.md',
					before: { exists: false, content: null, sha256: null, bytes: 0 },
					after: { content: 'created', sha256: 'c'.repeat(64), bytes: 7 }
				},
				capabilities: [],
				fingerprint: 'f'.repeat(64),
				created_at: 10,
				expires_at: 20
			},
			onDecision: vi.fn()
		});

		expect(screen.getByText('New file')).toBeInTheDocument();
		expect(screen.getByText('File does not exist')).toBeInTheDocument();
	});

	it('shows secret reference labels and environment names without rendering values', () => {
		const approval = {
			approval_id: 'approval-secret',
			run_id: 'run-secret',
			kind: 'process.spawn',
			arguments: {
				program: '/usr/bin/curl',
				args: ['https://example.test'],
				environment: {},
				secret_environment: { API_TOKEN: '5f7cc8b4-e848-4cb4-91ef-27c5983c41a5' }
			},
			secret_references: [
				{
					id: '5f7cc8b4-e848-4cb4-91ef-27c5983c41a5',
					label: 'Example API token',
					environment: 'API_TOKEN',
					value: 'actual-secret-must-not-render'
				}
			],
			capabilities: [],
			fingerprint: 'f'.repeat(64),
			created_at: 10,
			expires_at: 20
		} as unknown as Approval;
		render(ApprovalItem, {
			approval,
			onDecision: vi.fn()
		});

		expect(screen.getByText('Example API token')).toBeInTheDocument();
		expect(screen.getByText('API_TOKEN')).toBeInTheDocument();
		expect(screen.queryByText('actual-secret-must-not-render')).not.toBeInTheDocument();
	});
});
