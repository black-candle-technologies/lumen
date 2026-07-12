import { fireEvent, render, screen } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';

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
		expect(screen.getAllByText('/bin/echo', { exact: false })).toHaveLength(2);
		expect(screen.getByText('a'.repeat(64), { exact: false })).toBeInTheDocument();

		await fireEvent.click(screen.getByRole('button', { name: 'Grant approval' }));
		expect(onDecision).toHaveBeenCalledWith('approval-1', 'grant');
	});
});
