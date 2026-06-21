export type Risk = 'low' | 'medium' | 'high' | 'critical';
export type Status = 'ok' | 'warning' | 'blocked' | 'disabled' | 'running' | 'pending';

export type Approval = {
	id: string;
	risk: Risk;
	requester: string;
	action: string;
	target: string;
	time: string;
	state: 'pending' | 'approved' | 'denied';
};

export type AuditEvent = {
	id: string;
	time: string;
	actor: string;
	action: string;
	target: string;
	tool: string;
	risk: Risk;
	status: 'allowed' | 'denied' | 'pending' | 'failed';
	approval: string;
	source: string;
	permission: string;
	version: string;
	systems: string[];
	result: string;
	raw: Record<string, unknown>;
};

export const runtime = {
	status: 'running',
	host: 'localhost:7410',
	mode: 'local-only',
	uptime: '02h 18m',
	queue: '3 pending approvals',
	model: 'llama-3.1-8b-local'
};

export const activity = [
	'Approval requested for shell command in workspace',
	'Nightly repo scan completed with 2 warnings',
	'Plugin filesystem.safe-read loaded in restricted scope',
	'Local model runner health check passed'
];

export const jobs = [
	{
		name: 'Nightly repo scan',
		schedule: '0 2 * * *',
		owner: 'maintenance-agent',
		status: 'enabled',
		lastRun: 'Today 02:00',
		nextRun: 'Tomorrow 02:00'
	},
	{
		name: 'Inbox action draft',
		schedule: '*/30 9-17 * * Mon-Fri',
		owner: 'assistant',
		status: 'enabled',
		lastRun: '11:30',
		nextRun: '12:00'
	},
	{
		name: 'Monthly archive cleanup',
		schedule: '0 5 1 * *',
		owner: 'storage-agent',
		status: 'disabled',
		lastRun: 'Never',
		nextRun: '-'
	}
];

export const approvals: Approval[] = [
	{
		id: 'appr_1042',
		risk: 'high',
		requester: 'shell-agent',
		action: 'Run command: pnpm install',
		target: 'local shell',
		time: '12:14',
		state: 'pending'
	},
	{
		id: 'appr_1041',
		risk: 'medium',
		requester: 'plugin-manager',
		action: 'Install plugin: github.triage',
		target: 'plugin registry',
		time: '12:09',
		state: 'pending'
	},
	{
		id: 'appr_1040',
		risk: 'medium',
		requester: 'mail-agent',
		action: 'Send external message',
		target: 'gmail',
		time: '11:58',
		state: 'pending'
	},
	{
		id: 'appr_1039',
		risk: 'critical',
		requester: 'cleanup-agent',
		action: 'Delete data older than 90 days',
		target: 'local vault',
		time: '11:47',
		state: 'pending'
	},
	{
		id: 'appr_1038',
		risk: 'high',
		requester: 'scheduler',
		action: 'Create recurring job',
		target: 'jobs',
		time: '11:31',
		state: 'pending'
	}
];

export const auditEvents: AuditEvent[] = [
	{
		id: 'evt_58291',
		time: '12:14:33',
		actor: 'shell-agent',
		action: 'command.requested',
		target: 'C:\\Users\\laneb\\lumen',
		tool: 'shell.local',
		risk: 'high',
		status: 'pending',
		approval: 'appr_1042',
		source: 'chat',
		permission: 'shell.exec.workspace',
		version: 'core@0.1.0',
		systems: ['filesystem', 'shell'],
		result: 'Waiting for human approval',
		raw: { command: 'pnpm install', cwd: 'C:\\Users\\laneb\\lumen', approval: 'required' }
	},
	{
		id: 'evt_58277',
		time: '12:02:10',
		actor: 'maintenance-agent',
		action: 'job.completed',
		target: 'nightly repo scan',
		tool: 'jobs.scheduler',
		risk: 'low',
		status: 'allowed',
		approval: 'not required',
		source: 'scheduler',
		permission: 'workspace.read',
		version: 'core@0.1.0',
		systems: ['filesystem'],
		result: 'Completed with warnings',
		raw: { warnings: 2, duration_ms: 1824 }
	},
	{
		id: 'evt_58240',
		time: '11:47:55',
		actor: 'cleanup-agent',
		action: 'data.delete.requested',
		target: 'local vault',
		tool: 'storage.vault',
		risk: 'critical',
		status: 'denied',
		approval: 'appr_1039',
		source: 'job',
		permission: 'vault.delete',
		version: 'storage@0.3.2 hash:9f42c0',
		systems: ['vault', 'filesystem'],
		result: 'Denied by policy',
		raw: { retention_days: 90, policy: 'manual approval required' }
	}
];

export const plugins = [
	{
		name: 'filesystem.safe-read',
		enabled: true,
		permissions: ['workspace.read', 'path.allowlist'],
		version: '0.2.1',
		hash: 'sha256:8b4a...19cd',
		scope: 'workspace'
	},
	{
		name: 'shell.local',
		enabled: true,
		permissions: ['shell.exec.workspace'],
		version: '0.1.0',
		hash: 'sha256:ae72...441a',
		scope: 'approval-gated'
	},
	{
		name: 'gmail.draft-only',
		enabled: false,
		permissions: ['mail.read', 'mail.draft'],
		version: '0.4.0',
		hash: 'sha256:772b...a933',
		scope: 'user'
	}
];

export const models = [
	{
		provider: 'Local runner',
		status: 'ok',
		model: 'llama-3.1-8b-local',
		endpoint: 'http://127.0.0.1:11434',
		streaming: true,
		role: 'default chat and jobs'
	},
	{
		provider: 'OpenAI-compatible',
		status: 'pending',
		model: 'gpt-compatible-placeholder',
		endpoint: 'https://api.example.local/v1',
		streaming: true,
		role: 'optional remote fallback'
	},
	{
		provider: 'Experimental vision',
		status: 'disabled',
		model: 'vision-disabled',
		endpoint: '-',
		streaming: false,
		role: 'disabled example'
	}
];

export const messages = [
	{ role: 'system', body: 'Runtime policy loaded. High-risk actions require approval.' },
	{ role: 'user', body: 'Scan this repo and summarize risky changes.' },
	{
		role: 'agent',
		body: 'I can inspect the workspace with read-only permissions. Shell commands will pause for approval.'
	}
];
