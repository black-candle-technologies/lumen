export type Risk = 'low' | 'medium' | 'high' | 'critical';
export type AuditFilter = 'all' | Risk;

export type ApprovalState = 'pending' | 'approved' | 'denied';
export type AuditStatus = 'allowed' | 'denied' | 'pending' | 'failed';
export type ProviderStatus = 'ok' | 'pending' | 'disabled';

export type Approval = {
	id: string;
	risk: Risk;
	requester: string;
	action: string;
	target: string;
	timestamp: string;
	riskReason: string;
	state: ApprovalState;
};

export type AuditEvent = {
	id: string;
	timestamp: string;
	actor: string;
	action: string;
	target: string;
	tool: string;
	risk: Risk;
	status: AuditStatus;
	approval: string;
	source: string;
	permission: string;
	version: string;
	systems: string[];
	result: string;
	raw: Record<string, unknown>;
};

export type Job = {
	name: string;
	schedule: string;
	owner: string;
	status: 'enabled' | 'disabled';
	lastRun: string;
	nextRun: string;
};

export type Plugin = {
	name: string;
	enabled: boolean;
	permissions: string[];
	version: string;
	hash: string;
	scope: string;
};

export type ModelProvider = {
	provider: string;
	status: ProviderStatus;
	model: string;
	endpoint: string;
	streaming: boolean;
	role: string;
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

export const jobs: Job[] = [
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
		nextRun: 'Not scheduled'
	}
];

export const approvals: Approval[] = [
	{
		id: 'appr_1042',
		risk: 'high',
		requester: 'shell-agent',
		action: 'Run command: pnpm install',
		target: 'local shell',
		timestamp: '2026-06-20 12:14:33',
		riskReason: 'Shell execution can mutate the workspace and install third-party code.',
		state: 'pending'
	},
	{
		id: 'appr_1041',
		risk: 'medium',
		requester: 'plugin-manager',
		action: 'Install plugin: github.triage',
		target: 'plugin registry',
		timestamp: '2026-06-20 12:09:18',
		riskReason: 'New plugins must declare permissions before they can access local context.',
		state: 'pending'
	},
	{
		id: 'appr_1040',
		risk: 'medium',
		requester: 'mail-agent',
		action: 'Send external message',
		target: 'gmail',
		timestamp: '2026-06-20 11:58:02',
		riskReason: 'External messages can transmit private local information outside the machine.',
		state: 'pending'
	},
	{
		id: 'appr_1039',
		risk: 'critical',
		requester: 'cleanup-agent',
		action: 'Delete data older than 90 days',
		target: 'local vault',
		timestamp: '2026-06-20 11:47:55',
		riskReason: 'Data deletion is irreversible without a verified backup.',
		state: 'pending'
	},
	{
		id: 'appr_1038',
		risk: 'high',
		requester: 'scheduler',
		action: 'Create recurring job',
		target: 'jobs',
		timestamp: '2026-06-20 11:31:09',
		riskReason: 'Recurring jobs can repeatedly execute future actions without fresh prompts.',
		state: 'pending'
	}
];

export const auditEvents: AuditEvent[] = [
	{
		id: 'evt_58291',
		timestamp: '2026-06-20 12:14:33',
		actor: 'shell-agent',
		action: 'command.requested',
		target: 'C:\\Users\\laneb\\lumen',
		tool: 'shell.local',
		risk: 'high',
		status: 'pending',
		approval: 'appr_1042 pending',
		source: 'chat',
		permission: 'shell.exec.workspace',
		version: 'core@0.1.0 hash:ae72...441a',
		systems: ['filesystem', 'shell'],
		result: 'Waiting for human approval',
		raw: { command: 'pnpm install', cwd: 'C:\\Users\\laneb\\lumen', approval: 'required' }
	},
	{
		id: 'evt_58284',
		timestamp: '2026-06-20 12:09:18',
		actor: 'plugin-manager',
		action: 'plugin.install.requested',
		target: 'github.triage',
		tool: 'plugins.registry',
		risk: 'medium',
		status: 'pending',
		approval: 'appr_1041 pending',
		source: 'settings',
		permission: 'plugin.install',
		version: 'github.triage@0.1.0 hash:4bc1...18ad',
		systems: ['plugin registry', 'workspace metadata'],
		result: 'Install paused for permission review',
		raw: { plugin: 'github.triage', permissions: ['repo.read', 'issues.read'], approval: 'required' }
	},
	{
		id: 'evt_58277',
		timestamp: '2026-06-20 12:02:10',
		actor: 'maintenance-agent',
		action: 'job.completed',
		target: 'nightly repo scan',
		tool: 'jobs.scheduler',
		risk: 'low',
		status: 'allowed',
		approval: 'not required',
		source: 'scheduler',
		permission: 'workspace.read',
		version: 'core@0.1.0 hash:2c21...a9fd',
		systems: ['filesystem'],
		result: 'Completed with warnings',
		raw: { warnings: 2, duration_ms: 1824 }
	},
	{
		id: 'evt_58266',
		timestamp: '2026-06-20 11:58:02',
		actor: 'mail-agent',
		action: 'external.message.requested',
		target: 'gmail',
		tool: 'gmail.draft-only',
		risk: 'medium',
		status: 'pending',
		approval: 'appr_1040 pending',
		source: 'chat',
		permission: 'mail.send.external',
		version: 'gmail.draft-only@0.4.0 hash:772b...a933',
		systems: ['gmail'],
		result: 'Send paused for human review',
		raw: { recipient_domain: 'external.example', mode: 'send', approval: 'required' }
	},
	{
		id: 'evt_58240',
		timestamp: '2026-06-20 11:47:55',
		actor: 'cleanup-agent',
		action: 'data.delete.requested',
		target: 'local vault',
		tool: 'storage.vault',
		risk: 'critical',
		status: 'denied',
		approval: 'appr_1039 denied by policy',
		source: 'job',
		permission: 'vault.delete',
		version: 'storage@0.3.2 hash:9f42...77ba',
		systems: ['vault', 'filesystem'],
		result: 'Denied by policy',
		raw: { retention_days: 90, policy: 'manual approval required', backup_verified: false }
	},
	{
		id: 'evt_58192',
		timestamp: '2026-06-20 11:25:41',
		actor: 'model-router',
		action: 'model.selected',
		target: 'llama-3.1-8b-local',
		tool: 'model.local-runner',
		risk: 'low',
		status: 'allowed',
		approval: 'not required',
		source: 'chat',
		permission: 'model.local.invoke',
		version: 'local-runner@0.1.0 hash:190a...ce22',
		systems: ['local model runner'],
		result: 'Local model selected for mock session',
		raw: { provider: 'local', model: 'llama-3.1-8b-local', streaming: true }
	}
];

export const plugins: Plugin[] = [
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

export const models: ModelProvider[] = [
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
		endpoint: 'not configured',
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

export const settingsGroups = [
	{ name: 'Runtime', fields: ['Workspace root', 'Local API port', 'Startup mode'] },
	{ name: 'Local Model Runner', fields: ['Provider path', 'Default model', 'Context window'] },
	{ name: 'Security & Approvals', fields: ['Risk threshold', 'Approval timeout', 'Deny by default'] },
	{ name: 'User/Channel Allowlist', fields: ['Local user', 'Trusted channels', 'Blocked channels'] },
	{ name: 'Secrets', fields: ['Vault path', 'Key source', 'Rotation policy'] }
];
