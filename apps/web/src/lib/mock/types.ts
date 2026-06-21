// yaml fixtures are typed here until the runtime api exists
export type Risk = 'low' | 'medium' | 'high' | 'critical';
export type AuditFilter = 'all' | Risk;
export type ApprovalState = 'pending' | 'approved' | 'denied';
export type AuditStatus = 'allowed' | 'denied' | 'pending';
export type ProviderStatus = 'ok' | 'pending' | 'disabled';

export type RuntimeStatus = {
	status: string;
	host: string;
	mode: string;
	uptime: string;
	model: string;
};

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

export type Message = {
	role: 'system' | 'user' | 'agent';
	body: string;
};

export type SettingsGroup = {
	name: string;
	fields: string[];
};
