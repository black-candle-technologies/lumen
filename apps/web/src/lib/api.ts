export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

export type ConnectionSettings = {
	baseUrl: string;
	workspaceId: string;
	token: string;
};

export type RunEvent = {
	id: number;
	event: string;
	data: JsonValue;
};

export type Approval = {
	approval_id: string;
	run_id: string;
	kind: string;
	arguments: JsonValue;
	capabilities: JsonValue[];
	fingerprint: string;
	created_at: number;
	expires_at: number;
	secret_references?: Array<{ id: string; label: string; environment: string }>;
};

export type AuditEvent = {
	sequence: number;
	event_id: string;
	timestamp: number;
	kind: string;
	outcome: string;
	workspace_id: string;
	payload: JsonValue;
};

export type PrincipalSummary = {
	provider: string;
	subject: string;
};

export type StagedPluginReview = {
	stage_id: string;
	plugin_id: string;
	version: string;
	runtime: string;
	package_digest: string;
	manifest_digest: string;
	artifact_digest: string;
	file_hashes: Record<string, string>;
	requested_by: PrincipalSummary;
	created_at: number;
};

export type PluginComponentReview = {
	id: string;
	kind: string;
	requested_capabilities: JsonValue[];
	effective_grants: JsonValue[];
	grant_revision: number;
	grant_set_digest: string;
};

export type PluginSettingReview = {
	scope_type: string;
	scope_id: string;
	config_version: number;
	config: JsonValue;
	schema_digest: string;
	settings_digest: string;
};

export type PluginFailureReview = {
	class: string;
	count: number;
	diagnostic: string;
	diagnostic_digest: string;
	last_seen_at: number;
};

export type PluginVersionDetails = {
	plugin_id: string;
	version: string;
	state: string;
	package_digest: string;
	manifest_digest: string;
	artifact_digest: string;
	components: PluginComponentReview[];
	settings: PluginSettingReview[];
	failures: PluginFailureReview[];
};

export type PluginActionRequest = {
	kind: string;
	plugin_id: string;
	plugin_version: string;
	expected_digest: string;
	arguments?: JsonValue;
};

export class ApiError extends Error {
	constructor(
		public readonly status: number,
		public readonly code: string,
		message: string
	) {
		super(message);
	}
}

export class ApiClient {
	private readonly baseUrl: string;

	constructor(
		private readonly settings: ConnectionSettings,
		private readonly fetcher: typeof fetch = fetch
	) {
		this.baseUrl = settings.baseUrl.replace(/\/+$/, '');
	}

	async createRun(prompt: string): Promise<{ run_id: string }> {
		return this.request('runs', { method: 'POST', body: JSON.stringify({ prompt }) });
	}

	async cancelRun(runId: string): Promise<{ run_id: string; state: string }> {
		return this.request(`runs/${encodeURIComponent(runId)}/cancel`, { method: 'POST' });
	}

	async listApprovals(): Promise<Approval[]> {
		const response = await this.request<{ approvals: Approval[] }>('approvals');
		return response.approvals;
	}

	async decideApproval(approvalId: string, decision: 'grant' | 'reject'): Promise<void> {
		await this.request(`approvals/${encodeURIComponent(approvalId)}/decision`, {
			method: 'POST',
			body: JSON.stringify({ decision })
		});
	}

	async listAudit(after = 0, limit = 100): Promise<AuditEvent[]> {
		const response = await this.request<{ events: AuditEvent[] }>(
			`audit?after=${after}&limit=${limit}`
		);
		return response.events;
	}

	async listStagedPlugins(limit = 50, after = 0): Promise<StagedPluginReview[]> {
		const response = await this.request<{ packages: StagedPluginReview[] }>(
			`plugins/staged?after=${after}&limit=${limit}`
		);
		return response.packages;
	}

	async getPluginVersion(pluginId: string, version: string): Promise<PluginVersionDetails> {
		return this.request(
			`plugins/${encodeURIComponent(pluginId)}/versions/${encodeURIComponent(version)}`
		);
	}

	async requestPluginAction(
		request: PluginActionRequest
	): Promise<{ run_id: string; state: string }> {
		return this.request('plugins/actions', { method: 'POST', body: JSON.stringify(request) });
	}

	async streamRunEvents(
		runId: string,
		after: number,
		onEvent: (event: RunEvent) => void,
		signal?: AbortSignal
	): Promise<void> {
		const response = await this.fetcher(this.url(`runs/${encodeURIComponent(runId)}/events`), {
			headers: this.headers({ 'Last-Event-ID': String(after) }),
			signal
		});
		if (!response.ok) await this.throwResponse(response);
		if (!response.body) throw new ApiError(0, 'stream_unavailable', 'Run event stream is unavailable');

		const reader = response.body.getReader();
		const decoder = new TextDecoder();
		let buffer = '';
		while (true) {
			const { done, value } = await reader.read();
			buffer += decoder.decode(value, { stream: !done }).replace(/\r\n/g, '\n');
			let boundary = buffer.indexOf('\n\n');
			while (boundary !== -1) {
				const frame = buffer.slice(0, boundary);
				buffer = buffer.slice(boundary + 2);
				const event = parseFrame(frame);
				if (event) onEvent(event);
				boundary = buffer.indexOf('\n\n');
			}
			if (done) break;
		}
	}

	private async request<T>(path: string, init: RequestInit = {}): Promise<T> {
		const response = await this.fetcher(this.url(path), {
			...init,
			headers: this.headers(init.headers)
		});
		if (!response.ok) await this.throwResponse(response);
		if (response.status === 204) return undefined as T;
		return (await response.json()) as T;
	}

	private url(path: string): string {
		return `${this.baseUrl}/api/v1/workspaces/${encodeURIComponent(this.settings.workspaceId)}/${path}`;
	}

	private headers(extra?: HeadersInit): Headers {
		const headers = new Headers(extra);
		headers.set('Authorization', `Bearer ${this.settings.token}`);
		headers.set('Accept', 'application/json');
		if (!headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
		return headers;
	}

	private async throwResponse(response: Response): Promise<never> {
		let code = 'request_failed';
		let message = `Runtime returned HTTP ${response.status}`;
		try {
			const body = (await response.json()) as { error?: { code?: string; message?: string } };
			code = body.error?.code ?? code;
			message = body.error?.message ?? message;
		} catch {
			// Keep the bounded status-only fallback for non-JSON failures.
		}
		throw new ApiError(response.status, code, message);
	}
}

function parseFrame(frame: string): RunEvent | null {
	let id = 0;
	let event = 'message';
	const data: string[] = [];
	for (const line of frame.split('\n')) {
		if (line.startsWith(':')) continue;
		const separator = line.indexOf(':');
		const field = separator === -1 ? line : line.slice(0, separator);
		const value = separator === -1 ? '' : line.slice(separator + 1).replace(/^ /, '');
		if (field === 'id') id = Number.parseInt(value, 10);
		if (field === 'event') event = value;
		if (field === 'data') data.push(value);
	}
	if (data.length === 0 || !Number.isFinite(id)) return null;
	return { id, event, data: JSON.parse(data.join('\n')) as JsonValue };
}
