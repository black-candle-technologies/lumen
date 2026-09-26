/**
 * Pi's documented RPC dialog subprotocol supplies correlation over stdio.
 * The reserved title is a transport discriminator, never a human approval.
 * A host without this protocol times out/returns undefined and grants nothing.
 */
export const BRIDGE_TITLE = "lumen.pi-bridge/2";
export const BRIDGE_TIMEOUT_MS = 60_000;

export interface HostDialogs {
    input(title: string, placeholder: string,
          options: { signal: AbortSignal; timeout: number }): Promise<string | undefined>;
}

function record(value: unknown): Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new Error("Malformed host response");
    }
    return value as Record<string, unknown>;
}

function exact(value: Record<string, unknown>, fields: string[]) {
    if (Object.keys(value).length !== fields.length || fields.some(f => !(f in value))) {
        throw new Error("Unknown or missing host response fields");
    }
}

function hash(value: unknown): value is string {
    return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}

export function decodeReply(raw: string, toolCallId: string, maxBytes: number) {
    if (new TextEncoder().encode(raw).byteLength > 2 * 1024 * 1024) {
        throw new Error("Host response exceeded size limit");
    }
    const reply = record(JSON.parse(raw));
    exact(reply, ["version", "tool_call_id", "action_digest", "outcome"]);
    if (reply.version !== 2 || reply.tool_call_id !== toolCallId || !hash(reply.action_digest)) {
        throw new Error("Host response version, correlation, or digest mismatch");
    }
    const outcome = record(reply.outcome);
    if (outcome.status !== "completed") {
        const fields: Record<string, string[]> = {
            denied: ["status", "reason"],
            pending_approval: ["status", "reason", "approval_request_id"],
            invalid_request: ["status", "reason"],
            fault: ["status", "reason"],
            uncertain: ["status", "reason", "result", "usage", "action_digest", "staged_audit_ref"],
        };
        const expected = typeof outcome.status === "string" ? fields[outcome.status] : undefined;
        if (!expected) throw new Error("Unknown host outcome; no execution result");
        exact(outcome, expected);
        if (typeof outcome.reason !== "string") throw new Error("Missing host outcome reason");
        if (outcome.status === "pending_approval" &&
            (typeof outcome.approval_request_id !== "string" || !outcome.approval_request_id)) {
            throw new Error("Missing approval request identifier");
        }
        // Never retry or run a local operation for deny, pending, fault, or
        // uncertain. Never return uncertain output as an audited completion.
        throw new Error(`Lumen ${outcome.status}: ${outcome.reason}`);
    }
    exact(outcome, ["status", "result", "usage", "audit_ref"]);
    const result = record(outcome.result);
    exact(result, ["exit_code", "output_tail"]);
    const usage = record(outcome.usage);
    exact(usage, ["cpu_ms", "memory_bytes_max", "egress_bytes"]);
    if (Object.values(usage).some(n => typeof n !== "number" || !Number.isSafeInteger(n) || n < 0)) {
        throw new Error("Unknown or invalid execution usage");
    }
    const audit = record(outcome.audit_ref);
    exact(audit, ["event_id", "chain_hash"]);
    if (typeof audit.event_id !== "string" || !audit.event_id || !hash(audit.chain_hash)) {
        throw new Error("Missing durable audit reference");
    }
    if (result.exit_code !== 0 || typeof result.output_tail !== "string" ||
        new TextEncoder().encode(result.output_tail).byteLength > maxBytes) {
        throw new Error("Invalid or oversized read result");
    }
    return {
        content: [{ type: "text" as const, text: result.output_tail }],
        details: { action_digest: reply.action_digest, usage, audit_ref: audit },
    };
}

export async function requestRead(
    toolCallId: string, params: Record<string, unknown>, signal: AbortSignal | undefined, dialogs: HostDialogs,
) {
    // The pinned Pi ToolDefinition permits an absent signal. The RPC timeout
    // still bounds the dialog, and a provided signal is preserved unchanged.
    const cancellation = signal ?? new AbortController().signal;
    const maxBytes = params.max_bytes === undefined ? 65_536 : params.max_bytes;
    if (!/^[a-zA-Z0-9_.:-]{1,128}$/.test(toolCallId) ||
        typeof params.path !== "string" || !params.path.startsWith("/") ||
        params.path.includes("\0") || new TextEncoder().encode(params.path).byteLength > 4096 ||
        Object.keys(params).some(k => k !== "path" && k !== "max_bytes") ||
        typeof maxBytes !== "number" || !Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 1_048_576) {
        throw new Error("Invalid read arguments");
    }
    cancellation.throwIfAborted();
    const request = JSON.stringify({ version: 2, tool_call_id: toolCallId, tool: "bct.read_file",
                                    arguments: { path: params.path, max_bytes: maxBytes } });
    const raw = await dialogs.input(BRIDGE_TITLE, request, { signal: cancellation, timeout: BRIDGE_TIMEOUT_MS });
    cancellation.throwIfAborted();
    if (raw === undefined) throw new Error("Host bridge unavailable, cancelled, or timed out");
    return decodeReply(raw, toolCallId, maxBytes);
}
