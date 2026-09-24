/**
 * Minimal client for the Lumen kernel's authenticated local transport.
 *
 * Protocol: `lumen-kernel/1` over a Unix domain socket, one JSON object per
 * line in each direction (JSONL). The credential is the per-session nonce
 * the host placed in `LUMEN_KERNEL_NONCE`.
 *
 * A fresh connection is opened per evaluation: simple, robust against
 * half-open sockets, and cheap on loopback Unix sockets.
 */

import { connect } from "node:net";

export interface ActionEnvelope {
	version: number;
	action_id: string;
	session_id: string;
	tool: { name: string; version: string };
	arguments: Record<string, unknown>;
	inputs: Array<{ content_hash: string; snapshot_id?: string }>;
	resources: {
		paths: Array<{ path: string; rights: "read" | "write" }>;
		network: unknown[];
		secrets: unknown[];
	};
	expected_effects: {
		file_read: boolean;
		file_write: boolean;
		network_egress: boolean;
		network_ingress: boolean;
		process_spawn: boolean;
	};
	lease_chain: string[];
	nonce: string;
	expires_at_ms: number;
}

export type PolicyDecision =
	| { version: number; decision: "allow"; obligations: Array<{ type: string; [k: string]: unknown }> }
	| { version: number; decision: "deny"; reason: { code: string; detail: string } }
	| { version: number; decision: "pending"; approval_id: string; reason: string };

export interface KernelWireResponse {
	protocol: string;
	decision?: PolicyDecision;
	audit_sequence?: number;
	action_digest?: string;
	error?: { code: string; detail: string };
}

const MAX_RESPONSE_BYTES = 1024 * 1024;
const CONNECT_TIMEOUT_MS = 5_000;

export async function evaluateAction(
	socketPath: string,
	credential: string,
	envelope: ActionEnvelope,
): Promise<KernelWireResponse> {
	return new Promise((resolve, reject) => {
		const socket = connect(socketPath);
		let settled = false;
		const done = (fn: () => void) => {
			if (!settled) {
				settled = true;
				clearTimeout(timer);
				fn();
			}
		};
		const timer = setTimeout(() => {
			done(() => {
				socket.destroy();
				reject(new Error(`kernel connect/read timed out after ${CONNECT_TIMEOUT_MS}ms`));
			});
		}, CONNECT_TIMEOUT_MS);

		let buffer = "";
		socket.on("connect", () => {
			const request = JSON.stringify({
				protocol: "lumen-kernel/1",
				credential,
				envelope,
			});
			socket.write(request + "\n");
		});
		socket.on("data", (chunk: Buffer) => {
			buffer += chunk.toString("utf8");
			if (buffer.length > MAX_RESPONSE_BYTES) {
				done(() => {
					socket.destroy();
					reject(new Error("kernel response exceeded size limit"));
				});
				return;
			}
			const newline = buffer.indexOf("\n");
			if (newline !== -1) {
				const line = buffer.slice(0, newline);
				done(() => {
					socket.end();
					try {
						resolve(JSON.parse(line) as KernelWireResponse);
					} catch (err) {
						reject(new Error(`malformed kernel response: ${String(err)}`));
					}
				});
			}
		});
		socket.on("error", (err) => {
			done(() => reject(new Error(`kernel socket error: ${err.message}`)));
		});
		socket.on("close", () => {
			done(() => reject(new Error("kernel closed the connection before responding")));
		});
	});
}
