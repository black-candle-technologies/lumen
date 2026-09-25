/**
 * BCT Pi extension — phase-0 architecture spike.
 *
 * Registers kernel-mediated tools (`bct.*`) and serializes every tool
 * request to the Lumen kernel for an allow / deny / pending-approval
 * decision. The extension is a stub, not a security boundary: all
 * enforcement is repeated kernel-side, and replacing this extension cannot
 * grant authority the kernel did not issue (see the bypass inventory in
 * `crates/lumen-acceptance/tests/pi_bypass_inventory.rs`).
 *
 * Launch contract (set by the host supervisor):
 * - `pi --mode rpc --no-session --no-builtin-tools --extension <this file>`
 * - `LUMEN_KERNEL_SOCKET` — kernel Unix socket path
 * - `LUMEN_KERNEL_NONCE`  — per-session credential for the kernel transport
 * - `LUMEN_SESSION_ID`    — ephemeral Courier subject for this session
 * - `LUMEN_LEASE_IDS`     — comma-separated lease chain, leaf → root
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "@earendil-works/pi-ai";
import { defineTool } from "@earendil-works/pi-coding-agent";
import { randomUUID } from "node:crypto";
import { readFile, realpath } from "node:fs/promises";
import { effectiveReadCap, truncateUtf8Bytes } from "./read-limits.js";
import { evaluateAction, type ActionEnvelope } from "./kernel-client.js";

const TOOL_VERSION = "1";
const ACTION_TTL_MS = 60_000;

function kernelConfig() {
	const socketPath = process.env.LUMEN_KERNEL_SOCKET;
	const credential = process.env.LUMEN_KERNEL_NONCE;
	const sessionId = process.env.LUMEN_SESSION_ID;
	if (!socketPath || !credential || !sessionId) {
		throw new Error(
			"Lumen kernel is not configured: LUMEN_KERNEL_SOCKET, LUMEN_KERNEL_NONCE and LUMEN_SESSION_ID must be set",
		);
	}
	const leaseChain = (process.env.LUMEN_LEASE_IDS ?? "")
		.split(",")
		.map((s) => s.trim())
		.filter((s) => s.length > 0);
	return { socketPath, credential, sessionId, leaseChain };
}

function buildEnvelope(
	toolName: string,
	args: Record<string, unknown>,
	path: string,
): ActionEnvelope {
	const { sessionId, leaseChain } = kernelConfig();
	return {
		version: 1,
		action_id: randomUUID(),
		session_id: sessionId,
		tool: { name: toolName, version: TOOL_VERSION },
		arguments: args,
		inputs: [],
		resources: {
			paths: [{ path, rights: "read" }],
			network: [],
			secrets: [],
		},
		expected_effects: {
			file_read: true,
			file_write: false,
			network_egress: false,
			network_ingress: false,
			process_spawn: false,
		},
		lease_chain: leaseChain,
		nonce: randomUUID(),
		expires_at_ms: Date.now() + ACTION_TTL_MS,
	};
}

const readFileTool = defineTool({
	name: "bct.read_file",
	label: "Read file (kernel-mediated)",
	description:
		"Read a UTF-8 text file through the Lumen kernel. The kernel must allow the action " +
		"against an active lease before any byte is read. Use this for all file reads; " +
		"never use shell commands or other tools to read files.",
	parameters: Type.Object({
		path: Type.String({ description: "Absolute path of the file to read" }),
		max_bytes: Type.Optional(
			Type.Number({ description: "Maximum bytes to return (default 65536)" }),
		),
	}),

	async execute(toolCallId, params, _signal, _onUpdate, _ctx) {
		void toolCallId;
		const { socketPath, credential } = kernelConfig();
		const path = params.path as string;
		const requestedMax = params.max_bytes as number | undefined;

		const envelope = buildEnvelope("bct.read_file", { path }, path);
		const response = await evaluateAction(socketPath, credential, envelope);

		if (response.error) {
			throw new Error(`Lumen kernel error [${response.error.code}]: ${response.error.detail}`);
		}
		const decision = response.decision;
		if (!decision) {
			throw new Error("Lumen kernel returned no decision");
		}
		if (decision.decision === "deny") {
			throw new Error(
				`Denied by Lumen kernel [${decision.reason.code}]: ${decision.reason.detail}`,
			);
		}
		if (decision.decision === "pending_approval") {
			throw new Error(
				`Action requires human approval (${decision.approval_id}): ${decision.reason}. ` +
					`Action digest: ${response.action_digest ?? "unknown"}`,
			);
		}
		// The wire is untrusted JSON: fail closed on any decision string the
		// client does not explicitly handle.
		const decisionKind = decision.decision as string;
		if (decisionKind !== "allow") {
			throw new Error(
				`Lumen kernel returned unexpected decision '${decisionKind}'; refusing to read`,
			);
		}

		// The byte cap comes from the kernel's TruncateOutput obligation:
		// the kernel authorized at most this many bytes. Fail closed when
		// the obligation is absent instead of falling back to a local
		// constant that could exceed the authorization.
		const cap = effectiveReadCap(decision.obligations, requestedMax);

		// The kernel authorized `path` lexically, but readFile follows
		// symlinks: `/leased/escape/etc/passwd` (where `escape` -> `/`)
		// would expose an unleased file. Resolve first and refuse when
		// canonicalization changes the path, so the bytes read are the
		// bytes the kernel authorized.
		let resolved: string;
		try {
			resolved = await realpath(path);
		} catch (err) {
			throw new Error(
				`Lumen kernel allowed ${path} but it cannot be resolved: ${String(err)}`,
			);
		}
		if (resolved !== path) {
			throw new Error(
				`Refusing to read ${path}: it traverses a symlink (resolves to ${resolved}); ` +
					"kernel authorization is lexical and cannot cover the target",
			);
		}

		// Allowed: perform the read inside the Pi process. (Phase 0 mediates
		// reads kernel-side for authorization; phase 2 executes even reads
		// inside the sandbox.)
		const raw = await readFile(resolved, "utf8");
		// Truncate on UTF-8 byte boundaries: `cap` is a byte limit, and
		// slicing the JS string could split a multi-byte character or hand
		// back more bytes than authorized.
		const { text, truncated } = truncateUtf8Bytes(raw, cap);
		return {
			content: [
				{
					type: "text",
					text: truncated
						? `${text}\n…[truncated at ${cap} bytes by kernel obligation]`
						: text,
				},
			],
			details: {
				action_digest: response.action_digest,
				audit_sequence: response.audit_sequence,
				decision: "allow",
			},
		};
	},
});

export default function bctExtension(pi: ExtensionAPI) {
	pi.registerTool(readFileTool);

	// Defense in depth: only kernel-mediated tools may execute. The primary
	// control is `--no-builtin-tools` at process launch; this handler covers
	// the case where the flag was not passed, and a `tool_call` handler
	// failure blocks the tool as a fail-safe.
	pi.on("tool_call", (event) => {
		if (!event.toolName.startsWith("bct.")) {
			return {
				block: true,
				reason: `Tool '${event.toolName}' is not a kernel-mediated BCT tool and cannot execute in this session`,
			};
		}
		return undefined;
	});

	// Keep the active tool set minimal even if Pi was launched without
	// `--no-builtin-tools`.
	pi.on("session_start", () => {
		pi.setActiveTools(["bct.read_file"]);
	});

	// Block the raw `bash` RPC command path. The supervisor never sends it;
	// this handler guarantees it cannot execute if it ever is sent, by
	// returning a replacement result (returning undefined would fall through
	// to local execution).
	pi.on("user_bash", (event) => {
		const preview = event.command.slice(0, 200);
		return {
			result: {
				output:
					`Blocked by the Lumen boundary: raw shell execution is unavailable in this session. ` +
					`Use kernel-mediated tools instead. Refused command: ${preview}`,
				exitCode: 126,
				cancelled: false,
				truncated: false,
			},
		};
	});
}
