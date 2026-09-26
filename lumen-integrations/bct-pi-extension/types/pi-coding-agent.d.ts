/**
 * Minimal compile-time declarations for the Pi extension API surface used by
 * the BCT extension. At runtime Pi serves the real implementations through
 * its virtual modules (`@earendil-works/pi-coding-agent`); these stubs exist
 * only so `tsc --noEmit` can check the extension without Pi's source tree.
 *
 * Pinned Pi: see ../PINNED_PI.md.
 */

export type ContentBlock = { type: "text"; text: string } | { type: "image"; data: string; mimeType: string };

export interface ToolResult {
	content: ContentBlock[];
	details?: unknown;
}

export interface ToolCallContext {
    ui: {
        input(title: string, placeholder: string,
              options: { signal: AbortSignal; timeout: number }): Promise<string | undefined>;
    };
}

export interface DefinedTool {
	name: string;
	label?: string;
	description: string;
	parameters: unknown;
	execute: (
		toolCallId: string,
		params: Record<string, unknown>,
		signal: AbortSignal | undefined,
		onUpdate: ((partial: unknown) => void) | undefined,
		ctx: ToolCallContext,
	) => Promise<ToolResult>;
}

export function defineTool(tool: {
	name: string;
	label?: string;
	description: string;
	parameters: unknown;
	execute: DefinedTool["execute"];
}): DefinedTool;

export interface ToolCallEvent {
	type: "tool_call";
	toolCallId: string;
	toolName: string;
	input: Record<string, unknown>;
}

export interface ToolCallEventResult {
	block?: boolean;
	reason?: string;
	terminate?: boolean;
}

export interface UserBashEvent {
	type: "user_bash";
	command: string;
	excludeFromContext: boolean;
	cwd: string;
}

export interface BashResult {
	output: string;
	exitCode: number | undefined;
	cancelled: boolean;
	truncated: boolean;
	fullOutputPath?: string;
}

export type UserBashEventResult =
	| { operations: unknown; result?: never }
	| { operations?: never; result: BashResult };

export interface ExtensionAPI {
	registerTool(tool: DefinedTool): void;
	setActiveTools(toolNames: string[]): void;
	on(event: "tool_call", handler: (event: ToolCallEvent) => ToolCallEventResult | undefined | Promise<ToolCallEventResult | undefined>): () => void;
	on(event: "user_bash", handler: (event: UserBashEvent) => UserBashEventResult | undefined | Promise<UserBashEventResult | undefined>): () => void;
	on(event: "session_start", handler: () => void | Promise<void>): () => void;
}
