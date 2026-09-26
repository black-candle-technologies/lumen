/** PiBridge v2 stub. No filesystem, process, network, or credential access. */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "@earendil-works/pi-ai";
import { defineTool } from "@earendil-works/pi-coding-agent";
import { requestRead } from "./host-client.js";

const readFileTool = defineTool({
    name: "bct.read_file",
    label: "Read file (kernel-mediated)",
    description: "Request a bounded file read through the Lumen host and kernel.",
    parameters: Type.Object({
        path: Type.String({ description: "Absolute path of the file to read" }),
        max_bytes: Type.Optional(Type.Number({ description: "Maximum output bytes (default 65536)" })),
    }, { additionalProperties: false }),
    async execute(toolCallId, params, signal, _onUpdate, ctx) {
        return requestRead(toolCallId, params, signal, ctx.ui);
    },
});

export default function bctExtension(pi: ExtensionAPI) {
    pi.registerTool(readFileTool);
    // Convenience only. OS confinement must stop a replaced extension too.
    pi.on("tool_call", (event) => {
        if (event.toolName !== "bct.read_file") {
            return { block: true, reason: "Tool is not in the pinned BCT catalog" };
        }
        return undefined;
    });
    pi.on("session_start", () => { pi.setActiveTools(["bct.read_file"]); });
    pi.on("user_bash", () => ({
        result: { output: "Raw shell execution is unavailable", exitCode: 126,
                  cancelled: false, truncated: false },
    }));
}
