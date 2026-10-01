import { strict as assert } from "node:assert";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { BRIDGE_TITLE, BRIDGE_TIMEOUT_MS, MAX_BRIDGE_READ_BYTES, MAX_BRIDGE_METADATA_BYTES,
    MAX_BRIDGE_REPLY_BYTES, decodeReply, requestRead } from "./host-client.js";

function completed() {
    return { version: 2, tool_call_id: "call-1", action_digest: "a".repeat(64), outcome: {
        status: "completed", result: { exit_code: 0, output_tail: "host-result" },
        usage: { cpu_ms: 1, memory_bytes_max: 4096, egress_bytes: 0 },
        audit_ref: { event_id: "audit-1", chain_hash: "b".repeat(64) },
    } };
}

function completedAtCap(text: string) {
    const reply = completed();
    reply.tool_call_id = "c".repeat(128);
    reply.outcome.result.output_tail = text;
    reply.outcome.usage = { cpu_ms: 1234, memory_bytes_max: 268_435_456, egress_bytes: 0 };
    reply.outcome.audit_ref.event_id = "018f6c6e-7f4a-7000-8000-0123456789ab";
    return reply;
}

test("TS limits match the shared PiBridge v2 wire budget", () => {
    const budget = JSON.parse(readFileSync(new URL(
        "../../../crates/lumen-protocol/fixtures/pibridge_reply_budget.v2.json", import.meta.url), "utf8"));
    assert.equal(MAX_BRIDGE_READ_BYTES, budget.max_decoded_bytes);
    assert.equal(MAX_BRIDGE_METADATA_BYTES, budget.max_metadata_bytes);
    assert.equal(MAX_BRIDGE_REPLY_BYTES, budget.max_wire_bytes);
    assert.equal(MAX_BRIDGE_REPLY_BYTES,
        budget.max_json_escape_bytes_per_decoded_byte * MAX_BRIDGE_READ_BYTES + MAX_BRIDGE_METADATA_BYTES);
});

for (const [name, unit] of [
    ["newline", "\n"], ["quote", '"'], ["backslash", "\\"], ["control", "\u0001"],
    ["multibyte", "é日😀a"], // 2 + 3 + 4 + 1 = 10 UTF-8 bytes per unit.
]) {
    test(`${name} results round-trip at the advertised cap with metadata and reject floods`, async () => {
        const unitBytes = Buffer.byteLength(unit, "utf8");
        const text = unit.repeat(Math.floor(MAX_BRIDGE_READ_BYTES / unitBytes)) +
            "x".repeat(MAX_BRIDGE_READ_BYTES % unitBytes);
        assert.equal(Buffer.byteLength(text, "utf8"), MAX_BRIDGE_READ_BYTES);
        const reply = completedAtCap(text);
        const raw = JSON.stringify(reply);
        assert.ok(Buffer.byteLength(raw, "utf8") <= MAX_BRIDGE_REPLY_BYTES);
        const result = await requestRead(reply.tool_call_id,
            { path: "/workspace/notes.txt", max_bytes: MAX_BRIDGE_READ_BYTES }, undefined, {
                async input(_title, request) {
                    assert.equal(JSON.parse(request).arguments.max_bytes, MAX_BRIDGE_READ_BYTES);
                    return raw;
                },
            });
        assert.equal(result.content[0].text, text);
        assert.deepEqual(result.details.audit_ref, reply.outcome.audit_ref);
        assert.deepEqual(result.details.usage, reply.outcome.usage);

        // A decoded overflow still fits the enlarged wire budget and must fail.
        reply.outcome.result.output_tail += "x";
        const overflow = JSON.stringify(reply);
        assert.ok(Buffer.byteLength(overflow, "utf8") < MAX_BRIDGE_REPLY_BYTES);
        assert.throws(() => decodeReply(overflow, reply.tool_call_id, MAX_BRIDGE_READ_BYTES),
            /oversized read result/);
        assert.throws(() => decodeReply(overflow, reply.tool_call_id, MAX_BRIDGE_READ_BYTES + 1),
            /oversized read result/);

        // Valid trailing JSON whitespace floods the wire without enlarging output.
        const wireFlood = raw + " ".repeat(MAX_BRIDGE_REPLY_BYTES - Buffer.byteLength(raw, "utf8") + 1);
        assert.equal(Buffer.byteLength(wireFlood, "utf8"), MAX_BRIDGE_REPLY_BYTES + 1);
        assert.throws(() => decodeReply(wireFlood, reply.tool_call_id, MAX_BRIDGE_READ_BYTES),
            /^Error: Host response exceeded size limit$/);
    });
}

test("worst-case escaping fits even at the metadata allowance; metadata floods fail", () => {
    const reply = completedAtCap("\u0001".repeat(MAX_BRIDGE_READ_BYTES));
    const metadata = completedAtCap("");
    // Include escaping in metadata accounting as well as ordinary audit metadata.
    metadata.outcome.audit_ref.event_id += "\u0001".repeat(100);
    metadata.outcome.audit_ref.event_id += "x".repeat(
        MAX_BRIDGE_METADATA_BYTES - Buffer.byteLength(JSON.stringify(metadata), "utf8"));
    reply.outcome.audit_ref = metadata.outcome.audit_ref;
    const raw = JSON.stringify(reply);
    assert.equal(Buffer.byteLength(raw, "utf8"), MAX_BRIDGE_REPLY_BYTES);
    assert.equal(decodeReply(raw, reply.tool_call_id, MAX_BRIDGE_READ_BYTES).content[0].text,
        reply.outcome.result.output_tail);

    metadata.outcome.audit_ref.event_id += "x";
    assert.throws(() => decodeReply(JSON.stringify(metadata), metadata.tool_call_id, MAX_BRIDGE_READ_BYTES),
        /metadata exceeded size limit/);
});

test("read sends intent over Pi stdio dialog and returns only host result", async () => {
    const signal = new AbortController().signal;
    let calls = 0;
    const result = await requestRead("call-1", {path: "/etc/passwd"}, signal, {
        async input(title, request, options) {
            calls++;
            assert.equal(title, BRIDGE_TITLE);
            assert.deepEqual(JSON.parse(request), {version: 2, tool_call_id: "call-1", tool: "bct.read_file",
                arguments: {path: "/etc/passwd", max_bytes: 65536}});
            assert.equal(options.signal, signal);
            assert.equal(options.timeout, BRIDGE_TIMEOUT_MS);
            return JSON.stringify(completed());
        },
    });
    assert.equal(calls, 1);
    assert.equal(result.content[0].text, "host-result");
});

test("allow-only, unknown versions, correlation swaps and unknown fields fail closed", () => {
    for (const value of [
        {decision: "allow"}, {...completed(), version: 1}, {...completed(), version: 3},
        {...completed(), tool_call_id: "another-session-call"}, {...completed(), credential: "unexpected"},
        {...completed(), action_digest: ""}, {...completed(), outcome: {status: "allow"}},
    ]) assert.throws(() => decodeReply(JSON.stringify(value), "call-1", 65536));
});

test("pinned Pi may omit the cancellation signal", async () => {
    const result = await requestRead("call-1", {path: "/a"}, undefined, {
        async input(_title, _request, options) {
            assert.equal(options.signal.aborted, false);
            assert.equal(options.timeout, BRIDGE_TIMEOUT_MS);
            return JSON.stringify(completed());
        },
    });
    assert.equal(result.content[0].text, "host-result");
});

test("missing audit, unknown usage, oversized UTF-8 and failed execution are not results", () => {
    const values = ["audit", "usage", "size", "exit", "extra"];
    for (const variant of values) {
        const value = completed();
        if (variant === "audit") value.outcome.audit_ref.chain_hash = "";
        if (variant === "usage") value.outcome.usage.cpu_ms = -1;
        if (variant === "size") value.outcome.result.output_tail = "é".repeat(10);
        if (variant === "exit") value.outcome.result.exit_code = 1;
        if (variant === "extra") Object.assign(value.outcome.usage, {secret: "unexpected"});
        assert.throws(() => decodeReply(JSON.stringify(value), "call-1", 12));
    }
});

test("deny, pending, fault and uncertain return errors exactly once", async () => {
    for (const outcome of [
        {status: "denied", reason: "scope"},
        {status: "pending_approval", reason: "approval needed", approval_request_id: "apr-1"},
        {status: "fault", reason: "audit unavailable"},
        {status: "uncertain", reason: "completion audit unavailable", result: {}, usage: {},
            action_digest: "a".repeat(64), staged_audit_ref: {}},
    ]) {
        let calls = 0;
        await assert.rejects(requestRead("call-1", {path: "/etc/passwd"}, new AbortController().signal, {
            async input() { calls++; return JSON.stringify({...completed(), outcome}); },
        }), new RegExp(outcome.status));
        assert.equal(calls, 1);
    }
});

test("unavailable host, timeout, cancellation and changed arguments never fall back", async () => {
    const controller = new AbortController();
    await assert.rejects(requestRead("call-1", {path: "/etc/passwd"}, controller.signal, {
        async input() { return undefined; },
    }), /unavailable, cancelled, or timed out/);
    await assert.rejects(requestRead("call-1", {path: "/etc/passwd"}, controller.signal, {
        async input() { controller.abort(); return JSON.stringify(completed()); },
    }), /abort/i);
    let calls = 0;
    const dialogs = {async input() { calls++; return JSON.stringify(completed()); }};
    for (const params of [{path: "/a", max_bytes: -1}, {path: "/a", max_bytes: 1.5},
        {path: "relative"}, {path: "/a", session_id: "forged"}]) {
        await assert.rejects(requestRead("call-1", params, new AbortController().signal, dialogs));
    }
    assert.equal(calls, 0);
});
