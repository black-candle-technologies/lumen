import { strict as assert } from "node:assert";
import { test } from "node:test";
import { BRIDGE_TITLE, BRIDGE_TIMEOUT_MS, decodeReply, requestRead } from "./host-client.js";

function completed() {
    return { version: 2, tool_call_id: "call-1", action_digest: "a".repeat(64), outcome: {
        status: "completed", result: { exit_code: 0, output_tail: "host-result" },
        usage: { cpu_ms: 1, memory_bytes_max: 4096, egress_bytes: 0 },
        audit_ref: { event_id: "audit-1", chain_hash: "b".repeat(64) },
    } };
}

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
