// Smoke test for read-limits.ts (no test runner in this package).
// Run: npx tsc src/read-limits.ts --outDir <dir> --module commonjs --target es2022 && node <dir>/test-read-limits.js
import { strict as assert } from "node:assert";
import { effectiveReadCap, truncateUtf8Bytes, MAX_READ_BYTES } from "./read-limits.js";

// effectiveReadCap: kernel obligation is authoritative.
assert.equal(effectiveReadCap([{ type: "truncate_output", max_bytes: 1024 }], undefined), 1024);
assert.equal(effectiveReadCap([{ type: "truncate_output", max_bytes: 1024 }], 512), 512);
// Requested cap can never raise the kernel's cap.
assert.equal(effectiveReadCap([{ type: "truncate_output", max_bytes: 1024 }], 999_999), 1024);
// Local ceiling can only lower.
assert.equal(
	effectiveReadCap([{ type: "truncate_output", max_bytes: 10 * MAX_READ_BYTES }], undefined),
	MAX_READ_BYTES,
);
// Fail closed: absent / malformed obligation.
assert.throws(() => effectiveReadCap([], undefined), /truncate_output/);
assert.throws(() => effectiveReadCap([{ type: "other" }], undefined), /truncate_output/);
assert.throws(
	() => effectiveReadCap([{ type: "truncate_output", max_bytes: NaN }], undefined),
	/truncate_output/,
);
assert.throws(
	() => effectiveReadCap([{ type: "truncate_output", max_bytes: -5 }], undefined),
	/truncate_output/,
);
assert.throws(
	() => effectiveReadCap([{ type: "truncate_output", max_bytes: "1024" }], undefined),
	/truncate_output/,
);
// Invalid requestedMax falls back to the kernel cap (fail-closed direction).
assert.equal(effectiveReadCap([{ type: "truncate_output", max_bytes: 100 }], NaN), 100);
assert.equal(effectiveReadCap([{ type: "truncate_output", max_bytes: 100 }], -1), 100);

// truncateUtf8Bytes: byte-accurate, never splits a character, never exceeds cap.
{
	const { text, truncated } = truncateUtf8Bytes("hello", 10);
	assert.equal(text, "hello");
	assert.equal(truncated, false);
}
{
	// "é" is 2 bytes; cap 3 fits "aé" (3 bytes) exactly.
	const { text, truncated } = truncateUtf8Bytes("aé", 3);
	assert.equal(text, "aé");
	assert.equal(truncated, false);
}
{
	// cap 2 cannot fit "é" (2 bytes) after "a": drops the whole character.
	const { text, truncated } = truncateUtf8Bytes("aé", 2);
	assert.equal(text, "a");
	assert.equal(truncated, true);
	assert.ok(Buffer.from(text, "utf8").length <= 2);
}
{
	// cap 1 with a 2-byte char: empty, not a replacement character.
	const { text, truncated } = truncateUtf8Bytes("é", 1);
	assert.equal(text, "");
	assert.equal(truncated, true);
}
{
	// 4-byte emoji straddling the boundary is dropped whole.
	const { text, truncated } = truncateUtf8Bytes("ab😀cd", 4);
	assert.equal(text, "ab");
	assert.equal(truncated, true);
	assert.ok(Buffer.from(text, "utf8").length <= 4);
}
{
	// Property-ish sweep: output never exceeds the cap, always valid UTF-8.
	const samples = ["héllo wörld 😀😀😀", "日本語テスト", "a".repeat(100) + "é".repeat(50)];
	for (const s of samples) {
		for (let cap = 0; cap < 40; cap++) {
			const { text } = truncateUtf8Bytes(s, cap);
			const bytes = Buffer.from(text, "utf8").length;
			assert.ok(bytes <= cap, `cap=${cap} bytes=${bytes} text=${JSON.stringify(text)}`);
			assert.equal(Buffer.from(text, "utf8").toString("utf8"), text, "must round-trip");
		}
	}
}

console.log("read-limits smoke test: all assertions passed");
