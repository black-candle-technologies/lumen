/**
 * Read-limit helpers for the `bct.read_file` tool.
 *
 * The byte cap is an authorization decision made by the Lumen kernel: the
 * `truncate_output` obligation on an allow decision states the maximum number
 * of file bytes the kernel authorized this read to return. These helpers are
 * pure so they can be unit-tested without the Pi SDK.
 */

/** Local defensive ceiling; never raises a cap, only lowers one. */
export const MAX_READ_BYTES = 64 * 1024;

export interface TruncateObligation {
	type: string;
	[k: string]: unknown;
}

/**
 * Derive the effective byte cap from the kernel's `truncate_output`
 * obligation.
 *
 * The effective cap never exceeds the kernel's obligated maximum; the
 * caller's requested cap and the local defensive ceiling can only lower it.
 * Throws (fail closed) when the obligation is absent or malformed, instead
 * of falling back to a local constant that could exceed the authorization.
 */
export function effectiveReadCap(
	obligations: TruncateObligation[] | undefined,
	requestedMax: number | undefined,
): number {
	const truncate = (obligations ?? []).find((o) => o.type === "truncate_output");
	const obligatedMax = truncate?.max_bytes;
	if (typeof obligatedMax !== "number" || !Number.isFinite(obligatedMax) || obligatedMax < 0) {
		throw new Error(
			"Lumen kernel allow decision carried no truncate_output obligation; refusing to read",
		);
	}
	const kernelCap = Math.floor(obligatedMax);
	const requestedCap =
		typeof requestedMax === "number" && Number.isFinite(requestedMax) && requestedMax >= 0
			? Math.floor(requestedMax)
			: kernelCap;
	return Math.min(requestedCap, kernelCap, MAX_READ_BYTES);
}

/**
 * Truncate a string to at most `cap` UTF-8 bytes without splitting a
 * multi-byte character.
 *
 * The returned text re-encoded as UTF-8 is always `<= cap` bytes: a
 * character straddling the boundary is dropped whole rather than replaced
 * with U+FFFD (whose 3-byte encoding could exceed the cap).
 */
export function truncateUtf8Bytes(raw: string, cap: number): { text: string; truncated: boolean } {
	const encoded = Buffer.from(raw, "utf8");
	if (encoded.length <= cap) {
		return { text: raw, truncated: false };
	}
	// Shrink `end` to a character boundary: drop the trailing character
	// while it does not fit completely inside `[0, end)`.
	let end = Math.max(0, Math.floor(cap));
	while (end > 0) {
		let start = end - 1;
		while (start > 0 && (encoded[start] & 0xc0) === 0x80) {
			start--;
		}
		const lead = encoded[start];
		const expected = lead < 0x80 ? 1 : lead < 0xe0 ? 2 : lead < 0xf0 ? 3 : 4;
		if (start + expected <= end) {
			break;
		}
		end = start;
	}
	return { text: encoded.subarray(0, end).toString("utf8"), truncated: true };
}
