/**
 * Minimal compile-time declarations for the `@earendil-works/pi-ai` surface
 * used by the BCT extension (TypeBox re-export). Runtime: Pi virtual module.
 */
export declare const Type: {
	Object<T extends Record<string, unknown>>(props: T, options?: Record<string, unknown>): T;
	String(options?: Record<string, unknown>): string;
	Number(options?: Record<string, unknown>): number;
	Optional<T>(schema: T): T | undefined;
};
