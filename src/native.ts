import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { arch, platform } from "node:process";
import { fileURLToPath } from "node:url";

export interface Argon2NativeOptions {
	memoryKib?: number;
	iterations?: number;
	parallelism?: number;
	/** Secret pepper — not stored in the hash; required identically at verify. */
	secret?: Buffer;
	/** Variant: "d", "i" or "id". Default "id". */
	variant?: "d" | "i" | "id";
	/** Output length in bytes. Default 32. */
	hashLength?: number;
	/** Salt size in bytes. Default 16. */
	saltLength?: number;
}

export interface ScryptNativeOptions {
	cost?: number;
	blockSize?: number;
	parallelization?: number;
	keyLength?: number;
	saltLength?: number;
}

/**
 * The engine's surface, as the Rust declares it.
 *
 * Derived from `./native/generated.js` — written by `pnpm build:napi-types`
 * from napi-derive's own `type-def` output — rather than restated here, where
 * nothing would notice a `pub fn` gaining a parameter or changing its return.
 *
 * The option types above stay hand-written on purpose: they narrow what the
 * Rust types loosely (`variant` is a `String` there, three literals here). The
 * calls below still have to satisfy the generated signatures, so a field the
 * engine drops or renames stops compiling instead of failing at runtime.
 */
type NativeSigil = typeof import("./native/generated.js");

let native: NativeSigil | null = null;
let attempted = false;

export async function loadNative(): Promise<void> {
	// Cache both success (`native !== null`) and failure (`attempted === true`).
	// Without the failure cache, every consumer call would re-run `require()`
	// for an absent binary, triggering OS-level lookup churn.
	if (native || attempted) return;
	attempted = true;
	try {
		const req = createRequire(import.meta.url);
		const dir = dirname(fileURLToPath(import.meta.url));
		const platformMap: Record<string, string> = {
			"linux-x64": "linux-x64-gnu",
			"linux-arm64": "linux-arm64-gnu",
			"darwin-x64": "darwin-x64",
			"darwin-arm64": "darwin-arm64",
			"win32-x64": "win32-x64-msvc",
		};
		const suffix = platformMap[`${platform}-${arch}`];
		if (suffix) {
			native = req(join(dir, `../index.${suffix}.node`));
		}
	} catch {
		// Binary not loadable — `attempted` keeps subsequent calls O(1).
	}
}

export function isNativeLoaded(): boolean {
	return native !== null;
}

export function argon2Hash(
	password: string,
	options?: Argon2NativeOptions,
): string | null {
	return native?.argon2Hash(password, options) ?? null;
}

/**
 * The Argon2 cost parameters the engine applies when nothing is configured.
 *
 * `needsReHash` needs them to answer its actual question — "would hashing this
 * again produce something stronger?" — for an application that configured no
 * parameters, which is most of them. Asking the engine keeps the answer right
 * when the crate raises its defaults.
 */
export function argon2Defaults(): {
	memoryKib: number;
	iterations: number;
	parallelism: number;
} | null {
	return native?.argon2Defaults() ?? null;
}

export function argon2Verify(
	password: string,
	hash: string,
	secret?: Buffer,
): boolean | null {
	return native?.argon2Verify(password, hash, secret) ?? null;
}

export function bcryptHash(
	password: string,
	rounds?: number,
	version?: number,
	saltLength?: number,
): string | null {
	return native?.bcryptHash(password, rounds, version, saltLength) ?? null;
}

export function bcryptVerify(password: string, hash: string): boolean | null {
	return native?.bcryptVerify(password, hash) ?? null;
}

export function scryptHash(
	password: string,
	options?: ScryptNativeOptions,
): string | null {
	return native?.scryptHash(password, options) ?? null;
}

export function scryptVerify(password: string, hash: string): boolean | null {
	return native?.scryptVerify(password, hash) ?? null;
}
