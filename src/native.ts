import { arch, platform } from "node:process";
import {
	hasFunctions,
	loadNativeBinary,
	muslHint,
	supportedTargets,
} from "./vendor/nativeBinary.js";

/**
 * The npm name the platform packages derive from: `@c9up/sigil-<suffix>`,
 * one per target, each an optional dependency pinned to this version.
 */
const PACKAGE_NAME = "@c9up/sigil";

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
	/** Largest working set in bytes, `128 * r * (N + p + 2)`. Default 32 MiB. */
	maxMemory?: number;
}

/**
 * What this package calls on the engine, typed as the Rust declares it.
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
const NATIVE_CALLS = [
	"argon2Hash",
	"argon2Verify",
	"argon2Defaults",
	"costLimits",
	"bcryptHash",
	"bcryptVerify",
	"scryptHash",
	"scryptVerify",
] as const;

type NativeSigil = Pick<
	typeof import("./native/generated.js"),
	(typeof NATIVE_CALLS)[number]
>;

/** What the package calls, checked at load: a stale binary loads just as well. */
function isNativeSigil(value: unknown): value is NativeSigil {
	return hasFunctions(value, NATIVE_CALLS);
}

let native: NativeSigil | null = null;
let attempted = false;
/** Why the engine is not loaded, kept for the refusal that follows. */
let failure: { fix: string; cause?: unknown } = {
	fix: "the engine has not been loaded: sigil loads it on the first hash or verify.",
};

export async function loadNative(): Promise<void> {
	// Cache both success (`native !== null`) and failure (`attempted === true`).
	// Without the failure cache, every consumer call would re-run `require()`
	// for an absent binary, triggering OS-level lookup churn.
	if (native || attempted) return;
	attempted = true;
	// `attempted` keeps a second call O(1): a missing binary would otherwise
	// send the OS looking for it on every hash.
	const attempt = loadNativeBinary(isNativeSigil, NATIVE_CALLS, {
		packageName: PACKAGE_NAME,
	});
	if (attempt.loaded) {
		native = attempt.binary;
		return;
	}
	failure = {
		fix: remedy(attempt.suffix, attempt.platformPackage),
		cause: attempt.cause,
	};
}

/**
 * What to do about a missing engine, phrased for whoever has to fix it.
 *
 * An application installs the platform package; a checkout of sigil builds
 * the local binary. The load error itself is not in here: it names paths on
 * the host, so it travels as the refusal's `cause` instead of its message.
 */
function remedy(
	suffix: string | undefined,
	platformPackage: string | undefined,
): string {
	if (suffix === undefined) {
		return `no prebuilt binary for ${platform}-${arch}; sigil ships one for ${supportedTargets().join(", ")}.`;
	}
	if (platformPackage === undefined) {
		return `index.${suffix}.node failed to load. Rebuild it: cd packages/sigil && pnpm build:napi`;
	}
	return (
		`install ${platformPackage} at the exact version of ${PACKAGE_NAME}: it is the optional dependency that carries the ${suffix} binary, ` +
		"and an install that omits optional dependencies skips it. " +
		`In a checkout of sigil, build it instead: pnpm build:napi.${muslHint()}`
	);
}

/**
 * Why the engine is not loaded: the fix to print and the load error, if any.
 * Only meaningful while `isNativeLoaded()` is false.
 */
export function nativeUnavailable(): { fix: string; cause?: unknown } {
	return failure;
}

export function isNativeLoaded(): boolean {
	return native !== null;
}

// Every hash and verify below runs on the libuv thread pool and returns a
// Promise; `null` means the engine is not loaded.

export function argon2Hash(
	password: string,
	options?: Argon2NativeOptions,
): Promise<string> | null {
	return native?.argon2Hash(password, options) ?? null;
}

/**
 * The Argon2 cost parameters the engine applies when nothing is configured.
 * The driver states the same values; a test holds the two together.
 */
export function argon2Defaults(): {
	memoryKib: number;
	iterations: number;
	parallelism: number;
} | null {
	return native?.argon2Defaults() ?? null;
}

/**
 * The most work a stored hash may ask for at verify time, which the drivers
 * also apply to their configuration. A test holds the two together.
 */
export function costLimits(): {
	maxArgon2Work: number;
	maxBcryptCost: number;
	maxScryptWork: number;
} | null {
	return native?.costLimits() ?? null;
}

export function argon2Verify(
	password: string,
	hash: string,
	secret?: Buffer,
): Promise<boolean> | null {
	return native?.argon2Verify(password, hash, secret) ?? null;
}

export function bcryptHash(
	password: string,
	rounds?: number,
	version?: number,
	saltLength?: number,
): Promise<string> | null {
	return native?.bcryptHash(password, rounds, version, saltLength) ?? null;
}

export function bcryptVerify(
	password: string,
	hash: string,
): Promise<boolean> | null {
	return native?.bcryptVerify(password, hash) ?? null;
}

export function scryptHash(
	password: string,
	options?: ScryptNativeOptions,
): Promise<string> | null {
	return native?.scryptHash(password, options) ?? null;
}

export function scryptVerify(
	password: string,
	hash: string,
	maxMemory?: number,
): Promise<boolean> | null {
	return native?.scryptVerify(password, hash, maxMemory) ?? null;
}
