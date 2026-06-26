/**
 * Hash — multi-driver password hashing service.
 *
 *   await hash.make('password')
 *   await hash.verify(hashed, 'password')   // verify(hash, plainValue) — AdonisJS order
 *
 * All drivers backed by Rust NAPI — no JS/TS fallback.
 * Drivers: argon2id, bcrypt, scrypt.
 */

import {
	type Argon2NativeOptions,
	argon2Hash,
	argon2Verify,
	bcryptHash,
	bcryptVerify,
	isNativeLoaded,
	loadNative,
	scryptHash,
	scryptVerify,
} from "./native.js";

export interface HashDriver {
	make(value: string): Promise<string>;
	/** Verify `value` against a stored `hash`. Arg order mirrors AdonisJS: (hash, value). */
	verify(hash: string, value: string): Promise<boolean>;
	/**
	 * Whether `hash` should be re-hashed because it was produced by a different
	 * algorithm or with different parameters than this driver's current config
	 * (AdonisJS `hash.needsReHash`). Call after a successful verify to upgrade
	 * stored hashes on login. Parses the hash's embedded params — no native call.
	 */
	needsReHash(hash: string): boolean;
}

export interface HashConfig {
	default: string;
	drivers: Record<string, { driver: string; [key: string]: unknown }>;
}

const MAX_PASSWORD_BYTES = 1024;
// Bcrypt silently truncates inputs past 72 bytes — two distinct long
// passwords sharing a 72-byte prefix would hash identically. Reject
// rather than let the truncation collision surface as a "feature".
const BCRYPT_MAX_BYTES = 72;

async function ensureNative(): Promise<void> {
	if (isNativeLoaded()) return;
	await loadNative();
}

export class E_SIGIL_NAPI_REQUIRED extends Error {
	readonly code = "SIGIL_NAPI_REQUIRED" as const;
	constructor(driver: string, options?: ErrorOptions) {
		super(
			`[SIGIL_NAPI_REQUIRED] The ${driver} Rust engine is required but not loaded.\n` +
				`  Fix: cd packages/sigil && pnpm build:napi`,
			options,
		);
		this.name = "E_SIGIL_NAPI_REQUIRED";
	}
}

function requireNative<T>(result: T | null, driver: string): T {
	if (result === null) throw new E_SIGIL_NAPI_REQUIRED(driver);
	return result;
}

class Argon2Driver implements HashDriver {
	#options: Argon2NativeOptions | undefined;

	constructor(config: Record<string, unknown> = {}) {
		// Accept `{ memoryKib, iterations, parallelism }`. Numeric coercion is
		// strict — non-numbers are ignored so a config typo never silently
		// downgrades the params.
		const opts: Argon2NativeOptions = {};
		if (typeof config.memoryKib === "number") opts.memoryKib = config.memoryKib;
		if (typeof config.iterations === "number")
			opts.iterations = config.iterations;
		if (typeof config.parallelism === "number")
			opts.parallelism = config.parallelism;
		this.#options = Object.keys(opts).length > 0 ? opts : undefined;
	}

	async make(value: string): Promise<string> {
		if (Buffer.byteLength(value, "utf8") > MAX_PASSWORD_BYTES) {
			throw new Error(
				`Password exceeds maximum length of ${MAX_PASSWORD_BYTES} bytes`,
			);
		}
		await ensureNative();
		return requireNative(argon2Hash(value, this.#options), "argon2");
	}

	async verify(hash: string, value: string): Promise<boolean> {
		await ensureNative();
		return requireNative(argon2Verify(value, hash), "argon2");
	}

	needsReHash(hash: string): boolean {
		if (!hash.startsWith("$argon2")) return true; // different algorithm
		const o = this.#options;
		if (!o) return false; // native defaults — no configured params to drift from
		const m = hash.match(/m=(\d+),t=(\d+),p=(\d+)/);
		if (!m) return true;
		if (o.memoryKib !== undefined && Number(m[1]) !== o.memoryKib) return true;
		if (o.iterations !== undefined && Number(m[2]) !== o.iterations)
			return true;
		if (o.parallelism !== undefined && Number(m[3]) !== o.parallelism)
			return true;
		return false;
	}
}

class BcryptDriver implements HashDriver {
	#rounds: number;
	constructor(config: Record<string, unknown> = {}) {
		this.#rounds = typeof config.rounds === "number" ? config.rounds : 12;
	}

	async make(value: string): Promise<string> {
		const bytes = Buffer.byteLength(value, "utf8");
		if (bytes > MAX_PASSWORD_BYTES) {
			throw new Error(
				`Password exceeds maximum length of ${MAX_PASSWORD_BYTES} bytes`,
			);
		}
		if (bytes > BCRYPT_MAX_BYTES) {
			throw new Error(
				`Bcrypt cannot hash inputs longer than ${BCRYPT_MAX_BYTES} bytes (got ${bytes}); use argon2id for long passphrases`,
			);
		}
		await ensureNative();
		return requireNative(bcryptHash(value, this.#rounds), "bcrypt");
	}

	async verify(hash: string, value: string): Promise<boolean> {
		await ensureNative();
		return requireNative(bcryptVerify(value, hash), "bcrypt");
	}

	needsReHash(hash: string): boolean {
		const m = hash.match(/^\$2[aby]\$(\d{2})\$/);
		if (!m) return true; // not a bcrypt hash → re-hash
		return Number(m[1]) !== this.#rounds;
	}
}

class ScryptDriver implements HashDriver {
	#keyLength: number;
	#saltLength: number;
	constructor(config: Record<string, unknown> = {}) {
		this.#keyLength =
			typeof config.keyLength === "number" ? config.keyLength : 64;
		this.#saltLength =
			typeof config.saltLength === "number" ? config.saltLength : 32;
	}

	async make(value: string): Promise<string> {
		if (Buffer.byteLength(value, "utf8") > MAX_PASSWORD_BYTES) {
			throw new Error(
				`Password exceeds maximum length of ${MAX_PASSWORD_BYTES} bytes`,
			);
		}
		await ensureNative();
		return requireNative(
			scryptHash(value, this.#saltLength, this.#keyLength),
			"scrypt",
		);
	}

	async verify(hash: string, value: string): Promise<boolean> {
		await ensureNative();
		return requireNative(scryptVerify(value, hash, this.#keyLength), "scrypt");
	}

	needsReHash(_hash: string): boolean {
		// scrypt hashes don't carry a self-describing, portable param header we can
		// reliably introspect here, so we conservatively never force a re-hash.
		return false;
	}
}

const driverFactories: Record<
	string,
	(config: Record<string, unknown>) => HashDriver
> = {
	argon2: (config) => new Argon2Driver(config),
	bcrypt: (config) => new BcryptDriver(config),
	scrypt: (config) => new ScryptDriver(config),
};

export class Hash {
	#drivers: Map<string, HashDriver> = new Map();
	#defaultDriver: string;

	constructor(config: HashConfig) {
		this.#defaultDriver = config.default;
		for (const [name, driverConfig] of Object.entries(config.drivers)) {
			const factory = driverFactories[driverConfig.driver];
			if (factory) this.#drivers.set(name, factory(driverConfig));
		}
	}

	async make(value: string): Promise<string> {
		return this.use().make(value);
	}
	async verify(hash: string, value: string): Promise<boolean> {
		return this.use().verify(hash, value);
	}

	/** Whether `hash` should be re-hashed under the default driver's current params. */
	needsReHash(hash: string): boolean {
		return this.use().needsReHash(hash);
	}

	use(name?: string): HashDriver {
		const n = name ?? this.#defaultDriver;
		const driver = this.#drivers.get(n);
		if (!driver) throw new Error(`Hash driver '${n}' not configured`);
		return driver;
	}
}
