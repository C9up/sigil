/**
 * Hash — multi-driver password hashing service.
 *
 *   await hash.make('password')
 *   await hash.verify(hashed, 'password')   // verify(hash, plainValue) — AdonisJS order
 *
 * All real drivers are backed by Rust NAPI — no JS/TS fallback.
 * Drivers: argon2id, bcrypt, scrypt (+ a `fake` test driver via hash.fake()).
 *
 * Structure vs `@adonisjs/hash`: Adonis splits a `HashManager` (holds the list
 * of hashers) from a per-driver `Hash`. Sigil keeps a single public `Hash`
 * class as the manager (the container token consumers already resolve) and
 * exposes the per-driver facade as `Hasher` — Adonis's `Hash`. `use()` returns
 * a `Hasher`, so `isValidHash`/`assertEquals`/… are available off both.
 *
 * Config shape: Adonis embeds live factory closures in `config.list`. Sigil's
 * provider hydrates config from a serializable store, so the config is
 * `{ default, drivers: { <name>: { driver, ...options } } }` — a deliberate,
 * serializable divergence, not the `list` factory form.
 */

import { AssertionError } from "node:assert";
import {
	type Argon2NativeOptions,
	argon2Hash,
	argon2Verify,
	bcryptHash,
	bcryptVerify,
	isNativeLoaded,
	loadNative,
	type ScryptNativeOptions,
	scryptHash,
	scryptVerify,
} from "./native.js";

export interface HashDriver {
	/**
	 * Whether `value` looks like a hash this driver produced. Format check only
	 * — no cryptographic verification (AdonisJS `isValidHash`).
	 */
	isValidHash(value: string): boolean;
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

/** One driver's settings — its name plus whatever that driver reads. */
export interface HashDriverConfig {
	driver: string;
	[key: string]: unknown;
}

/**
 * Hash configuration.
 *
 * `list` is the AdonisJS spelling, `drivers` is sigil's own. Both are accepted
 * and mean the same thing, so a migrated `config/hash.ts` runs with its imports
 * rewritten and nothing else — which is the whole point.
 *
 * Named deviation: AdonisJS puts a live factory closure under each name.
 * Sigil's provider hydrates config from a SERIALIZABLE store, which cannot hold
 * a closure, so a driver is described by a plain object. The `drivers.*`
 * helpers produce exactly that, so the call site reads the same either way.
 */
export interface HashConfig {
	default: string;
	drivers?: Record<string, HashDriverConfig>;
	/** AdonisJS spelling of `drivers`. */
	list?: Record<string, HashDriverConfig>;
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
	#secret: Buffer | undefined;

	constructor(config: Record<string, unknown> = {}) {
		// Accept `{ memory | memoryKib, iterations, parallelism, secret }`.
		// Numeric coercion is strict — non-numbers are ignored so a config typo
		// never silently downgrades the params.
		const opts: Argon2NativeOptions = {};
		// AdonisJS names the memory option `memory` (KiB). Read it first, keeping
		// `memoryKib` as a backwards-compatible alias, so a config copied from an
		// Adonis app is not silently downgraded to native defaults.
		if (typeof config.memory === "number") opts.memoryKib = config.memory;
		else if (typeof config.memoryKib === "number")
			opts.memoryKib = config.memoryKib;
		if (typeof config.iterations === "number")
			opts.iterations = config.iterations;
		if (typeof config.parallelism === "number")
			opts.parallelism = config.parallelism;
		if (typeof config.secret === "string" && config.secret.length > 0) {
			this.#secret = Buffer.from(config.secret, "utf8");
			opts.secret = this.#secret;
		}
		// `variant`, `hashLength` and `saltSize` were declared on Argon2Options
		// and never read: an app asking for argon2i silently got argon2id, and
		// the two lengths silently stayed at the defaults.
		if (config.variant !== undefined) {
			// Dropping an unrecognised value would be the very bug this fixes:
			// the caller would get argon2id and never learn its config was
			// ignored.
			if (
				config.variant !== "d" &&
				config.variant !== "i" &&
				config.variant !== "id"
			) {
				throw new Error(
					`Unknown Argon2 variant "${String(config.variant)}" — expected "d", "i", or "id".`,
				);
			}
			opts.variant = config.variant;
		}
		if (typeof config.hashLength === "number")
			opts.hashLength = config.hashLength;
		// AdonisJS names it `saltSize`; the native layer calls it saltLength.
		if (typeof config.saltSize === "number") opts.saltLength = config.saltSize;
		this.#options = Object.keys(opts).length > 0 ? opts : undefined;
	}

	isValidHash(hash: string): boolean {
		return /^\$argon2(id|i|d)\$/.test(hash);
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
		return requireNative(argon2Verify(value, hash, this.#secret), "argon2");
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
	#version: number | undefined;
	#saltSize: number | undefined;
	constructor(config: Record<string, unknown> = {}) {
		this.#rounds = typeof config.rounds === "number" ? config.rounds : 12;
		// `version` and `saltSize` were declared on BcryptOptions and never read.
		// AdonisJS spells the version as a char code (97 = "2a", 98 = "2b").
		this.#version =
			typeof config.version === "number" ? config.version : undefined;
		this.#saltSize =
			typeof config.saltSize === "number" ? config.saltSize : undefined;
	}

	isValidHash(hash: string): boolean {
		return /^\$2[aby]\$\d{2}\$/.test(hash);
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
		return requireNative(
			bcryptHash(value, this.#rounds, this.#version, this.#saltSize),
			"bcrypt",
		);
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
	#options: ScryptNativeOptions;
	#cost: number;
	#blockSize: number;
	#parallelization: number;
	#maxMemory: number;

	constructor(config: Record<string, unknown> = {}) {
		// AdonisJS scrypt config names: cost (N), blockSize (r), parallelization
		// (p), keyLength, saltSize, maxMemory. Defaults match Adonis.
		this.#cost = typeof config.cost === "number" ? config.cost : 16384;
		this.#blockSize =
			typeof config.blockSize === "number" ? config.blockSize : 8;
		this.#parallelization =
			typeof config.parallelization === "number" ? config.parallelization : 1;
		this.#maxMemory =
			typeof config.maxMemory === "number"
				? config.maxMemory
				: 32 * 1024 * 1024;
		const opts: ScryptNativeOptions = {
			cost: this.#cost,
			blockSize: this.#blockSize,
			parallelization: this.#parallelization,
		};
		if (typeof config.keyLength === "number") opts.keyLength = config.keyLength;
		// Accept the Adonis name `saltSize`, keeping `saltLength` as an alias.
		if (typeof config.saltSize === "number") opts.saltLength = config.saltSize;
		else if (typeof config.saltLength === "number")
			opts.saltLength = config.saltLength;
		this.#options = opts;
	}

	isValidHash(hash: string): boolean {
		return /^\$scrypt\$n=\d+,r=\d+,p=\d+\$/.test(hash);
	}

	async make(value: string): Promise<string> {
		if (Buffer.byteLength(value, "utf8") > MAX_PASSWORD_BYTES) {
			throw new Error(
				`Password exceeds maximum length of ${MAX_PASSWORD_BYTES} bytes`,
			);
		}
		// AdonisJS-parity memory guard: the working set is 128 * N * r bytes;
		// reject configs whose set would meet or exceed maxMemory. Fail closed
		// rather than let the native derivation allocate past the bound.
		if (128 * this.#cost * this.#blockSize >= this.#maxMemory) {
			throw new Error(
				`Scrypt working set (128 * cost * blockSize) exceeds maxMemory of ${this.#maxMemory} bytes; raise maxMemory or lower cost/blockSize`,
			);
		}
		await ensureNative();
		return requireNative(scryptHash(value, this.#options), "scrypt");
	}

	async verify(hash: string, value: string): Promise<boolean> {
		await ensureNative();
		return requireNative(scryptVerify(value, hash), "scrypt");
	}

	needsReHash(hash: string): boolean {
		// The Adonis-parity PHC form encodes n/r/p — compare them to the config.
		const m = hash.match(/^\$scrypt\$n=(\d+),r=(\d+),p=(\d+)\$/);
		if (!m) return true; // not a scrypt hash (or the old format) → re-hash
		if (Number(m[1]) !== this.#cost) return true;
		if (Number(m[2]) !== this.#blockSize) return true;
		if (Number(m[3]) !== this.#parallelization) return true;
		return false;
	}
}

/**
 * Fake driver for tests (AdonisJS `Fake`): no hashing. `make` is identity,
 * `verify` is plain string equality, `needsReHash` is always false. Enabled via
 * `hash.fake()`.
 */
class FakeDriver implements HashDriver {
	isValidHash(_hash: string): boolean {
		return true;
	}
	async make(value: string): Promise<string> {
		return value;
	}
	async verify(hash: string, value: string): Promise<boolean> {
		return hash === value;
	}
	needsReHash(_hash: string): boolean {
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

/**
 * Per-driver facade — the AdonisJS `Hash` equivalent. Wraps a single
 * `HashDriver` and adds the japa-style `assertEquals`/`assertNotEquals`
 * helpers. Returned by `Hash.use()`.
 */
export class Hasher implements HashDriver {
	#driver: HashDriver;
	constructor(driver: HashDriver) {
		this.#driver = driver;
	}

	isValidHash(value: string): boolean {
		return this.#driver.isValidHash(value);
	}
	make(value: string): Promise<string> {
		return this.#driver.make(value);
	}
	verify(hash: string, value: string): Promise<boolean> {
		return this.#driver.verify(hash, value);
	}
	needsReHash(hash: string): boolean {
		return this.#driver.needsReHash(hash);
	}

	/** Assert `value` passes verification against `hash`; throws otherwise. */
	async assertEquals(hash: string, value: string): Promise<void> {
		const ok = await this.#driver.verify(hash, value);
		if (!ok) {
			throw new AssertionError({
				// Never interpolate `value` — it is the plaintext secret; a leaked
				// AssertionError easily lands in CI / app logs.
				message: "Expected the value to pass hash verification",
				expected: true,
				actual: false,
				operator: "strictEqual",
				stackStartFn: this.assertEquals,
			});
		}
	}

	/** Assert `value` fails verification against `hash`; throws otherwise. */
	async assertNotEquals(hash: string, value: string): Promise<void> {
		const ok = await this.#driver.verify(hash, value);
		if (ok) {
			throw new AssertionError({
				// Never interpolate `value` — it is the plaintext secret.
				message: "Expected the value to fail hash verification",
				expected: false,
				actual: true,
				operator: "strictEqual",
				stackStartFn: this.assertNotEquals,
			});
		}
	}
}

export class Hash implements HashDriver {
	#drivers: Map<string, HashDriver> = new Map();
	#hashers: Map<string, Hasher> = new Map();
	#defaultDriver: string;
	#fakeHasher: Hasher | undefined;

	constructor(config: HashConfig) {
		this.#defaultDriver = config.default;
		this.config = config;
		// `list` (AdonisJS) and `drivers` (sigil) are the same map under two
		// names; a config that sets both gets both, last name wins per key.
		const declared = { ...config.drivers, ...config.list };
		for (const [name, driverConfig] of Object.entries(declared)) {
			const factory = driverFactories[driverConfig.driver];
			if (factory) this.#drivers.set(name, factory(driverConfig));
		}
	}

	/** The configuration this manager was built from (AdonisJS `HashManager.config`). */
	readonly config: HashConfig;

	async make(value: string): Promise<string> {
		return this.use().make(value);
	}
	async verify(hash: string, value: string): Promise<boolean> {
		return this.use().verify(hash, value);
	}

	/** Format check for the default driver (AdonisJS `isValidHash`). */
	isValidHash(hash: string): boolean {
		return this.use().isValidHash(hash);
	}

	/** Whether `hash` should be re-hashed under the default driver's current params. */
	needsReHash(hash: string): boolean {
		return this.use().needsReHash(hash);
	}

	/** Assert `value` passes verification against `hash` under the default driver. */
	assertEquals(hash: string, value: string): Promise<void> {
		return this.use().assertEquals(hash, value);
	}

	/** Assert `value` fails verification against `hash` under the default driver. */
	assertNotEquals(hash: string, value: string): Promise<void> {
		return this.use().assertNotEquals(hash, value);
	}

	use(name?: string): Hasher {
		// When faked, every hasher (named or default) resolves to the fake — the
		// AdonisJS `fake()` semantics.
		if (this.#fakeHasher) return this.#fakeHasher;
		const n = name ?? this.#defaultDriver;
		const cached = this.#hashers.get(n);
		if (cached) return cached;
		const driver = this.#drivers.get(n);
		if (!driver) throw new Error(`Hash driver '${n}' not configured`);
		const hasher = new Hasher(driver);
		this.#hashers.set(n, hasher);
		return hasher;
	}

	/**
	 * Swap every driver for the no-op fake driver (tests). Returns a disposable
	 * so `using guard = hash.fake()` auto-restores at scope exit (AdonisJS
	 * `fake()`); call `restore()` manually otherwise.
	 */
	fake(): { [Symbol.dispose](): void } {
		if (!this.#fakeHasher) this.#fakeHasher = new Hasher(new FakeDriver());
		return { [Symbol.dispose]: () => this.restore() };
	}

	/** Disable fake mode, restoring the real drivers. */
	restore(): void {
		this.#fakeHasher = undefined;
	}
}
