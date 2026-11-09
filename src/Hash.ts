/**
 * Hash — multi-driver password hashing service.
 *
 *   await hash.make('password')
 *   await hash.verify(hashed, 'password')   // verify(hash, plainValue) — AdonisJS order
 *
 * All real drivers are backed by Rust NAPI — no JS/TS fallback. The key
 * derivation runs on the libuv thread pool, never on the event loop.
 * Drivers: argon2id, bcrypt, scrypt (+ a `fake` test driver via hash.fake()).
 *
 * Structure vs `@adonisjs/hash`: Adonis splits a `HashManager` (holds the list
 * of hashers) from a per-driver `Hash`. Sigil keeps a single public `Hash`
 * class as the manager (the container token consumers already resolve) and
 * exposes the per-driver facade as `Hasher` — Adonis's `Hash`. `use()` returns
 * a `Hasher`, so `isValidHash`/`assertEquals`/… are available off both.
 *
 * Config shape: `{ default, list: { <name>: { driver, ...options } } }`. The
 * key is `list`, as it is upstream; what differs is the VALUE — upstream puts a
 * live factory closure under each name, and sigil's provider hydrates its
 * config from a serializable store, which cannot hold one. The `drivers.*`
 * helpers produce that plain object, so the call site reads the same.
 */

import { AssertionError } from "node:assert";
import {
	ARGON2_DEFAULTS,
	checkEnum,
	checkInteger,
	integerOption,
	MAX_ARGON2_WORK,
	MAX_BCRYPT_COST,
	MAX_SCRYPT_WORK,
	MAX_UINT24,
	MAX_UINT32,
	MIN_BCRYPT_COST,
	SCRYPT_DEFAULT_MAX_MEMORY,
	scryptMemory,
} from "./limits.js";
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
 * `list` is the key; `drivers` is sigil's older spelling. Both are accepted
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
	/** The hashers this application can use, by name. */
	list?: Record<string, HashDriverConfig>;
	/** Sigil's older spelling of {@link list}. Both are accepted; `list` wins. */
	drivers?: Record<string, HashDriverConfig>;
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

const ARGON2_VARIANTS: readonly ("d" | "i" | "id")[] = ["d", "i", "id"];
const BCRYPT_VERSIONS: readonly number[] = [97, 98, 121];

/**
 * The Argon2 `secret`: a string, or a wrapper that releases one — the
 * `Secret` an environment schema hands back for `APP_KEY` — so the upstream
 * call site `drivers.argon2({ secret: env.get('APP_KEY') })` works unchanged.
 */
function releaseSecret(secret: unknown): string {
	if (typeof secret === "string") return secret;
	if (typeof secret === "object" && secret !== null && "release" in secret) {
		const release: unknown = secret.release;
		if (typeof release === "function") {
			const released: unknown = release.call(secret);
			if (typeof released === "string") return released;
		}
	}
	throw new TypeError(
		`The "secret" option must be a string or a Secret wrapping one`,
	);
}

class Argon2Driver implements HashDriver {
	#options: Readonly<Argon2NativeOptions>;
	#variant: "d" | "i" | "id";
	#memory: number;
	#iterations: number;
	#parallelism: number;
	#secret: Buffer | undefined;

	constructor(config: Record<string, unknown> = {}) {
		// Every option is validated here, as upstream does, so a bad config
		// fails at boot. Same ranges, except where the engine is narrower
		// (salt and output lengths: the PHC string caps both) or sigil is
		// stricter on purpose (the work cap, see ./limits.ts).
		this.#variant =
			config.variant === undefined
				? "id"
				: checkEnum("variant", config.variant, ARGON2_VARIANTS);
		this.#parallelism =
			integerOption(config, "parallelism", [1, MAX_UINT24]) ??
			ARGON2_DEFAULTS.parallelism;
		this.#iterations =
			integerOption(config, "iterations", [2, MAX_UINT32]) ??
			ARGON2_DEFAULTS.iterations;
		// AdonisJS names the memory option `memory` (KiB); `memoryKib` is
		// sigil's older alias.
		const memoryKey = config.memory !== undefined ? "memory" : "memoryKib";
		this.#memory = checkInteger(
			memoryKey,
			config[memoryKey] ?? ARGON2_DEFAULTS.memory,
			[8 * this.#parallelism, MAX_UINT32],
		);
		if (this.#memory * this.#iterations > MAX_ARGON2_WORK) {
			throw new TypeError(
				`The "memory" * "iterations" options must not exceed ${MAX_ARGON2_WORK} (got ${this.#memory} * ${this.#iterations}): verify refuses a hash costing more`,
			);
		}
		const opts: Argon2NativeOptions = {
			memoryKib: this.#memory,
			iterations: this.#iterations,
			parallelism: this.#parallelism,
			variant: this.#variant,
		};
		const hashLength = integerOption(config, "hashLength", [10, 64]);
		if (hashLength !== undefined) opts.hashLength = hashLength;
		// AdonisJS names it `saltSize`; the native layer calls it saltLength.
		const saltSize = integerOption(config, "saltSize", [8, 48]);
		if (saltSize !== undefined) opts.saltLength = saltSize;
		if (config.secret !== undefined) {
			const secret = releaseSecret(config.secret);
			if (secret.length > 0) {
				this.#secret = Buffer.from(secret, "utf8");
				opts.secret = this.#secret;
			}
		}
		this.#options = Object.freeze(opts);
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
		return await requireNative(argon2Hash(value, this.#options), "argon2");
	}

	async verify(hash: string, value: string): Promise<boolean> {
		await ensureNative();
		return await requireNative(
			argon2Verify(value, hash, this.#secret),
			"argon2",
		);
	}

	needsReHash(hash: string): boolean {
		const m = hash.match(
			/^\$argon2(id|i|d)\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$/,
		);
		// Another algorithm, or an argon2 string without its version: re-hash.
		if (!m) return true;
		// argon2i and argon2d are not what argon2id would produce, and the
		// difference is a security property rather than a formatting one.
		if (m[1] !== this.#variant) return true;
		// sigil writes version 19 (0x13) only.
		if (Number(m[2]) !== 19) return true;
		// Compared against the resolved configuration, defaults included: an
		// application that configures nothing still upgrades a hash minted
		// with weak parameters.
		if (Number(m[3]) !== this.#memory) return true;
		if (Number(m[4]) !== this.#iterations) return true;
		if (Number(m[5]) !== this.#parallelism) return true;
		return false;
	}
}

/**
 * The bcrypt hash forms verify accepts:
 *
 * - MCF, `$2a$` / `$2b$` / `$2y$` + two-digit cost — what sigil writes;
 * - PHC, `$bcrypt$[v=97|98$]r=<cost>$<b64 salt>$<b64 digest>` — what
 *   `@adonisjs/hash` writes.
 */
const BCRYPT_MCF = /^\$2(?<letter>[aby])\$(?<cost>\d{2})\$[./A-Za-z0-9]{53}$/;
const BCRYPT_PHC =
	/^\$bcrypt\$(?:v=(?:97|98)\$)?r=(?<cost>\d{1,2})\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]+$/;
/** The version sigil writes when none is configured: 98, `$2b$`. */
const BCRYPT_DEFAULT_VERSION = 98;

class BcryptDriver implements HashDriver {
	#rounds: number;
	#version: number | undefined;
	#saltSize: number | undefined;
	constructor(config: Record<string, unknown> = {}) {
		// Validated here so a bad config fails at boot. The range is narrower
		// than upstream's 4..31 on both ends, deliberately: 10 is the OWASP
		// floor, and MAX_BCRYPT_COST is what verify accepts (./limits.ts).
		this.#rounds =
			integerOption(config, "rounds", [MIN_BCRYPT_COST, MAX_BCRYPT_COST]) ?? 12;
		// AdonisJS spells the version as a char code (97 = "2a", 98 = "2b").
		// 121 ("2y") is the same algorithm and verify reads it; 120 ("2x"), the
		// crypt_blowfish-bug marker, is refused — nothing verifies it.
		this.#version =
			config.version === undefined
				? undefined
				: checkEnum("version", config.version, BCRYPT_VERSIONS);
		// The algorithm fixes the salt at 16 bytes; anything else would write a
		// hash no bcrypt implementation can read.
		this.#saltSize = integerOption(config, "saltSize", [16, 16]);
	}

	isValidHash(hash: string): boolean {
		const m = hash.match(BCRYPT_MCF) ?? hash.match(BCRYPT_PHC);
		if (!m) return false;
		const cost = Number(m.groups?.cost);
		return cost >= 4 && cost <= 31;
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
		return await requireNative(
			bcryptHash(value, this.#rounds, this.#version, this.#saltSize),
			"bcrypt",
		);
	}

	async verify(hash: string, value: string): Promise<boolean> {
		// Both of these are answers, not failures. A stored hash bcrypt did not
		// produce belongs to an application that changed algorithms — the case
		// `needsReHash` below exists to handle — and a value past the 72-byte
		// limit could never have been hashed by `make`, so no stored hash can
		// match it. The native call reports either as an error, which turned an
		// ordinary failed login into a 500 on a route anyone can reach.
		// argon2 and scrypt both return false here.
		if (!this.isValidHash(hash)) return false;
		if (Buffer.byteLength(value, "utf8") > BCRYPT_MAX_BYTES) return false;
		await ensureNative();
		return await requireNative(bcryptVerify(value, hash), "bcrypt");
	}

	/**
	 * Named deviation: sigil writes bcrypt in the MCF form (`$2b$12$…`), the
	 * one every bcrypt implementation reads — upstream writes a PHC string. A
	 * PHC hash stored by upstream therefore verifies, then reports that it
	 * needs a re-hash, so it migrates to MCF on the user's next login.
	 *
	 * Otherwise the rule is upstream's: a hash needs a re-hash when its version
	 * or its cost differs from the configuration. The version is the prefix
	 * letter, whose char code is the configured number (`$2a$` is 97).
	 */
	needsReHash(hash: string): boolean {
		const m = hash.match(BCRYPT_MCF);
		if (!m) return true; // PHC, or not a bcrypt hash → re-hash
		const version = this.#version ?? BCRYPT_DEFAULT_VERSION;
		if (m.groups?.letter !== String.fromCharCode(version)) return true;
		return Number(m.groups?.cost) !== this.#rounds;
	}
}

class ScryptDriver implements HashDriver {
	#options: Readonly<ScryptNativeOptions>;
	#cost: number;
	#blockSize: number;
	#parallelization: number;
	#maxMemory: number;

	constructor(config: Record<string, unknown> = {}) {
		// AdonisJS scrypt config names and ranges: cost (N), blockSize (r),
		// parallelization (p), keyLength, saltSize, maxMemory. Validated here so
		// a bad config fails at boot.
		this.#blockSize = integerOption(config, "blockSize", [1, MAX_UINT32]) ?? 8;
		this.#cost = integerOption(config, "cost", [2, MAX_UINT32]) ?? 16384;
		// Node's crypto.scrypt refuses any other N too, but only at hash time.
		if (!Number.isInteger(Math.log2(this.#cost))) {
			throw new TypeError(`The "cost" option must be a power of two`);
		}
		this.#parallelization =
			integerOption(config, "parallelization", [
				1,
				Math.floor((MAX_UINT32 * 32) / (128 * this.#blockSize)),
			]) ?? 1;
		const work = this.#cost * this.#blockSize * this.#parallelization;
		if (work > MAX_SCRYPT_WORK) {
			throw new TypeError(
				`The "cost" * "blockSize" * "parallelization" options must not exceed ${MAX_SCRYPT_WORK} (got ${work}): verify refuses a hash costing more`,
			);
		}
		// The working set is `128 * r * (N + p + 2)` bytes; upstream accepts a
		// smaller maxMemory here and only fails at the first hash.
		this.#maxMemory = checkInteger(
			"maxMemory",
			config.maxMemory ?? SCRYPT_DEFAULT_MAX_MEMORY,
			[
				scryptMemory(this.#cost, this.#blockSize, this.#parallelization),
				MAX_UINT32,
			],
		);
		const opts: ScryptNativeOptions = {
			cost: this.#cost,
			blockSize: this.#blockSize,
			parallelization: this.#parallelization,
			maxMemory: this.#maxMemory,
		};
		const keyLength = integerOption(config, "keyLength", [64, 128]);
		if (keyLength !== undefined) opts.keyLength = keyLength;
		// Accept the Adonis name `saltSize`, keeping `saltLength` as an alias.
		const saltKey = config.saltSize !== undefined ? "saltSize" : "saltLength";
		const saltSize = integerOption(config, saltKey, [8, 1024]);
		if (saltSize !== undefined) opts.saltLength = saltSize;
		this.#options = Object.freeze(opts);
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
		await ensureNative();
		return await requireNative(scryptHash(value, this.#options), "scrypt");
	}

	async verify(hash: string, value: string): Promise<boolean> {
		await ensureNative();
		// maxMemory bounds verify as well as make: a stored hash whose working
		// set exceeds it is refused, not derived.
		return await requireNative(
			scryptVerify(value, hash, this.#maxMemory),
			"scrypt",
		);
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
 * `HashDriver` and adds the helix-style `assertEquals`/`assertNotEquals`
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
