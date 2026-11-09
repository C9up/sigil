/**
 * Driver option bounds, and the validators that apply them when a driver is
 * constructed.
 *
 * Checked at construction so a bad `config/hash.ts` fails at boot rather than
 * at the first sign-up in production, and so a value of the wrong type — a
 * `rounds: '12'` read from an environment variable — throws instead of being
 * quietly replaced by the default.
 *
 * The cost caps mirror the engine's (`MAX_ARGON2_WORK`, `MAX_BCRYPT_COST`,
 * `MAX_SCRYPT_WORK` in crates/sigil-engine). The engine refuses, at verify, a
 * stored hash costing more than they allow, so a configuration above them
 * would write hashes that never verify again; it is refused here instead. A
 * test holds these numbers to the engine's.
 */

export const MAX_UINT32 = 2 ** 32 - 1;
export const MAX_UINT24 = 2 ** 24 - 1;

/** Argon2 cost when none is configured: argon2id, 64 MiB, 3 passes, 4 lanes. */
export const ARGON2_DEFAULTS: Readonly<{
	memory: number;
	iterations: number;
	parallelism: number;
}> = Object.freeze({
	memory: 65536,
	iterations: 3,
	parallelism: 4,
});

/** Largest Argon2 `memory (KiB) * iterations`. */
export const MAX_ARGON2_WORK = 2 ** 20;
/** Largest bcrypt cost. */
export const MAX_BCRYPT_COST = 16;
/** Smallest bcrypt cost sigil hashes with (OWASP minimum). */
export const MIN_BCRYPT_COST = 10;
/** Largest scrypt `cost * blockSize * parallelization`. */
export const MAX_SCRYPT_WORK = 2 ** 22;
/** Scrypt `maxMemory` when none is configured. */
export const SCRYPT_DEFAULT_MAX_MEMORY = 32 * 1024 * 1024;

/**
 * Bytes a scrypt derivation allocates, `128 * r * (N + p + 2)` — the figure
 * Node's `crypto.scrypt` compares to `maxmem`, and the engine to `maxMemory`.
 */
export function scryptMemory(
	cost: number,
	blockSize: number,
	p: number,
): number {
	return 128 * blockSize * (cost + p + 2);
}

/** `value` as an integer within `[min, max]`, or a TypeError naming `label`. */
export function checkInteger(
	label: string,
	value: unknown,
	[min, max]: readonly [number, number],
): number {
	if (typeof value !== "number" || !Number.isInteger(value)) {
		throw new TypeError(`The "${label}" option must be an integer`);
	}
	if (value < min || value > max) {
		throw new TypeError(
			`The "${label}" option must be in the range (${min} <= ${label} <= ${max})`,
		);
	}
	return value;
}

/** The integer option `key`, validated, or `undefined` when it is not set. */
export function integerOption(
	config: Record<string, unknown>,
	key: string,
	range: readonly [number, number],
): number | undefined {
	const value = config[key];
	return value === undefined ? undefined : checkInteger(key, value, range);
}

/** `value` if it is one of `allowed`, or a TypeError naming `label`. */
export function checkEnum<T>(
	label: string,
	value: unknown,
	allowed: readonly T[],
): T {
	const match = allowed.find((candidate) => candidate === value);
	if (match === undefined) {
		throw new TypeError(
			`The "${label}" option must be one of: ${allowed.join(",")}`,
		);
	}
	return match;
}
