// GENERATED FROM THE RUST — do not edit.
//
// Produced by scripts/generate-napi-types.mjs from napi-derive's type-def
// output. Editing this file by hand puts it back where it started: a
// description that can disagree with the code it describes.

export interface Argon2Options {
	/** Memory cost in KiB. ≥ 8 × parallelism. */
	memoryKib?: number;
	/** Time cost (iterations). ≥ 2. */
	iterations?: number;
	/** Parallelism (lanes). ≥ 1. */
	parallelism?: number;
	/** Secret pepper. Not stored in the hash; required identically at verify. */
	secret?: Buffer;
	/** Variant: "d", "i" or "id" (Adonis `variant`). Default "id". */
	variant?: string;
	/** Output length in bytes (Adonis `hashLength`). Default 32. */
	hashLength?: number;
	/** Salt size in bytes (Adonis `saltSize`). Default 16. */
	saltLength?: number;
}

/** The Argon2 cost parameters used when the application configures none. */

export interface Argon2Defaults {
	memoryKib: number;
	iterations: number;
	parallelism: number;
}

/**
 * The most work a stored hash may ask for at verify time, per algorithm —
 * and so the most a configuration may produce.
 */

export interface CostLimits {
	/** Argon2 `memory (KiB) * iterations`. */
	maxArgon2Work: number;
	/** Bcrypt cost (log2 of the rounds). */
	maxBcryptCost: number;
	/** Scrypt `cost * blockSize * parallelization`. */
	maxScryptWork: number;
}

export interface ScryptOptions {
	/** CPU/memory cost (N). Power of two > 1. Default 16384. */
	cost?: number;
	/** Block size (r). Default 8. */
	blockSize?: number;
	/** Parallelization (p). Default 1. */
	parallelization?: number;
	/** Derived key length in bytes, 64 to 128. Default 64. */
	keyLength?: number;
	/** Salt size in bytes. Default 16. */
	saltLength?: number;
	/** Largest working set in bytes, `128 * r * (N + p + 2)`. Default 32 MiB. */
	maxMemory?: number;
}

export declare function argon2Defaults(): Argon2Defaults;

export declare function costLimits(): CostLimits;

export declare function argon2Hash(
	password: string,
	options?: Argon2Options | undefined | null,
): Promise<string>;

export declare function argon2Verify(
	password: string,
	hash: string,
	secret?: Buffer | undefined | null,
): Promise<boolean>;

export declare function bcryptHash(
	password: string,
	rounds?: number | undefined | null,
	version?: number | undefined | null,
	saltLength?: number | undefined | null,
): Promise<string>;

export declare function bcryptVerify(
	password: string,
	hash: string,
): Promise<boolean>;

export declare function scryptHash(
	password: string,
	options?: ScryptOptions | undefined | null,
): Promise<string>;

/**
 * `max_memory` is the configured `maxMemory`: a stored hash whose working set
 * exceeds it is refused before deriving. Default 32 MiB.
 */

export declare function scryptVerify(
	password: string,
	hash: string,
	maxMemory?: number | undefined | null,
): Promise<boolean>;
