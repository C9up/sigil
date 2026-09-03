// GENERATED FROM THE RUST — do not edit.
//
// Produced by scripts/generate-napi-types.mjs from napi-derive's type-def
// output. Editing this file by hand puts it back where it started: a
// description that can disagree with the code it describes.

export interface Argon2Options {
	/** Memory cost in KiB. ≥ 8. */
	memoryKib?: number;
	/** Time cost (iterations). ≥ 1. */
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

/**
 * The Argon2 cost parameters used when the application configures none.
 * `needsReHash` compares a stored hash against these, so they must come from
 * the engine rather than be restated on the JavaScript side.
 */

export interface Argon2Defaults {
	memoryKib: number;
	iterations: number;
	parallelism: number;
}

export interface ScryptOptions {
	/** CPU/memory cost (N). Power of two > 1. Default 16384. */
	cost?: number;
	/** Block size (r). Default 8. */
	blockSize?: number;
	/** Parallelization (p). Default 1. */
	parallelization?: number;
	/** Derived key length in bytes. Default 64. */
	keyLength?: number;
	/** Salt size in bytes. Default 16. */
	saltLength?: number;
}

export declare function argon2Defaults(): Argon2Defaults;

export declare function argon2Hash(
	password: string,
	options?: Argon2Options | undefined | null,
): string;

export declare function argon2Verify(
	password: string,
	hash: string,
	secret?: Buffer | undefined | null,
): boolean;

export declare function bcryptHash(
	password: string,
	rounds?: number | undefined | null,
	version?: number | undefined | null,
	saltLength?: number | undefined | null,
): string;

export declare function bcryptVerify(password: string, hash: string): boolean;

export declare function scryptHash(
	password: string,
	options?: ScryptOptions | undefined | null,
): string;

export declare function scryptVerify(password: string, hash: string): boolean;
