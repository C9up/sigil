import type { HashConfig, HashDriverConfig } from "./Hash.js";

export function defineConfig(config: HashConfig): HashConfig {
	return config;
}

/** Anything that releases a secret string — an environment `Secret`. */
export interface ReleasableSecret {
	release(): string;
}

/** Argon2 settings (AdonisJS `ArgonConfig`). */
export interface Argon2Options {
	variant?: "d" | "i" | "id";
	iterations?: number;
	memory?: number;
	parallelism?: number;
	saltSize?: number;
	hashLength?: number;
	/**
	 * Pepper: a key mixed into every hash and NOT stored in it. Verifying then
	 * requires the same secret — lose it and every hash it produced is lost.
	 */
	secret?: string | ReleasableSecret;
}

/** Bcrypt settings (AdonisJS `BcryptConfig`). */
export interface BcryptOptions {
	rounds?: number;
	saltSize?: number;
	version?: number;
}

/** Scrypt settings (AdonisJS `ScryptConfig`). */
export interface ScryptOptions {
	cost?: number;
	blockSize?: number;
	parallelization?: number;
	saltSize?: number;
	maxMemory?: number;
	keyLength?: number;
}

/**
 * Driver descriptors for `defineConfig`, matching the AdonisJS call site:
 *
 *   defineConfig({
 *     default: 'scrypt',
 *     list: { scrypt: drivers.scrypt({ cost: 16384, blockSize: 8 }) },
 *   })
 *
 * Named deviation: AdonisJS returns a config PROVIDER that lazily imports the
 * driver. Sigil returns the plain descriptor its provider can persist — the
 * call site is identical, and there is nothing to import lazily because every
 * driver lives in the same Rust engine.
 */
export const drivers = {
	argon2: (config: Argon2Options = {}): HashDriverConfig => ({
		...config,
		driver: "argon2",
	}),
	bcrypt: (config: BcryptOptions = {}): HashDriverConfig => ({
		...config,
		driver: "bcrypt",
	}),
	scrypt: (config: ScryptOptions = {}): HashDriverConfig => ({
		...config,
		driver: "scrypt",
	}),
};

export type { HashConfig, HashDriverConfig };
