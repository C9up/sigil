export type {
	Argon2Options,
	BcryptOptions,
	ScryptOptions,
} from "./config.js";
export { defineConfig, drivers } from "./config.js";
export type { HashConfig, HashDriver, HashDriverConfig } from "./Hash.js";
/**
 * `Hash` is the multi-driver manager; `Hasher` wraps one driver.
 *
 * AdonisJS names these the other way round — its `Hash` is the single-driver
 * wrapper and `HashManager` the multi-driver one. `HashManager` is exported as
 * an alias so a migrated `import { HashManager }` resolves to the class that
 * actually manages drivers.
 */
export {
	E_SIGIL_NAPI_REQUIRED,
	Hash,
	Hash as HashManager,
	Hasher,
} from "./Hash.js";
export { default as SigilProvider } from "./SigilProvider.js";
