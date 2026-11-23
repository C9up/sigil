/**
 * Sigil errors, one per code. A caller branches on `error.code` or on
 * `error instanceof errors.E_SIGIL_*`.
 */

import { createError } from "@c9up/flare";

/**
 * Raised when a driver is used without the Rust engine loaded: the binary is
 * missing, fails to load, or lacks a call sigil makes. Hashing goes through
 * the engine or does not happen; there is no weaker fallback.
 */
export const E_SIGIL_NAPI_REQUIRED = createError<[driver: string]>(
	"[E_SIGIL_NAPI_REQUIRED] The %s Rust engine is required but not loaded.\n" +
		"  Fix: cd packages/sigil && pnpm build:napi",
	"E_SIGIL_NAPI_REQUIRED",
);

/**
 * Raised when `@c9up/sigil/services/main` is used before
 * `SigilProvider.boot()` bound a hasher to it.
 */
export const E_SIGIL_NOT_BOOTED = createError<[member: string]>(
	"[E_SIGIL_NOT_BOOTED] hash.%s used before SigilProvider.boot() ran. " +
		"Check that `@c9up/sigil/provider` is listed in your reamrc.ts providers.",
	"E_SIGIL_NOT_BOOTED",
);

/**
 * Raised at construction for a hasher whose `driver` names no driver sigil
 * has, so a typo fails at boot rather than at the first hash.
 */
export const E_SIGIL_UNKNOWN_DRIVER = createError<
	[name: string, driver: unknown, known: string]
>(
	'[E_SIGIL_UNKNOWN_DRIVER] Hasher "%s" names driver %j, which is not one of: %s',
	"E_SIGIL_UNKNOWN_DRIVER",
);

/**
 * Raised when a hasher name is not declared in the config: a `default` naming
 * none of them (at construction, so the boot fails like an unknown driver
 * does), or `use(name)` for an undeclared name. The last value lists the
 * declared names, or says there are none.
 */
export const E_SIGIL_UNKNOWN_HASHER = createError<
	[name: string, declared: string]
>(
	"[E_SIGIL_UNKNOWN_HASHER] No hasher named %j is declared in the hash config. %s",
	"E_SIGIL_UNKNOWN_HASHER",
);

/**
 * Raised when a driver is built with an option it cannot use: not an integer,
 * out of range, not one of the allowed values, a scrypt `cost` that is not a
 * power of two, or options whose combined work exceeds what `verify` accepts.
 * The site builds the message, which names the option.
 */
export const E_SIGIL_INVALID_OPTION = createError<[message: string]>(
	"%s",
	"E_SIGIL_INVALID_OPTION",
);

/**
 * Raised by `make` for a password longer than the driver accepts: the
 * shared byte cap every driver enforces, or bcrypt's own 72-byte limit.
 * The site builds the message, which names the limit.
 */
export const E_SIGIL_PASSWORD_TOO_LONG = createError<[message: string]>(
	"%s",
	"E_SIGIL_PASSWORD_TOO_LONG",
);
