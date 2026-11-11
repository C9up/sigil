/**
 * Sigil errors.
 *
 * Every error sigil raises on its own carries an `E_SIGIL_*` code, so a caller
 * branches on `error.code` rather than on a message, and catches every one of
 * them by the base class.
 */

/** Base class, so a caller can catch every sigil error by one name. */
export class SigilError extends Error {
	readonly code: string;

	constructor(code: string, message: string, options?: ErrorOptions) {
		super(message, options);
		this.name = new.target.name;
		this.code = code;
	}
}

/**
 * Raised when `@c9up/sigil/services/main` is used before
 * `SigilProvider.boot()` bound a hasher to it.
 */
export class E_SIGIL_NOT_BOOTED extends SigilError {
	constructor(member: string) {
		super(
			"E_SIGIL_NOT_BOOTED",
			`[E_SIGIL_NOT_BOOTED] hash.${member} used before SigilProvider.boot() ran. ` +
				"Check that `@c9up/sigil/provider` is listed in your reamrc.ts providers.",
		);
	}
}

/**
 * Raised at construction for a hasher whose `driver` names no driver sigil
 * has, so a typo fails at boot rather than at the first hash.
 */
export class E_SIGIL_UNKNOWN_DRIVER extends SigilError {
	constructor(name: string, driver: unknown, known: readonly string[]) {
		super(
			"E_SIGIL_UNKNOWN_DRIVER",
			`[E_SIGIL_UNKNOWN_DRIVER] Hasher "${name}" names driver ${JSON.stringify(driver)}, ` +
				`which is not one of: ${known.join(", ")}`,
		);
	}
}
