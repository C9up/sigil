/**
 * Default `Hash` singleton — mirror of Adonis's
 * `import hash from '@adonisjs/hash/services/main'` shape.
 *
 *   import hash from '@c9up/sigil/services/main'
 *
 *   const digest = await hash.make('hunter2')
 *   const ok = await hash.verify(digest, 'hunter2') // verify(hash, value) — AdonisJS order
 *
 * Populated by `SigilProvider.boot()`.
 */

import { E_SIGIL_NOT_BOOTED } from "../errors.js";
import type { Hash } from "../Hash.js";

let instance: Hash | undefined;

/** @internal Bind the singleton (called by SigilProvider). */
export function setHash(value: Hash): void {
	instance = value;
}

/** @internal Read the singleton (or `undefined` pre-boot). */
export function getHash(): Hash | undefined {
	return instance;
}

/**
 * @internal Release the singleton, so a shut-down application does not leave a
 * dead hasher reachable through `services/main`.
 *
 * The caller checks ownership first (`getHash() === mine`): two applications
 * share this module in one process, and the one shutting down must not clear
 * what the other has since bound.
 */
export function clearHash(): void {
	instance = undefined;
}

// The target is never read through — every trap forwards to `instance`, so
// the trap takes the property alone.
const target: Hash = Object.create(null);

const hash: Hash = new Proxy(target, {
	get(...[, prop]: [Hash, string | symbol]) {
		// A module loader inspects what it imports before anyone uses it: it
		// reads `then` to decide whether the value is thenable, and various
		// symbols for interop and formatting. They are not members of Hash, so
		// answer undefined and let a genuine access be the one that reports.
		if (typeof prop === "symbol" || prop === "then") {
			return undefined;
		}
		if (!instance) throw new E_SIGIL_NOT_BOOTED(prop);
		const value = Reflect.get(instance, prop, instance);
		return typeof value === "function" ? value.bind(instance) : value;
	},
});

export default hash;
