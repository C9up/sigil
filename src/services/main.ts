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

const hash: Hash = new Proxy({} as Hash, {
	get(_target, prop) {
		if (!instance) {
			throw new Error(
				"[sigil] Hash singleton accessed before SigilProvider.boot() ran. " +
					"Check that `@c9up/sigil/provider` is listed in your reamrc.ts providers.",
			);
		}
		const value = Reflect.get(instance, prop, instance);
		return typeof value === "function" ? value.bind(instance) : value;
	},
});

export default hash;
