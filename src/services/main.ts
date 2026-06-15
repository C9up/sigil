/**
 * Default `Hash` singleton — mirror of Adonis's
 * `import hash from '@adonisjs/hash/services/main'` shape.
 *
 *   import hash from '@c9up/sigil/services/main'
 *
 *   const digest = await hash.make('hunter2')
 *   const ok = await hash.verify('hunter2', digest) // verify(value, hash)
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
