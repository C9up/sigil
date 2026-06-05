/**
 * Default `Hash` singleton — mirror of Adonis's
 * `import hash from '@adonisjs/hash/services/main'` shape.
 *
 *   import hash from '@c9up/sigil/services/main'
 *
 *   const digest = await hash.make('hunter2')
 *   const ok = await hash.verify(digest, 'hunter2')
 *
 * Populated by `SigilProvider.boot()`.
 */

import type { Hash } from "../Hash.js";

let _instance: Hash | undefined;

/** @internal Bind the singleton (called by SigilProvider). */
export function _setHash(instance: Hash): void {
	_instance = instance;
}

/** @internal Read the singleton (or `undefined` pre-boot). */
export function _getHash(): Hash | undefined {
	return _instance;
}

const hash: Hash = new Proxy({} as Hash, {
	get(_target, prop) {
		if (!_instance) {
			throw new Error(
				"[sigil] Hash singleton accessed before SigilProvider.boot() ran. " +
					"Check that `@c9up/sigil/provider` is listed in your reamrc.ts providers.",
			);
		}
		const value = Reflect.get(_instance, prop, _instance);
		return typeof value === "function" ? value.bind(_instance) : value;
	},
});

export default hash;
