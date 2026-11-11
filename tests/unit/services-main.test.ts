/**
 * The `services/main` singleton before `SigilProvider.boot()` ran.
 *
 * A module loader, `await`, `Promise.resolve` and `util.inspect` all probe
 * what they are handed (`then`, well-known symbols) before anyone calls a
 * member. Those probes must not trip the "not booted" error: only a genuine
 * member access reports, and it reports a code a caller can branch on.
 */

import { inspect } from "node:util";
import { beforeEach, describe, expect, it } from "vitest";
import { Hash } from "../../src/Hash.js";
import hash, { clearHash, setHash } from "../../src/services/main.js";

describe("services/main before boot", () => {
	beforeEach(() => {
		clearHash();
	});

	it("is not thenable, so awaiting it yields the proxy itself", async () => {
		await expect(Promise.resolve(hash)).resolves.toBe(hash);
		const awaited = await hash;
		expect(awaited).toBe(hash);
	});

	it("can be returned from an async function", async () => {
		const resolve = async () => hash;
		await expect(resolve()).resolves.toBe(hash);
	});

	it("answers undefined to symbol probes", () => {
		expect(Reflect.get(hash, Symbol.toStringTag)).toBeUndefined();
		expect(Reflect.get(hash, Symbol.iterator)).toBeUndefined();
		expect(() => Object.prototype.toString.call(hash)).not.toThrow();
		expect(() => inspect(hash)).not.toThrow();
	});

	it("reports a genuine member access with E_SIGIL_NOT_BOOTED", () => {
		let caught: unknown;
		try {
			hash.make("secret");
		} catch (error) {
			caught = error;
		}
		expect(caught).toBeInstanceOf(Error);
		expect(caught).toMatchObject({
			code: "E_SIGIL_NOT_BOOTED",
			name: "E_SIGIL_NOT_BOOTED",
		});
	});

	it("forwards to the bound instance once booted", () => {
		const bound = new Hash({
			default: "scrypt",
			list: { scrypt: { driver: "scrypt" } },
		});
		setHash(bound);
		expect(hash.config).toBe(bound.config);
		expect(hash.isValidHash("$scrypt$n=16384,r=8,p=1$c2FsdA$aGFzaA")).toBe(
			true,
		);
		// The singleton itself still is not thenable once a hasher is bound.
		expect(Reflect.get(hash, "then")).toBeUndefined();
	});
});
