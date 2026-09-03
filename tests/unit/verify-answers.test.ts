/**
 * `verify` answers; it does not fail.
 *
 * A wrong password is an ordinary outcome of a login form, and so are the two
 * shapes that reach this code with it: a stored hash this driver did not
 * produce (an application that switched algorithms — the case `needsReHash`
 * exists to handle), and a value longer than the algorithm can hash, which is
 * one long passphrase away from any password manager.
 *
 * argon2 and scrypt both return false for these. bcrypt threw, turning a 401
 * into a 500 on a path anyone can reach unauthenticated.
 */

import { describe, expect, it } from "vitest";
import { Hash } from "../../src/Hash.js";

function hasher(driver: string, config: object = {}) {
	return new Hash({
		default: driver,
		list: { [driver]: { driver, ...config } },
	} as never);
}

const bcrypt = () => hasher("bcrypt", { rounds: 10 });

describe("sigil > verify answers rather than throwing", () => {
	it("refuses a hash bcrypt did not produce", async () => {
		const fromArgon2 = await hasher("argon2").make("secret");

		await expect(bcrypt().verify(fromArgon2, "secret")).resolves.toBe(false);
	});

	it("refuses a value bcrypt could never have hashed", async () => {
		const stored = await bcrypt().make("secret");
		// `make` refuses beyond 72 bytes, so no stored hash can match this.
		const tooLong = "x".repeat(100);

		await expect(bcrypt().verify(stored, tooLong)).resolves.toBe(false);
	});

	it("refuses something that is not a hash at all", async () => {
		await expect(bcrypt().verify("not-a-hash", "secret")).resolves.toBe(false);
	});

	// The behaviour the other two drivers already had, kept honest.
	it("still accepts the right password", async () => {
		const stored = await bcrypt().make("secret");

		await expect(bcrypt().verify(stored, "secret")).resolves.toBe(true);
		await expect(bcrypt().verify(stored, "wrong")).resolves.toBe(false);
	});
});
