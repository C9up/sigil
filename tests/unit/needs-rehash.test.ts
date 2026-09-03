/**
 * `needsReHash` has to answer for an application that configured nothing.
 *
 * It is the whole migration path: an application calls it after a successful
 * verify and re-hashes when it says so. It used to return false outright
 * whenever no parameters were configured — so a hash minted with weak
 * parameters was never upgraded in exactly the applications that took the
 * defaults, which is most of them.
 *
 * The comparison is against the engine's own defaults rather than numbers
 * written down here, because the question is what hashing it again would
 * produce today.
 */

import { describe, expect, it } from "vitest";
import { Hash } from "../../src/Hash.js";

function hasher(config: object = {}) {
	return new Hash({
		default: "argon2",
		list: { argon2: { driver: "argon2", ...config } },
	} as never);
}

describe("sigil > needsReHash with no configuration", () => {
	it("upgrades a hash minted with weak parameters", async () => {
		const weak = await hasher({
			memory: 512,
			iterations: 1,
			parallelism: 1,
		}).make("secret");

		expect(hasher().needsReHash(weak)).toBe(true);
	});

	// The other half: saying "yes" always would re-hash every user on every
	// login, which is the same as saying nothing.
	it("leaves a hash it just made alone", async () => {
		const fresh = await hasher().make("secret");

		expect(hasher().needsReHash(fresh)).toBe(false);
	});

	it("leaves a hash matching the configured parameters alone", async () => {
		const config = { memory: 19456, iterations: 2, parallelism: 1 };
		const fresh = await hasher(config).make("secret");

		expect(hasher(config).needsReHash(fresh)).toBe(false);
	});

	// A weaker variant is not what argon2id would produce, and the difference
	// is a security property.
	it("upgrades a hash from another argon2 variant", async () => {
		const fromArgon2i = await hasher({ variant: "i" }).make("secret");

		expect(hasher().needsReHash(fromArgon2i)).toBe(true);
		expect(hasher({ variant: "i" }).needsReHash(fromArgon2i)).toBe(false);
	});
});
