/**
 * A migrated `config/hash.ts` must run with its imports rewritten and nothing
 * else — the AdonisJS `defineConfig({ default, list: { … drivers.scrypt() } })`
 * shape, alongside sigil's own serializable spelling.
 */
import { describe, expect, it } from "vitest";
import { defineConfig, drivers } from "../../src/config.js";
import { Hash, HashManager } from "../../src/index.js";

describe("sigil > AdonisJS config shape", () => {
	it("accepts `list` with the drivers helpers", async () => {
		const config = defineConfig({
			default: "scrypt",
			list: {
				scrypt: drivers.scrypt({ cost: 16384, blockSize: 8 }),
				argon: drivers.argon2({ memory: 65536 }),
			},
		});
		const hash = new Hash(config);
		expect(hash.use("scrypt")).toBeDefined();
		expect(hash.use("argon")).toBeDefined();
	});

	it("still accepts sigil's own `drivers` spelling", () => {
		const hash = new Hash({
			default: "bcrypt",
			drivers: { bcrypt: { driver: "bcrypt", rounds: 10 } },
		});
		expect(hash.use("bcrypt")).toBeDefined();
	});

	it("keeps the config readable, as the manager does upstream", () => {
		const config = defineConfig({
			default: "scrypt",
			list: { scrypt: drivers.scrypt({ cost: 16384 }) },
		});
		expect(new Hash(config).config).toBe(config);
	});

	it("carries each helper's settings through to the driver name", () => {
		expect(drivers.scrypt({ cost: 16384 })).toEqual({
			driver: "scrypt",
			cost: 16384,
		});
		expect(drivers.argon2({ memory: 65536 })).toEqual({
			driver: "argon2",
			memory: 65536,
		});
		expect(drivers.bcrypt({ rounds: 12 })).toEqual({
			driver: "bcrypt",
			rounds: 12,
		});
	});

	it("exposes the manager under the AdonisJS name too", () => {
		expect(HashManager).toBe(Hash);
	});

	it("hashes and verifies through a migrated config", async () => {
		const hash = new Hash(
			defineConfig({
				default: "scrypt",
				list: { scrypt: drivers.scrypt({ cost: 16384, blockSize: 8 }) },
			}),
		);
		const digest = await hash.make("correct horse battery staple");
		expect(hash.isValidHash(digest)).toBe(true);
		expect(await hash.verify(digest, "correct horse battery staple")).toBe(
			true,
		);
		expect(await hash.verify(digest, "wrong")).toBe(false);
	});
});
