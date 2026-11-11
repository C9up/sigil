/**
 * A bad driver configuration fails when the driver is built — at boot — not
 * at the first hash.
 *
 * The constructors used to store whatever they were given: an out-of-range
 * value surfaced as a 500 on the first sign-up in production, and a value of
 * the wrong type was silently replaced by the default, so `rounds: '12'` read
 * from an environment variable quietly became something else. Worse, bcrypt
 * accepted version 120 (`$2x$`), whose hashes it then never verified: every
 * account created under it could never log in again, and nothing errored.
 */

import { describe, expect, it } from "vitest";
import { drivers } from "../../src/config.js";
import { SigilError } from "../../src/errors.js";
import { Hash } from "../../src/Hash.js";

function hasher(driver: string, config: Record<string, unknown> = {}) {
	return new Hash({
		default: driver,
		list: { [driver]: { ...config, driver } },
	});
}

describe("sigil > an unknown driver name throws at construction", () => {
	it.each([
		// A typo used to be skipped, and surfaced only at the first use().
		"argon",
		"",
		// Names an object literal inherits used to resolve to Object.prototype
		// members: "constructor" stored the config object itself as the driver.
		"constructor",
		"__proto__",
		"toString",
		"hasOwnProperty",
	])("%j", (driver) => {
		let caught: unknown;
		try {
			new Hash({ default: "main", list: { main: { driver } } });
		} catch (error) {
			caught = error;
		}
		expect(caught).toBeInstanceOf(SigilError);
		expect(caught).toMatchObject({
			code: "E_SIGIL_UNKNOWN_DRIVER",
			name: "E_SIGIL_UNKNOWN_DRIVER",
		});
		expect(String(caught)).toContain('"main"');
		expect(String(caught)).toContain("argon2, bcrypt, scrypt");
	});

	it("checks the older `drivers` spelling too", () => {
		expect(
			() =>
				new Hash({
					default: "main",
					drivers: { main: { driver: "constructor" } },
				}),
		).toThrow(/E_SIGIL_UNKNOWN_DRIVER/);
	});
});

describe("sigil > invalid driver options throw at construction", () => {
	it.each([
		["bcrypt", { rounds: 4 }, /rounds/],
		["bcrypt", { rounds: "12" }, /"rounds" option must be an integer/],
		["bcrypt", { rounds: 12.5 }, /"rounds" option must be an integer/],
		["bcrypt", { version: 120 }, /"version" option must be one of: 97,98,121/],
		["bcrypt", { version: "98" }, /version/],
		["bcrypt", { saltSize: 32 }, /saltSize/],
		["argon2", { memory: 16, parallelism: 4 }, /memory/],
		["argon2", { memory: "65536" }, /"memory" option must be an integer/],
		["argon2", { memoryKib: 4 }, /memoryKib/],
		["argon2", { iterations: 1 }, /iterations/],
		["argon2", { parallelism: 0 }, /parallelism/],
		["argon2", { hashLength: 9 }, /hashLength/],
		["argon2", { hashLength: 65 }, /hashLength/],
		["argon2", { saltSize: 49 }, /saltSize/],
		["argon2", { variant: "x" }, /variant/],
		["argon2", { secret: 42 }, /secret/],
		["scrypt", { cost: 3000 }, /power of two/],
		["scrypt", { cost: 1 }, /cost/],
		["scrypt", { cost: "16384" }, /"cost" option must be an integer/],
		["scrypt", { blockSize: 0 }, /blockSize/],
		["scrypt", { parallelization: 0 }, /parallelization/],
		["scrypt", { keyLength: 32 }, /keyLength/],
		["scrypt", { keyLength: 129 }, /keyLength/],
		["scrypt", { saltSize: 4 }, /saltSize/],
		["scrypt", { saltLength: 2000 }, /saltLength/],
		["scrypt", { maxMemory: 1024 }, /maxMemory/],
		["scrypt", { cost: 32768 }, /maxMemory/],
	])("%s %j", (driver, config, message) => {
		expect(() => hasher(driver, config)).toThrow(message);
	});

	it("accepts every bcrypt version it can verify", async () => {
		for (const version of [97, 98, 121]) {
			const hash = hasher("bcrypt", { rounds: 10, version });
			const made = await hash.make("hunter2");

			expect(await hash.verify(made, "hunter2")).toBe(true);
			expect(hash.needsReHash(made)).toBe(false);
		}
	});

	it("accepts the full upstream defaults spelled out", () => {
		expect(() =>
			hasher("argon2", {
				variant: "id",
				iterations: 3,
				memory: 65536,
				parallelism: 4,
				saltSize: 16,
				hashLength: 32,
			}),
		).not.toThrow();
		expect(() =>
			hasher("scrypt", {
				cost: 16384,
				blockSize: 8,
				parallelization: 1,
				saltSize: 16,
				keyLength: 64,
				maxMemory: 33554432,
			}),
		).not.toThrow();
	});
});

describe("sigil > argon2 secret (pepper) in the config type", () => {
	it("takes a string through drivers.argon2 and applies it", async () => {
		const peppered = new Hash({
			default: "argon2",
			list: { argon2: drivers.argon2({ secret: "pepper-key" }) },
		});
		const plain = new Hash({
			default: "argon2",
			list: { argon2: drivers.argon2() },
		});
		const made = await peppered.make("hunter2");

		expect(await peppered.verify(made, "hunter2")).toBe(true);
		expect(await plain.verify(made, "hunter2")).toBe(false);
	});

	it("takes a Secret, as an environment schema returns for APP_KEY", async () => {
		const secret = {
			release: () => "pepper-key",
			toString: () => "[redacted]",
		};
		const fromSecret = new Hash({
			default: "argon2",
			list: { argon2: drivers.argon2({ secret }) },
		});
		const fromString = new Hash({
			default: "argon2",
			list: { argon2: drivers.argon2({ secret: "pepper-key" }) },
		});

		// The released value is the pepper, not the redacted placeholder.
		const made = await fromSecret.make("hunter2");
		expect(await fromString.verify(made, "hunter2")).toBe(true);
	});
});
