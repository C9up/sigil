/**
 * Hashes stored by an application built on `@adonisjs/hash` must keep working
 * after it moves to sigil, and must not be weakened by the move.
 *
 * The vectors below were written by `@adonisjs/hash` 10.1.1 itself (bcrypt 6,
 * argon2 0.44, Node crypto), from PASSWORD, with its default configuration
 * unless the name says otherwise. They are literals on purpose: regenerating
 * them from sigil would only prove sigil agrees with itself.
 *
 * Two failures they cover:
 * - upstream stores bcrypt as a PHC string (`$bcrypt$v=98$r=10$…`), which
 *   sigil did not read — every migrated user was locked out;
 * - sigil's argon2 defaults were a third of upstream's, so the "verify, then
 *   re-hash if needsReHash" login flow silently re-hashed every migrated
 *   password DOWNWARD.
 */

import { describe, expect, it } from "vitest";
import { Hash } from "../../src/Hash.js";

const PASSWORD = "correct horse battery staple";

const ADONIS = {
	bcryptV98R10:
		"$bcrypt$v=98$r=10$GUO2Wb6qbX++g+Rj7TMw/A$vKswmGJAaU23gK55NxkYg6Uumeo9a8A",
	bcryptV97R11:
		"$bcrypt$v=97$r=11$sy4yaS9zT8A/fr/YNcrXSQ$lrslf78zvt2SBEpxJpZxs6lAJH/SLRQ",
	argon2:
		"$argon2id$v=19$m=65536,t=3,p=4$apabyr1nIDcGd/NrAV/4rg$vurldQTOttPRWlO2VVrPfWFBToJxQNXSQoY0L1P6Gsw",
	scryptKeyLength128:
		"$scrypt$n=16384,r=8,p=1$dkKkDneyGYkDJrGJytFqiA$1OZPKHHUfoBuF61xlTDRbGw4rclzgdEhxyNKbeqVc23WfVaZ/p8xC++IrVU8H+lhhcFqKJK9up3PpFWSAbd9758ujFXeXu1nJGzKEhqJ89ziwgzZYNY0GOQljTzAShxN7VgHBsgZg8l68EZusxQQaftfiXw/fkcInvSdS+XuXGw",
};

function hasher(driver: string, config: Record<string, unknown> = {}) {
	return new Hash({
		default: driver,
		list: { [driver]: { ...config, driver } },
	});
}

describe("sigil > bcrypt hashes stored by @adonisjs/hash", () => {
	const bcrypt = hasher("bcrypt");

	it.each([
		["v=98 r=10", ADONIS.bcryptV98R10],
		["v=97 r=11", ADONIS.bcryptV97R11],
	])("verifies the PHC form (%s)", async (_label, stored) => {
		expect(bcrypt.isValidHash(stored)).toBe(true);
		expect(await bcrypt.verify(stored, PASSWORD)).toBe(true);
		expect(await bcrypt.verify(stored, "wrong password")).toBe(false);
	});

	it("verifies the older PHC form without a version", async () => {
		const unversioned = ADONIS.bcryptV97R11.replace("$v=97", "");

		expect(await bcrypt.verify(unversioned, PASSWORD)).toBe(true);
	});

	it("asks for a re-hash, so the row migrates to the configured format", async () => {
		expect(bcrypt.needsReHash(ADONIS.bcryptV98R10)).toBe(true);

		const migrated = await bcrypt.make(PASSWORD);
		expect(migrated.startsWith("$2b$12$")).toBe(true);
		expect(bcrypt.needsReHash(migrated)).toBe(false);
	});

	it.each([
		["an altered digest", ADONIS.bcryptV98R10.replace("vKsw", "vKsx")],
		["an unknown version", ADONIS.bcryptV98R10.replace("v=98", "v=120")],
		["a cost above the cap", ADONIS.bcryptV98R10.replace("r=10", "r=31")],
		[
			"a short salt",
			ADONIS.bcryptV98R10.replace("GUO2Wb6qbX++g+Rj7TMw/A", "GUO2Wb6qbX8"),
		],
		["no digest", ADONIS.bcryptV98R10.replace(/\$[^$]+$/, "$")],
	])("refuses a PHC string with %s", async (_label, malformed) => {
		expect(await bcrypt.verify(malformed, PASSWORD)).toBe(false);
	});
});

describe("sigil > argon2 defaults match @adonisjs/hash", () => {
	const argon2 = hasher("argon2");

	it("hashes with m=65536, t=3, p=4 when nothing is configured", async () => {
		const made = await argon2.make(PASSWORD);

		expect(made).toMatch(/^\$argon2id\$v=19\$m=65536,t=3,p=4\$/);
	});

	it("verifies an upstream default hash and leaves it alone", async () => {
		expect(await argon2.verify(ADONIS.argon2, PASSWORD)).toBe(true);
		expect(await argon2.verify(ADONIS.argon2, "wrong password")).toBe(false);
		// The downgrade: this used to answer true, and the re-hash came out at
		// m=19456,t=2,p=1.
		expect(argon2.needsReHash(ADONIS.argon2)).toBe(false);
	});

	it("still upgrades the weaker hash the previous defaults produced", () => {
		const previousDefault =
			"$argon2id$v=19$m=19456,t=2,p=1$pl/vS1MLvCPhYG1DepHagg$Sv6FvOhPCgtYiQLFw6m2UptaXQSlFR6h5OJKbUXSHcA";

		expect(argon2.needsReHash(previousDefault)).toBe(true);
	});

	it("upgrades an argon2 hash of the older version 16", () => {
		expect(argon2.needsReHash(ADONIS.argon2.replace("v=19", "v=16"))).toBe(
			true,
		);
	});

	it("refuses fewer than two iterations at construction, as upstream", () => {
		expect(() => hasher("argon2", { iterations: 1 })).toThrow(/iterations/);
	});
});

describe("sigil > scrypt hashes stored by @adonisjs/hash", () => {
	it("verifies a 128-byte key, the upper end of upstream's keyLength", async () => {
		const scrypt = hasher("scrypt");

		expect(await scrypt.verify(ADONIS.scryptKeyLength128, PASSWORD)).toBe(true);
		expect(
			await scrypt.verify(ADONIS.scryptKeyLength128, "wrong password"),
		).toBe(false);
	});

	it("makes a 128-byte key when configured to", async () => {
		const scrypt = hasher("scrypt", { keyLength: 128 });
		const made = await scrypt.make(PASSWORD);
		const key = Buffer.from(made.split("$").pop() ?? "", "base64");

		expect(key).toHaveLength(128);
		expect(await scrypt.verify(made, PASSWORD)).toBe(true);
	});
});
