/**
 * Argon2 `variant` / `hashLength` / `saltSize` and bcrypt `version`.
 *
 * All four were declared on the config interfaces and never read. An app that
 * set `variant: 'i'` got argon2id, one that set `hashLength: 64` got 32, and
 * one pinned to bcrypt `$2a$` for an existing user table got `$2b$` — silently,
 * in every case, with `isValidHash` accepting all of them so nothing looked
 * wrong.
 */

import { describe, expect, it } from "vitest";
import { Hash } from "../../src/Hash.js";

function argon2(config: Record<string, unknown> = {}): Hash {
	return new Hash({
		default: "argon",
		list: { argon: { driver: "argon2", ...config } },
	});
}

function bcrypt(config: Record<string, unknown> = {}): Hash {
	return new Hash({
		default: "bcrypt",
		list: { bcrypt: { driver: "bcrypt", ...config } },
	});
}

describe("sigil > argon2 variant", () => {
	it.each([
		["i", "$argon2i$"],
		["d", "$argon2d$"],
		["id", "$argon2id$"],
	])("honours variant %s", async (variant, prefix) => {
		const hashed = await argon2({ variant }).make("hunter2");

		expect(hashed.startsWith(prefix)).toBe(true);
		expect(await argon2({ variant }).verify(hashed, "hunter2")).toBe(true);
		expect(await argon2({ variant }).verify(hashed, "wrong")).toBe(false);
	});

	it("defaults to argon2id", async () => {
		expect((await argon2().make("hunter2")).startsWith("$argon2id$")).toBe(
			true,
		);
	});

	it("verifies across variants, reading the algorithm from the hash", async () => {
		// A hash made with argon2i must not be verified as argon2id.
		const made = await argon2({ variant: "i" }).make("hunter2");

		expect(await argon2({ variant: "id" }).verify(made, "hunter2")).toBe(true);
	});
});

describe("sigil > argon2 lengths", () => {
	it("honours hashLength", async () => {
		const hashed = await argon2({ hashLength: 64 }).make("hunter2");

		// 64 raw bytes is 86 unpadded base64 characters.
		expect(hashed.split("$").pop()).toHaveLength(86);
		expect(await argon2({ hashLength: 64 }).verify(hashed, "hunter2")).toBe(
			true,
		);
	});

	it("honours saltSize", async () => {
		const hashed = await argon2({ saltSize: 32 }).make("hunter2");

		// 32 raw bytes is 43 unpadded base64 characters.
		expect(hashed.split("$")[4]).toHaveLength(43);
		expect(await argon2({ saltSize: 32 }).verify(hashed, "hunter2")).toBe(true);
	});

	it("refuses a salt outside the safe range instead of quietly clamping it", async () => {
		await expect(argon2({ saltSize: 4 }).make("hunter2")).rejects.toThrow();
	});

	it("refuses an unknown variant at CONFIG time, not at the first hash", () => {
		// A bad config should surface at boot, not on a user's first login.
		expect(() => argon2({ variant: "z" })).toThrow(/Unknown Argon2 variant/);
	});
});

describe("sigil > bcrypt version", () => {
	it.each([
		[97, "$2a$"],
		[98, "$2b$"],
		[121, "$2y$"],
	])("honours version %i", async (version, prefix) => {
		const hashed = await bcrypt({ version, rounds: 10 }).make("hunter2");

		expect(hashed.startsWith(prefix)).toBe(true);
		expect(
			await bcrypt({ version, rounds: 10 }).verify(hashed, "hunter2"),
		).toBe(true);
	});

	it("defaults to $2b$", async () => {
		expect(
			(await bcrypt({ rounds: 10 }).make("hunter2")).startsWith("$2b$"),
		).toBe(true);
	});

	it("refuses a saltSize bcrypt cannot produce", async () => {
		// The algorithm fixes it at 16 bytes; anything else is unreadable.
		await expect(
			bcrypt({ rounds: 10, saltSize: 32 }).make("x"),
		).rejects.toThrow();
		await expect(
			bcrypt({ rounds: 10, saltSize: 16 }).make("x"),
		).resolves.toBeTruthy();
	});
});
