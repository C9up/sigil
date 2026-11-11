/**
 * A binary that loads is not necessarily the binary this package calls.
 *
 * A stale build, or one from another version, loads just as well. The loader
 * used to hand it over on the strength of a cast, so a missing function
 * surfaced as "native.bcryptHash is not a function" on the first hash, far
 * from the load. Now the package's guard checks every call at load, and a
 * binary that fails it is reported like one that failed to load: sigil then
 * degrades exactly as it does without a binary.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

/** Every function sigil calls on its engine. */
const CALLS = [
	"argon2Hash",
	"argon2Verify",
	"argon2Defaults",
	"costLimits",
	"bcryptHash",
	"bcryptVerify",
	"scryptHash",
	"scryptVerify",
];

const standIn = (omit?: string) =>
	Object.fromEntries(
		CALLS.filter((name) => name !== omit).map((name) => [name, () => null]),
	);

/**
 * The host the loader is told it runs on. Stubbed like the binary is, so the
 * suite runs, and asserts, on every platform: a host without a prebuilt
 * binary would otherwise make the loader stop before it ever calls `require`.
 */
const HOST = { platform: "linux", arch: "x64", suffix: "linux-x64-gnu" };

/** Load sigil with `require` answering `binary` for the `.node` file. */
async function withBinary(binary: unknown) {
	vi.resetModules();
	vi.doMock("node:process", async (importOriginal) => ({
		...(await importOriginal<typeof import("node:process")>()),
		platform: HOST.platform,
		arch: HOST.arch,
	}));
	vi.doMock("node:module", async (importOriginal) => ({
		...(await importOriginal<typeof import("node:module")>()),
		createRequire: () => () => binary,
	}));
	return {
		native: await import("../../src/native.js"),
		vendor: await import("../../src/vendor/nativeBinary.js"),
	};
}

afterEach(() => {
	vi.doUnmock("node:process");
	vi.doUnmock("node:module");
	vi.resetModules();
});

describe("sigil > the loaded binary is checked", () => {
	it("degrades on a binary missing any one call, instead of failing on it later", async () => {
		for (const missing of CALLS) {
			const { native } = await withBinary(standIn(missing));
			await native.loadNative();

			expect(native.isNativeLoaded(), missing).toBe(false);
			// Answered as "no engine", not as a TypeError on the missing call.
			expect(native.bcryptHash("secret"), missing).toBeNull();
		}
	});

	it("names the calls a rejected binary lacks", async () => {
		const { vendor } = await withBinary({ bcryptHash: () => null });
		const calls = ["bcryptHash", "scryptHash", "argon2Hash"];

		const attempt = vendor.loadNativeBinary(
			(value): value is object => vendor.hasFunctions(value, calls),
			calls,
		);

		expect(attempt.loaded).toBe(false);
		if (attempt.loaded) return;
		expect(attempt.suffix).toBe(HOST.suffix);
		expect(attempt.cause).toBeInstanceOf(Error);
		expect(String(attempt.cause)).toMatch(
			/loaded, but it lacks scryptHash, argon2Hash\. [\s\S]*rebuild it/,
		);
	});

	it("names every call when the module is not an object at all", async () => {
		const { vendor } = await withBinary("index.node");

		const attempt = vendor.loadNativeBinary(
			(value): value is object => vendor.hasFunctions(value, ["bcryptHash"]),
			["bcryptHash"],
		);

		expect(attempt.loaded).toBe(false);
		if (attempt.loaded) return;
		expect(String(attempt.cause)).toMatch(/it lacks bcryptHash\./);
	});

	it("lists what the binary exports when the guard has no list to name", async () => {
		const { vendor } = await withBinary({ bcryptHash: () => null });

		const attempt = vendor.loadNativeBinary((value): value is object =>
			vendor.hasFunctions(value, ["scryptHash"]),
		);

		expect(attempt.loaded).toBe(false);
		if (attempt.loaded) return;
		expect(String(attempt.cause)).toMatch(/it exports: bcryptHash\)/);
	});

	it("hands over a binary carrying every call", async () => {
		const { native } = await withBinary(standIn());
		await native.loadNative();

		expect(native.isNativeLoaded()).toBe(true);
	});
});
