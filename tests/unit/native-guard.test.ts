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
import { nativeBinarySuffix } from "../../src/vendor/nativeBinary.js";

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

/** Load sigil with `require` answering `binary` for the `.node` file. */
async function withBinary(binary: unknown) {
	vi.resetModules();
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
	vi.doUnmock("node:module");
	vi.resetModules();
});

describe.skipIf(nativeBinarySuffix() === undefined)(
	"sigil > the loaded binary is checked",
	() => {
		it("degrades on a binary missing any one call, instead of failing on it later", async () => {
			for (const missing of CALLS) {
				const { native } = await withBinary(standIn(missing));
				await native.loadNative();

				expect(native.isNativeLoaded(), missing).toBe(false);
				// Answered as "no engine", not as a TypeError on the missing call.
				expect(native.bcryptHash("secret"), missing).toBeNull();
			}
		});

		it("says what the rejected binary does export", async () => {
			const { vendor } = await withBinary({ bcryptHash: () => null });

			const attempt = vendor.loadNativeBinary(
				(value): value is { bcryptHash: () => null; scryptHash: () => null } =>
					vendor.hasFunctions(value, ["bcryptHash", "scryptHash"]),
			);

			expect(attempt.loaded).toBe(false);
			if (attempt.loaded) return;
			expect(attempt.suffix).toBe(nativeBinarySuffix());
			expect(attempt.cause).toBeInstanceOf(Error);
			expect(String(attempt.cause)).toMatch(
				/lacks functions this package calls \(it exports: bcryptHash\)[\s\S]*rebuild it/,
			);
		});

		it("refuses a module that is not an object at all", async () => {
			const { vendor } = await withBinary("index.node");

			const attempt = vendor.loadNativeBinary((value): value is object =>
				vendor.hasFunctions(value, ["bcryptHash"]),
			);

			expect(attempt.loaded).toBe(false);
			if (attempt.loaded) return;
			expect(String(attempt.cause)).toMatch(/it exports: none/);
		});

		it("hands over a binary carrying every call", async () => {
			const { native } = await withBinary(standIn());
			await native.loadNative();

			expect(native.isNativeLoaded()).toBe(true);
		});
	},
);
