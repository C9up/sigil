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
function withBinary(binary: unknown) {
	return withRequire(() => binary);
}

/** Load sigil with `require` running `load` for every module it asks for. */
async function withRequire(
	load: (id: string) => unknown,
	host: { platform: string; arch: string } = HOST,
) {
	vi.resetModules();
	vi.doMock("node:process", async (importOriginal) => ({
		...(await importOriginal<typeof import("node:process")>()),
		platform: host.platform,
		arch: host.arch,
	}));
	vi.doMock("node:module", async (importOriginal) => ({
		...(await importOriginal<typeof import("node:module")>()),
		createRequire: () => load,
	}));
	return {
		native: await import("../../src/native.js"),
		vendor: await import("../../src/vendor/nativeBinary.js"),
		sigil: await import("../../src/index.js"),
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

describe("sigil > without an engine, every driver refuses", () => {
	// A well-formed stored hash per driver, so verify reaches the engine
	// instead of answering false on the format check.
	it.each([
		[
			"argon2",
			"$argon2id$v=19$t=3,m=4096,p=1$drxJBWzWahR5tMubp+a1Sw$L/Oh2uw6QKW77i/KQ8eGuOt3ui52hEmmKlu1KBVBxiM",
		],
		["bcrypt", `$2b$10$${"a".repeat(53)}`],
		[
			"scrypt",
			"$scrypt$n=16384,r=8,p=1$iILKD1gVSx6bqualYqyLBQ$DNzIISdmTQS6sFdQ1tJ3UCZ7Uun4uGHNjj0x8FHOqB0pf2LYsu9Xaj5MFhHg21qBz8l5q/oxpeV+ZkgTAj+OzQ",
		],
	])(
		"%s rejects make and verify with E_SIGIL_NAPI_REQUIRED",
		async (driver, stored) => {
			const { sigil } = await withRequire(() => {
				throw new Error("Cannot find module 'index.linux-x64-gnu.node'");
			});
			const hash = new sigil.Hash({
				default: driver,
				list: { [driver]: { driver } },
			});

			expect(hash.isValidHash(stored)).toBe(true);
			for (const call of [
				() => hash.make("secret"),
				() => hash.verify(stored, "secret"),
			]) {
				const refusal = await call().then(
					() => undefined,
					(error: unknown) => error,
				);
				expect(refusal).toBeInstanceOf(sigil.errors.E_SIGIL_NAPI_REQUIRED);
				expect(refusal).toMatchObject({ code: "E_SIGIL_NAPI_REQUIRED" });
				expect(String(refusal)).toContain(
					`[E_SIGIL_NAPI_REQUIRED] The ${driver} Rust engine`,
				);
			}
		},
	);
});

/** What `require` throws for a module that is not there. */
function notFound(id: string): Error {
	return Object.assign(new Error(`Cannot find module '${id}'`), {
		code: "MODULE_NOT_FOUND",
	});
}

/** The platform package this host installs. */
const PLATFORM_PACKAGE = `@c9up/sigil-${HOST.suffix}`;

/** What `make` rejects with, or `undefined` when it resolves. */
async function refusalOf(sigil: typeof import("../../src/index.js")) {
	const hash = new sigil.Hash({
		default: "bcrypt",
		list: { bcrypt: { driver: "bcrypt" } },
	});
	return hash.make("secret").then(
		() => undefined,
		(error: unknown) => error,
	);
}

describe("sigil > the engine comes from the local build or the platform package", () => {
	it("loads the platform package when no local binary is built", async () => {
		const asked: string[] = [];
		const { native } = await withRequire((id) => {
			asked.push(id);
			if (id === PLATFORM_PACKAGE) return standIn();
			throw notFound(id);
		});
		await native.loadNative();

		expect(native.isNativeLoaded()).toBe(true);
		expect(asked).toHaveLength(2);
		expect(asked[0]).toMatch(/[\\/]index\.linux-x64-gnu\.node$/);
		expect(asked[1]).toBe(PLATFORM_PACKAGE);
	});

	it("prefers the local build, and never asks for the package then", async () => {
		const asked: string[] = [];
		const { native } = await withRequire((id) => {
			asked.push(id);
			return standIn();
		});
		await native.loadNative();

		expect(native.isNativeLoaded()).toBe(true);
		expect(asked).toHaveLength(1);
		expect(asked[0]).toMatch(/index\.linux-x64-gnu\.node$/);
	});

	it("names the platform package to install when neither is there", async () => {
		const { sigil } = await withRequire((id) => {
			throw notFound(id);
		});

		const refusal = await refusalOf(sigil);

		expect(refusal).toBeInstanceOf(sigil.errors.E_SIGIL_NAPI_REQUIRED);
		expect(String(refusal)).toContain(
			`Fix: install ${PLATFORM_PACKAGE} at the exact version of @c9up/sigil`,
		);
		expect(String(refusal)).toContain("pnpm build:napi");
		// The load error travels as the cause, not in the message.
		expect(refusal).toMatchObject({
			cause: { code: "MODULE_NOT_FOUND" },
		});
		expect(String(refusal)).not.toContain("Cannot find module");
	});

	it("reports a local build that fails to load, instead of falling back to the package", async () => {
		const asked: string[] = [];
		const { sigil } = await withRequire((id) => {
			asked.push(id);
			throw new Error("invalid ELF header");
		});

		const refusal = await refusalOf(sigil);

		expect(asked).toHaveLength(1);
		expect(String(refusal)).toContain(
			"Fix: index.linux-x64-gnu.node failed to load. Rebuild it",
		);
		expect(refusal).toMatchObject({
			cause: { message: "invalid ELF header" },
		});
	});

	it("rejects a platform package from another version, naming it", async () => {
		const { native, vendor } = await withRequire((id) => {
			if (id === PLATFORM_PACKAGE) return standIn("scryptVerify");
			throw notFound(id);
		});
		await native.loadNative();

		expect(native.isNativeLoaded()).toBe(false);
		const attempt = vendor.loadNativeBinary(
			(value): value is object => vendor.hasFunctions(value, CALLS),
			CALLS,
			{ packageName: "@c9up/sigil" },
		);
		expect(attempt.loaded).toBe(false);
		if (attempt.loaded) return;
		expect(attempt.platformPackage).toBe(PLATFORM_PACKAGE);
		expect(String(attempt.cause)).toContain(
			`${PLATFORM_PACKAGE} loaded, but it lacks scryptVerify. The binary is stale or from another version: install the version the package that loads it pins.`,
		);
	});

	it("looks only at the local file when the package names no platform packages", async () => {
		const asked: string[] = [];
		const { vendor } = await withRequire((id) => {
			asked.push(id);
			throw notFound(id);
		});

		const attempt = vendor.loadNativeBinary(
			(value): value is object => vendor.hasFunctions(value, CALLS),
			CALLS,
		);

		expect(attempt.loaded).toBe(false);
		expect(asked).toHaveLength(1);
		if (attempt.loaded) return;
		expect(attempt.platformPackage).toBeUndefined();
	});

	it("lists the supported targets on a host no binary is built for", async () => {
		const asked: string[] = [];
		const { sigil } = await withRequire(
			(id) => {
				asked.push(id);
				return standIn();
			},
			{ platform: "linux", arch: "riscv64" },
		);

		const refusal = await refusalOf(sigil);

		expect(asked).toHaveLength(0);
		expect(String(refusal)).toContain(
			"Fix: no prebuilt binary for linux-riscv64; sigil ships one for linux-x64, linux-arm64, darwin-x64, darwin-arm64, win32-x64.",
		);
	});
});
