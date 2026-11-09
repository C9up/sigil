/**
 * A stored hash names its own cost, so it decides how much work verifying it
 * takes — and a stored hash is not necessarily one this application wrote.
 *
 * Measured before the caps: an argon2 hash rewritten to m=262144,t=8 took two
 * seconds per verify, a bcrypt one rewritten to $2b$16$ close to three, and a
 * scrypt one rewritten to n=262144 derived a 256 MiB working set, eight times
 * the configured maxMemory. Any anonymous client could replay that with a
 * wrong password, as often as it liked.
 *
 * Every driver now refuses, before deriving, a hash costing more than any real
 * configuration would; and a configuration costing more is refused when the
 * driver is built, since it would write hashes verify then refuses forever.
 */

import { describe, expect, it } from "vitest";
import { Hash } from "../../src/Hash.js";
import {
	ARGON2_DEFAULTS,
	MAX_ARGON2_WORK,
	MAX_BCRYPT_COST,
	MAX_SCRYPT_WORK,
} from "../../src/limits.js";
import { argon2Defaults, costLimits, loadNative } from "../../src/native.js";

function hasher(driver: string, config: Record<string, unknown> = {}) {
	return new Hash({
		default: driver,
		list: { [driver]: { ...config, driver } },
	});
}

/** Verify, and how long it took. */
async function timedVerify(
	hash: Hash,
	stored: string,
	value: string,
): Promise<{ ok: boolean; ms: number }> {
	const start = performance.now();
	const ok = await hash.verify(stored, value);
	return { ok, ms: performance.now() - start };
}

const FAST_MS = 50;

describe("sigil > a stored hash cannot name an unbounded cost", () => {
	it("argon2 refuses a hash rewritten to a far higher cost, before deriving", async () => {
		const hash = hasher("argon2", { memory: 1024, iterations: 2 });
		const stored = await hash.make("secret");
		const forged = stored.replace(/m=\d+,t=\d+/, "m=262144,t=8");

		const { ok, ms } = await timedVerify(hash, forged, "secret");

		expect(ok).toBe(false);
		expect(ms).toBeLessThan(FAST_MS);
	});

	it("bcrypt refuses a hash rewritten to a far higher cost, before deriving", async () => {
		const hash = hasher("bcrypt", { rounds: 10 });
		const stored = await hash.make("secret");

		for (const cost of ["17", "20", "31"]) {
			const forged = `${stored.slice(0, 4)}${cost}${stored.slice(6)}`;
			const { ok, ms } = await timedVerify(hash, forged, "secret");

			expect(ok).toBe(false);
			expect(ms).toBeLessThan(FAST_MS);
		}
	});

	it("scrypt refuses a hash whose working set exceeds maxMemory, before deriving", async () => {
		const hash = hasher("scrypt");
		const stored = await hash.make("secret");
		// n=2^18, r=8 is 256 MiB, eight times the default maxMemory of 32 MiB.
		const forged = stored.replace("n=16384", "n=262144");

		const { ok, ms } = await timedVerify(hash, forged, "secret");

		expect(ok).toBe(false);
		expect(ms).toBeLessThan(FAST_MS);
	});

	it("scrypt verifies a hash at exactly the configured cost", async () => {
		const hash = hasher("scrypt");
		const stored = await hash.make("secret");

		expect(await hash.verify(stored, "secret")).toBe(true);
	});

	it("scrypt applies the configured maxMemory to verify, not only to make", async () => {
		// 2^15 needs 32 MiB and a little more: over the default, under 64 MiB.
		const roomy = hasher("scrypt", {
			cost: 32768,
			maxMemory: 64 * 1024 * 1024,
		});
		const stored = await roomy.make("secret");

		expect(await roomy.verify(stored, "secret")).toBe(true);
		// The same hash under the default bound is refused, password and all.
		expect(await hasher("scrypt").verify(stored, "secret")).toBe(false);
	});
});

describe("sigil > a configuration above the caps fails at construction", () => {
	it("argon2 memory * iterations", () => {
		expect(() => hasher("argon2", { memory: 2 ** 19, iterations: 3 })).toThrow(
			/must not exceed/,
		);
		// A partial config is checked against the defaults it inherits.
		expect(() => hasher("argon2", { iterations: 20 })).toThrow(
			/must not exceed/,
		);
	});

	it("bcrypt rounds", () => {
		expect(() => hasher("bcrypt", { rounds: 17 })).toThrow(/rounds/);
		expect(() => hasher("bcrypt", { rounds: 16 })).not.toThrow();
	});

	it("scrypt cost * blockSize * parallelization", () => {
		expect(() =>
			hasher("scrypt", {
				cost: 2 ** 20,
				blockSize: 8,
				maxMemory: 2 ** 32 - 1,
			}),
		).toThrow(/must not exceed/);
	});
});

describe("sigil > the driver bounds are the engine's", () => {
	it("states the same caps and argon2 defaults the engine applies", async () => {
		await loadNative();

		expect(costLimits()).toEqual({
			maxArgon2Work: MAX_ARGON2_WORK,
			maxBcryptCost: MAX_BCRYPT_COST,
			maxScryptWork: MAX_SCRYPT_WORK,
		});
		expect(argon2Defaults()).toEqual({
			memoryKib: ARGON2_DEFAULTS.memory,
			iterations: ARGON2_DEFAULTS.iterations,
			parallelism: ARGON2_DEFAULTS.parallelism,
		});
	});
});
