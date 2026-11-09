/**
 * Hashing must not run on the event loop.
 *
 * Every make/verify used to call the engine synchronously behind an `async`
 * signature: the key derivation ran on the main thread, so N concurrent login
 * attempts froze the whole process for N times the KDF cost — no other
 * request, timer or socket was served, for anyone. Measured: eight bcrypt-12
 * verifies stalled the loop for 1351 ms straight.
 *
 * The engine now computes on the libuv thread pool. These tests watch the
 * loop while hashes are being verified: a timer must keep firing, and
 * concurrent verifies must overlap instead of queueing behind one another.
 */

import { describe, expect, it } from "vitest";
import { Hash } from "../../src/Hash.js";

function hasher(driver: string, config: Record<string, unknown> = {}) {
	return new Hash({
		default: driver,
		list: { [driver]: { ...config, driver } },
	});
}

/** Run `work` while a 5 ms interval measures the longest gap between ticks. */
async function worstLoopGap(work: () => Promise<unknown>): Promise<number> {
	let last = performance.now();
	let worst = 0;
	const timer = setInterval(() => {
		const now = performance.now();
		worst = Math.max(worst, now - last);
		last = now;
	}, 5);
	try {
		await work();
		// Let the timer observe the loop once more after the work settles.
		await new Promise((resolve) => setTimeout(resolve, 10));
	} finally {
		clearInterval(timer);
	}
	return worst;
}

async function timed(work: () => Promise<unknown>): Promise<number> {
	const start = performance.now();
	await work();
	return performance.now() - start;
}

describe.each([
	["argon2", {}],
	["bcrypt", { rounds: 12 }],
	["scrypt", {}],
])("sigil > %s runs off the event loop", (driver, config) => {
	it("keeps the event loop ticking during concurrent verifies", async () => {
		const hash = hasher(driver, config);
		const stored = await hash.make("correct horse battery staple");
		const single = await timed(() => hash.verify(stored, "guess"));

		const gap = await worstLoopGap(() =>
			Promise.all(
				Array.from({ length: 8 }, () => hash.verify(stored, "guess")),
			),
		);

		// On the main thread the loop stalled for all eight verifies; off it,
		// the timer keeps firing within a fraction of one verify.
		expect(gap).toBeLessThan(single);
	});

	it("overlaps concurrent verifies instead of queueing them", async () => {
		const hash = hasher(driver, config);
		const stored = await hash.make("correct horse battery staple");
		const single = await timed(() => hash.verify(stored, "guess"));
		const n = 4;

		const total = await timed(() =>
			Promise.all(
				Array.from({ length: n }, () => hash.verify(stored, "guess")),
			),
		);

		expect(total).toBeLessThan(n * single * 0.8);
	});

	it("still answers correctly from the thread pool", async () => {
		const hash = hasher(driver, config);
		const stored = await hash.make("correct horse battery staple");

		const answers = await Promise.all([
			hash.verify(stored, "correct horse battery staple"),
			hash.verify(stored, "wrong"),
			hash.verify(stored, "correct horse battery staple"),
		]);

		expect(answers).toEqual([true, false, true]);
	});
});
