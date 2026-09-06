import { describe, expect, it } from "vitest";
import { Hash } from "../../src/index.js";
import type { SigilAppContext } from "../../src/SigilProvider.js";
import SigilProvider from "../../src/SigilProvider.js";

/**
 * A stopped application must not leave a live hasher behind.
 *
 * The singleton is a module-level cell, so `import hash from
 * '@c9up/sigil/services/main'` kept answering with the hasher of an
 * application that had shut down — and with two applications in one process,
 * whichever booted last owned the cell for both.
 */

/** A container stub that caches, because `singleton` is the point. */
function buildApp(): SigilAppContext {
	const factories = new Map<unknown, () => unknown>();
	const built = new Map<unknown, unknown>();
	return {
		container: {
			singleton(token: unknown, factory: () => unknown) {
				factories.set(token, factory);
			},
			async resolve<T = unknown>(token: unknown): Promise<T> {
				if (!built.has(token)) built.set(token, await factories.get(token)?.());
				return built.get(token) as T;
			},
		},
		config: { get: () => undefined },
	};
}

describe("SigilProvider > shutdown", () => {
	it("releases the services/main singleton it bound", async () => {
		const { getHash } = await import("../../src/services/main.js");
		const provider = new SigilProvider(buildApp());
		provider.register();
		await provider.boot();
		expect(getHash()).toBeInstanceOf(Hash);

		await provider.shutdown();

		expect(getHash()).toBeUndefined();
	});

	it("leaves a hasher another application has since bound alone", async () => {
		const { getHash } = await import("../../src/services/main.js");
		const provider = new SigilProvider(buildApp());
		provider.register();
		await provider.boot();

		const other = new SigilProvider(buildApp());
		other.register();
		await other.boot();
		const replacement = getHash();
		if (!replacement) throw new Error("expected the second boot to bind one");

		await provider.shutdown();

		expect(getHash()).toBe(replacement);
	});
});
