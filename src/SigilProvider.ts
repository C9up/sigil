import "./augmentations.js";
import type { HashConfig } from "./Hash.js";
import { Hash } from "./Hash.js";
import { setHash } from "./services/main.js";

/**
 * Duck-typed host context — sigil stays publishable without importing
 * `@c9up/ream`. Any framework that exposes a Container + a config
 * store satisfies the contract.
 */
interface SigilContainer {
	singleton(token: unknown, factory: () => unknown): void;
	resolve<T = unknown>(token: unknown): Promise<T>;
}
interface SigilConfigStore {
	get<T = unknown>(key: string): T | undefined;
}
export interface SigilAppContext {
	container: SigilContainer;
	config: SigilConfigStore;
}

export default class SigilProvider {
	constructor(protected app: SigilAppContext) {}

	register() {
		this.app.container.singleton(Hash, () => {
			const config = this.app.config.get<HashConfig>("hash");
			// Default to argon2 (argon2id under the hood) — matches the documented
			// canonical default. Was scrypt previously, which silently mismatched
			// every doc surface and turned into a security footgun (apps that
			// forgot to ship config/hash.ts would store scrypt hashes while the
			// docs promised argon2id).
			return new Hash(
				config ?? {
					default: "argon2",
					list: { argon2: { driver: "argon2" } },
				},
			);
		});
		this.app.container.singleton("hash", async () => {
			return await this.app.container.resolve<Hash>(Hash);
		});
	}

	async boot() {
		setHash(await this.app.container.resolve<Hash>(Hash));
	}

	async shutdown() {}
}
