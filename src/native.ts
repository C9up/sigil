import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { arch, platform } from "node:process";
import { fileURLToPath } from "node:url";

export interface Argon2NativeOptions {
	memoryKib?: number;
	iterations?: number;
	parallelism?: number;
	/** Secret pepper — not stored in the hash; required identically at verify. */
	secret?: Buffer;
}

export interface ScryptNativeOptions {
	cost?: number;
	blockSize?: number;
	parallelization?: number;
	keyLength?: number;
	saltLength?: number;
}

interface NativeSigil {
	argon2Hash(password: string, options?: Argon2NativeOptions): string;
	argon2Verify(password: string, hash: string, secret?: Buffer): boolean;
	bcryptHash(password: string, rounds?: number): string;
	bcryptVerify(password: string, hash: string): boolean;
	scryptHash(password: string, options?: ScryptNativeOptions): string;
	scryptVerify(password: string, hash: string): boolean;
}

let native: NativeSigil | null = null;
let attempted = false;

export async function loadNative(): Promise<void> {
	// Cache both success (`native !== null`) and failure (`attempted === true`).
	// Without the failure cache, every consumer call would re-run `require()`
	// for an absent binary, triggering OS-level lookup churn.
	if (native || attempted) return;
	attempted = true;
	try {
		const req = createRequire(import.meta.url);
		const dir = dirname(fileURLToPath(import.meta.url));
		const platformMap: Record<string, string> = {
			"linux-x64": "linux-x64-gnu",
			"linux-arm64": "linux-arm64-gnu",
			"darwin-x64": "darwin-x64",
			"darwin-arm64": "darwin-arm64",
			"win32-x64": "win32-x64-msvc",
		};
		const suffix = platformMap[`${platform}-${arch}`];
		if (suffix) {
			native = req(join(dir, `../index.${suffix}.node`));
		}
	} catch {
		// Binary not loadable — `attempted` keeps subsequent calls O(1).
	}
}

export function isNativeLoaded(): boolean {
	return native !== null;
}

export function argon2Hash(
	password: string,
	options?: Argon2NativeOptions,
): string | null {
	return native?.argon2Hash(password, options) ?? null;
}

export function argon2Verify(
	password: string,
	hash: string,
	secret?: Buffer,
): boolean | null {
	return native?.argon2Verify(password, hash, secret) ?? null;
}

export function bcryptHash(password: string, rounds?: number): string | null {
	return native?.bcryptHash(password, rounds) ?? null;
}

export function bcryptVerify(password: string, hash: string): boolean | null {
	return native?.bcryptVerify(password, hash) ?? null;
}

export function scryptHash(
	password: string,
	options?: ScryptNativeOptions,
): string | null {
	return native?.scryptHash(password, options) ?? null;
}

export function scryptVerify(password: string, hash: string): boolean | null {
	return native?.scryptVerify(password, hash) ?? null;
}
