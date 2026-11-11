import { describe, expect, it } from "vitest";
import { Hash } from "../../src/index.js";

describe("sigil > Hash", () => {
	it("the default hasher is the one `default` names, under either spelling", () => {
		for (const key of ["list", "drivers"] as const) {
			const hash = new Hash({
				default: "scrypt",
				[key]: { scrypt: { driver: "scrypt" } },
			});
			expect(hash.isValidHash("$scrypt$n=16384,r=8,p=1$c2FsdA$aGFzaA")).toBe(
				true,
			);
			expect(hash.isValidHash("$argon2id$v=19$m=65536,t=3,p=4$a$b")).toBe(
				false,
			);
		}
	});

	it("throws on unknown driver", () => {
		const hash = new Hash({
			default: "unknown",
			drivers: {},
		});
		expect(() => hash.use("unknown")).toThrow("not configured");
	});

	it("every driver hashes through the engine and verifies its own hash", async () => {
		// No branch on whether the binary loaded: a missing or rejected engine
		// must fail this test, not take a path that asserts nothing about
		// hashing. The refusal itself is pinned in native-guard.test.ts, with
		// the loader stubbed.
		const drivers = [
			{ name: "argon2", config: { driver: "argon2" } },
			{ name: "bcrypt", config: { driver: "bcrypt", rounds: 10 } },
			{ name: "scrypt", config: { driver: "scrypt" } },
		];

		for (const { name, config } of drivers) {
			const hash = new Hash({ default: name, drivers: { [name]: config } });
			const out = await hash.make("test");
			expect(hash.isValidHash(out), name).toBe(true);
			expect(await hash.verify(out, "test"), name).toBe(true);
			expect(await hash.verify(out, "wrong"), name).toBe(false);
		}
	});

	it("use() returns a specific driver", () => {
		const hash = new Hash({
			default: "argon2",
			drivers: {
				argon2: { driver: "argon2" },
				bcrypt: { driver: "bcrypt" },
				scrypt: { driver: "scrypt" },
			},
		});
		const stored = {
			argon2: "$argon2id$v=19$m=65536,t=3,p=4$a$b",
			bcrypt: `$2b$12$${"a".repeat(53)}`,
			scrypt: "$scrypt$n=16384,r=8,p=1$c2FsdA$aGFzaA",
		};
		for (const name of ["argon2", "bcrypt", "scrypt"] as const) {
			const hasher = hash.use(name);
			// Each name resolves to its own driver: it recognises its own format
			// and no other.
			for (const [format, value] of Object.entries(stored)) {
				expect(hasher.isValidHash(value), `${name} on ${format}`).toBe(
					format === name,
				);
			}
			// And the hasher is built once per name.
			expect(hash.use(name)).toBe(hasher);
		}
	});

	it("argon2 driver honors custom memoryKib/iterations/parallelism", async () => {
		const hardened = new Hash({
			default: "argon2",
			drivers: {
				argon2: {
					driver: "argon2",
					memoryKib: 32 * 1024,
					iterations: 3,
					parallelism: 2,
				},
			},
		});
		const out = await hardened.make("password");
		// The argon2 PHC string encodes the params used at hash time.
		expect(out).toContain("m=32768");
		expect(out).toContain("t=3");
		expect(out).toContain("p=2");
		expect(await hardened.verify(out, "password")).toBe(true);
	});

	it("rejects passwords exceeding max bytes", async () => {
		for (const driver of ["argon2", "bcrypt", "scrypt"]) {
			const hash = new Hash({
				default: driver,
				drivers: { [driver]: { driver } },
			});
			const longPassword = "a".repeat(2000);
			await expect(hash.make(longPassword)).rejects.toThrow("maximum length");
		}
	});

	describe("bcrypt 72-byte boundary", () => {
		// Bcrypt silently truncates inputs past 72 bytes — two distinct
		// passphrases sharing a 72-byte prefix would otherwise hash
		// identically. The driver must reject 73+ byte inputs before they
		// reach the Rust binding. 71 and 72 must still be hashed, and verify.
		const make = (driver: string) =>
			new Hash({
				default: driver,
				drivers: { [driver]: { driver } },
			});

		it("accepts 71 bytes", async () => {
			const hash = make("bcrypt");
			const out = await hash.make("a".repeat(71));
			expect(await hash.verify(out, "a".repeat(71))).toBe(true);
		});

		it("accepts exactly 72 bytes", async () => {
			const hash = make("bcrypt");
			const out = await hash.make("a".repeat(72));
			expect(await hash.verify(out, "a".repeat(72))).toBe(true);
		});

		it("rejects 73 bytes with a bcrypt-specific message", async () => {
			const hash = make("bcrypt");
			await expect(hash.make("a".repeat(73))).rejects.toThrow(/Bcrypt/);
		});

		it("argon2 accepts the same 73-byte input that bcrypt rejects", async () => {
			const hash = make("argon2");
			const out = await hash.make("a".repeat(73));
			expect(await hash.verify(out, "a".repeat(73))).toBe(true);
		});
	});

	describe("needsReHash (param/algo drift — pure parse, no native)", () => {
		it("argon2: false when params match, true when they drift or algo differs", () => {
			const h = new Hash({
				default: "argon2",
				drivers: {
					argon2: {
						driver: "argon2",
						memoryKib: 65536,
						iterations: 3,
						parallelism: 4,
					},
				},
			});
			expect(h.needsReHash("$argon2id$v=19$m=65536,t=3,p=4$abc$def")).toBe(
				false,
			);
			expect(h.needsReHash("$argon2id$v=19$m=19456,t=2,p=1$abc$def")).toBe(
				true,
			);
			expect(h.needsReHash(`$2b$12$${"x".repeat(53)}`)).toBe(true); // bcrypt under argon driver
		});

		it("bcrypt: compares the cost factor to the configured rounds", () => {
			const h = new Hash({
				default: "bcrypt",
				drivers: { bcrypt: { driver: "bcrypt", rounds: 12 } },
			});
			expect(h.needsReHash(`$2b$12$${"x".repeat(53)}`)).toBe(false);
			expect(h.needsReHash(`$2b$10$${"x".repeat(53)}`)).toBe(true);
		});

		it("bcrypt: compares the version letter to the configured version", () => {
			const tail = `$12$${"x".repeat(53)}`;
			const withVersion = (version?: number) =>
				new Hash({
					default: "bcrypt",
					drivers: {
						bcrypt:
							version === undefined
								? { driver: "bcrypt", rounds: 12 }
								: { driver: "bcrypt", rounds: 12, version },
					},
				});

			// Default 98 writes `$2b$`: a `$2a$` or `$2y$` hash at the same cost
			// is not what it would write, so it migrates.
			expect(withVersion().needsReHash(`$2b${tail}`)).toBe(false);
			expect(withVersion().needsReHash(`$2a${tail}`)).toBe(true);
			expect(withVersion().needsReHash(`$2y${tail}`)).toBe(true);
			expect(withVersion(97).needsReHash(`$2a${tail}`)).toBe(false);
			expect(withVersion(97).needsReHash(`$2b${tail}`)).toBe(true);
			expect(withVersion(121).needsReHash(`$2y${tail}`)).toBe(false);
		});

		it("scrypt: false when n/r/p match, true when they drift or algo differs", () => {
			const h = new Hash({
				default: "scrypt",
				drivers: {
					scrypt: {
						driver: "scrypt",
						cost: 16384,
						blockSize: 8,
						parallelization: 1,
					},
				},
			});
			expect(h.needsReHash("$scrypt$n=16384,r=8,p=1$abc$def")).toBe(false);
			expect(h.needsReHash("$scrypt$n=1024,r=8,p=1$abc$def")).toBe(true);
			expect(h.needsReHash("$scrypt$n=16384,r=16,p=1$abc$def")).toBe(true);
			// Legacy `scrypt$ln=` form (no leading $) and other algos → re-hash.
			expect(h.needsReHash("scrypt$ln=14$r=8$p=1$aa$bb")).toBe(true);
			expect(h.needsReHash("$argon2id$v=19$m=65536,t=3,p=4$abc$def")).toBe(
				true,
			);
		});
	});

	describe("isValidHash (format check — pure, no native)", () => {
		const make = (driver: string) =>
			new Hash({ default: driver, drivers: { [driver]: { driver } } });

		it("argon2 accepts $argon2(id|i|d)$ and rejects others", () => {
			const h = make("argon2");
			expect(h.isValidHash("$argon2id$v=19$m=65536,t=3,p=4$abc$def")).toBe(
				true,
			);
			expect(h.isValidHash("$argon2i$v=19$m=65536,t=3,p=4$abc$def")).toBe(true);
			expect(h.isValidHash(`$2b$12$${"x".repeat(53)}`)).toBe(false);
			expect(h.isValidHash("plain")).toBe(false);
		});

		it("bcrypt accepts $2[aby]$NN$ and rejects others", () => {
			const h = make("bcrypt");
			expect(h.isValidHash(`$2b$12$${"x".repeat(53)}`)).toBe(true);
			expect(h.isValidHash(`$2a$10$${"x".repeat(53)}`)).toBe(true);
			expect(h.isValidHash("$argon2id$v=19$m=1,t=1,p=1$a$b")).toBe(false);
		});

		it("scrypt accepts the PHC $scrypt$n=...,r=...,p=...$ form", () => {
			const h = make("scrypt");
			expect(h.isValidHash("$scrypt$n=16384,r=8,p=1$abc$def")).toBe(true);
			expect(h.isValidHash("scrypt$ln=14$r=8$p=1$aa$bb")).toBe(false);
			expect(h.isValidHash("nope")).toBe(false);
		});

		it("use() exposes isValidHash on the returned Hasher (chaining parity)", () => {
			const h = make("bcrypt");
			expect(h.use("bcrypt").isValidHash(`$2b$12$${"x".repeat(53)}`)).toBe(
				true,
			);
		});
	});

	describe("fake() / restore()", () => {
		it("make is identity and verify is string equality while faked", async () => {
			const h = new Hash({
				default: "argon2",
				drivers: { argon2: { driver: "argon2" } },
			});
			h.fake();
			expect(await h.make("secret")).toBe("secret");
			expect(await h.verify("secret", "secret")).toBe(true);
			expect(await h.verify("secret", "other")).toBe(false);
			expect(h.needsReHash("secret")).toBe(false);
			expect(h.isValidHash("anything")).toBe(true);
			h.restore();
		});

		it("[Symbol.dispose] auto-restores real drivers at scope exit", async () => {
			const h = new Hash({
				default: "argon2",
				drivers: { argon2: { driver: "argon2" } },
			});
			{
				using _guard = h.fake();
				expect(await h.make("secret")).toBe("secret");
			}
			// After dispose, the fake is gone — argon2 no longer returns identity.
			const out = await h.make("secret");
			expect(out).not.toBe("secret");
			expect(out.startsWith("$argon2id$")).toBe(true);
			expect(await h.verify(out, "secret")).toBe(true);
		});
	});

	describe("assertEquals / assertNotEquals (node:assert AssertionError)", () => {
		// Use the fake driver so these run without the native binary.
		const faked = () => {
			const h = new Hash({
				default: "argon2",
				drivers: { argon2: { driver: "argon2" } },
			});
			h.fake();
			return h;
		};

		it("assertEquals resolves on a match, throws AssertionError otherwise", async () => {
			const h = faked();
			await expect(h.assertEquals("secret", "secret")).resolves.toBeUndefined();
			await expect(h.assertEquals("secret", "wrong")).rejects.toMatchObject({
				name: "AssertionError",
			});
		});

		it("assert error messages never leak the plaintext value (log-safety)", async () => {
			const h = faked();
			const secret = "s3cr3t-p4ssw0rd";
			const eqErr: unknown = await h
				.assertEquals("stored-hash", secret)
				.catch((e: unknown) => e);
			const neqErr: unknown = await h
				.assertNotEquals(secret, secret)
				.catch((e: unknown) => e);
			for (const err of [eqErr, neqErr]) {
				const msg = err instanceof Error ? err.message : String(err);
				expect(msg).not.toContain(secret);
			}
		});

		it("assertNotEquals resolves on a mismatch, throws AssertionError otherwise", async () => {
			const h = faked();
			await expect(
				h.assertNotEquals("secret", "wrong"),
			).resolves.toBeUndefined();
			await expect(h.assertNotEquals("secret", "secret")).rejects.toMatchObject(
				{ name: "AssertionError" },
			);
		});

		it("use() exposes assertEquals on the returned Hasher (chaining parity)", async () => {
			const h = faked();
			await expect(
				h.use("argon2").assertEquals("secret", "secret"),
			).resolves.toBeUndefined();
		});
	});

	describe("argon2 secret (pepper) + memory alias", () => {
		it("a peppered hash only verifies with the same secret", async () => {
			const withSecret = new Hash({
				default: "argon2",
				drivers: { argon2: { driver: "argon2", secret: "pepper-key" } },
			});
			const other = new Hash({
				default: "argon2",
				drivers: { argon2: { driver: "argon2", secret: "different-key" } },
			});
			const plain = new Hash({
				default: "argon2",
				drivers: { argon2: { driver: "argon2" } },
			});
			const digest = await withSecret.make("hunter2");
			expect(digest.startsWith("$argon2")).toBe(true); // secret not encoded
			expect(await withSecret.verify(digest, "hunter2")).toBe(true);
			expect(await other.verify(digest, "hunter2")).toBe(false);
			expect(await plain.verify(digest, "hunter2")).toBe(false);
		});

		it("`memory` (Adonis name) drives the encoded param like `memoryKib`", async () => {
			const h = new Hash({
				default: "argon2",
				drivers: {
					argon2: { driver: "argon2", memory: 32 * 1024, iterations: 3 },
				},
			});
			const out = await h.make("password");
			expect(out).toContain("m=32768");
			expect(out).toContain("t=3");
			// needsReHash reads the `memory` alias into memoryKib for comparison.
			expect(h.needsReHash(out)).toBe(false);
			expect(h.needsReHash("$argon2id$v=19$m=19456,t=2,p=1$a$b")).toBe(true);
		});
	});

	describe("scrypt configurable work factor", () => {
		it("honors cost/blockSize/parallelization and round-trips", async () => {
			const h = new Hash({
				default: "scrypt",
				drivers: {
					scrypt: {
						driver: "scrypt",
						cost: 1024,
						blockSize: 8,
						parallelization: 2,
					},
				},
			});
			const out = await h.make("password");
			expect(out.startsWith("$scrypt$n=1024,r=8,p=2$")).toBe(true);
			expect(await h.verify(out, "password")).toBe(true);
			expect(await h.verify(out, "wrong")).toBe(false);
			// Same params → no re-hash; a differently-configured driver → re-hash.
			expect(h.needsReHash(out)).toBe(false);
			const stronger = new Hash({
				default: "scrypt",
				drivers: { scrypt: { driver: "scrypt", cost: 16384 } },
			});
			expect(stronger.needsReHash(out)).toBe(true);
		});

		it("rejects a maxMemory smaller than the working set, at construction", () => {
			expect(
				() =>
					new Hash({
						default: "scrypt",
						drivers: {
							scrypt: {
								driver: "scrypt",
								cost: 16384,
								blockSize: 8,
								maxMemory: 1024,
							},
						},
					}),
			).toThrow(/maxMemory/);
		});
	});
});
