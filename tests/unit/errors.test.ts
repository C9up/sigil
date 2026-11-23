import { Exception } from "@c9up/flare";
import { describe, expect, it } from "vitest";
import { errors } from "../../src/index.js";

describe("errors", () => {
	it("are exported as one namespace of flare exceptions", () => {
		const error = new errors.E_SIGIL_UNKNOWN_HASHER([
			"main",
			"The config declares none.",
		]);
		expect(error).toBeInstanceOf(Exception);
		expect(error).toMatchObject({
			code: "E_SIGIL_UNKNOWN_HASHER",
			status: 500,
			message:
				'[E_SIGIL_UNKNOWN_HASHER] No hasher named "main" is declared in the hash config. The config declares none.',
		});
	});
});
