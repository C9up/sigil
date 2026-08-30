/**
 * `ream configure @c9up/sigil` — wire password hashing in one command.
 *
 * The provider alone is not enough: it reads `config/hash.ts`, and a package
 * registered without one falls back to a default that is rarely the one an
 * application wants. Writing both together is what makes `ream add` mean
 * installed AND working.
 */

interface Codemods {
	addProvider(importPath: string): Promise<void>;
	writeFile(
		filePath: string,
		content: string,
		options?: { force?: boolean },
	): Promise<void>;
}

export async function configure(codemods: Codemods): Promise<void> {
	await codemods.addProvider("@c9up/sigil/provider");
	await codemods.writeFile(
		"config/hash.ts",
		`import { defineConfig, drivers } from '@c9up/sigil'
import env from '#start/env'

export default defineConfig({
  // argon2id unless there is a reason: it is the one that costs an attacker
  // memory as well as time.
  default: env.get('HASH_DRIVER', 'argon2'),

  list: {
    argon2: drivers.argon2(),
    // bcrypt: drivers.bcrypt({ rounds: 12 }),
  },
})`,
	);
}
