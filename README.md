# @c9up/sigil

> Canonical password hashing for the Ream ecosystem.

Multi-driver password hashing service backed by Rust NAPI. Built on the same model as `@adonisjs/hash` (v9): pluggable drivers, a single `Hash` class, fluent verification.

## Drivers

| Driver key | Algorithm | When to use |
|---|---|---|
| `argon2` *(default)* | argon2id | New applications. Memory-hard, side-channel resistant, OWASP-recommended for password storage. Pinned to the **argon2id** variant (V0x13). Tunable via config: `memory` (KiB, alias `memoryKib`), `iterations`, `parallelism`, and `secret` (a "pepper" not encoded in the hash — verification requires the same secret). |
| `bcrypt` | bcrypt | Interoperating with legacy systems (Rails, PHP, Java) that already store bcrypt hashes. `rounds` is configurable (default 12, OWASP minimum 10). Emits the standard `$2b$` MCF string, which `@adonisjs/hash` also accepts on verify. |
| `scrypt` | scrypt | Memory-hardness with a different parameter space than argon2. Work factor configurable via config: `cost` (N, default 16384), `blockSize` (r, default 8), `parallelization` (p, default 1), plus `keyLength`, `saltSize`, and a `maxMemory` guard. Emits the `@adonisjs/hash`-compatible PHC form `$scrypt$n=…,r=…,p=…$<b64 salt>$<b64 hash>`, so scrypt hashes cross-verify with AdonisJS. |

All drivers run through the dedicated `sigil-engine` Rust crate (the native half of `@c9up/sigil`) — no JavaScript or TypeScript fallback. This is intentional: password hashing must hit a vetted, constant-time native implementation.

## NAPI binding requirement

Sigil requires its native binding to be present at runtime. If the `.node` artifact is missing, the first call to `make()` / `verify()` throws:

```text
[SIGIL_NAPI_REQUIRED] The argon2 Rust engine is required but not loaded.
  Fix: cd packages/sigil && pnpm build:napi
```

The `argon2` token in the message is interpolated with the failing driver name (`argon2` / `bcrypt` / `scrypt`).

> The `pnpm build:napi` script is wired in story 40.4. Until then, build the native binding manually with `cargo build --release -p sigil-engine` from the package root.

Story 40.4 will harden runtime detection and ship prebuilt binaries via the same CI matrix as Ream and Atlas (linux-x64-gnu, linux-arm64-gnu, darwin-x64, darwin-arm64, win32-x64-msvc), so a fresh `pnpm install` will resolve the binding without a local Rust toolchain.

## Quick start

`Hash` is a class — instantiate it with a config:

```ts
import { Hash } from '@c9up/sigil'

const hash = new Hash({
  default: 'argon2',
  drivers: {
    argon2: { driver: 'argon2' },
  },
})

const hashed = await hash.make('correct horse battery staple')
// verify(hash, value) — hash FIRST, then the plaintext (AdonisJS arg order).
const ok = await hash.verify(hashed, 'correct horse battery staple')
// ok === true
```

In a Ream application, register `SigilProvider` and resolve `Hash` from the container instead of constructing it manually:

```ts
// providers.ts
import SigilProvider from '@c9up/sigil/provider' // default export
export default [SigilProvider]
```

```ts
// in a controller / handler
import type { AppContext } from '@c9up/ream'
import { Hash } from '@c9up/sigil'

async function register(app: AppContext) {
  const hash = app.container.resolve<Hash>(Hash)
  const stored = await hash.make(password)
}
```

Switch driver per call:

```ts
const bcryptDriver = hash.use('bcrypt')
const bcryptHashed = await bcryptDriver.make('password')

const scryptHashed = await hash.use('scrypt').make('password')
```

`hash.use(name)` returns a `HashDriver` whose `make` / `verify` methods run against the named driver.

## Configuration

The default driver and per-driver options are declared via `defineConfig`:

```ts
// config/hash.ts
import { defineConfig } from '@c9up/sigil'

export default defineConfig({
  default: 'argon2',
  drivers: {
    argon2: { driver: 'argon2' },
    bcrypt: { driver: 'bcrypt', rounds: 12 },
    scrypt: { driver: 'scrypt', keyLength: 64, saltLength: 32 },
  },
})
```

Honored config keys (anything else is silently ignored today):

- `argon2` — `memory` (KiB), `iterations`, `parallelism`, and `secret` (keyed hashing; a UTF-8 string). Omitted keys fall back to the Rust binding's defaults.
- `bcrypt` — `rounds: number` (default 12, minimum 10).
- `scrypt` — `cost` (N, default 16384), `blockSize` (r, default 8), `parallelization` (p, default 1), `keyLength` (default 64), `saltLength` (default 32), `maxMemory`.

When `SigilProvider` boots without a `config/hash.ts`, the fallback is `argon2` with the recommended defaults — see Story 40.1's `SigilProvider` fix.

## Why Sigil and not `@c9up/ream`?

Epic 40 declares Sigil the canonical password-hashing package for Ream:

- **Adonis-pattern parity.** Adonis isolates hashing in `@adonisjs/hash`, separate from the framework core. Sigil mirrors that boundary.
- **Single implementation.** Before Sigil, password hashing existed in `@c9up/ream/security/crypto` and (later) in `@c9up/warden`'s internal binding. Two NAPI argon2 implementations in one workspace was duplication waiting for divergence. Sigil consolidates.
- **Cleaner dependency graph.** Apps that need only password hashing (e.g., a CLI tool) can depend on `@c9up/sigil` alone, without pulling in the full Ream framework.

## Migration from `@c9up/ream/security/crypto`

`@c9up/ream/security/crypto` no longer exports password hashing. Earlier in development it carried throwing stubs (`argon2Hash`, `argon2Verify`, `bcryptHash`, `bcryptVerify`); story 40.1 removed them since they were never publicly available. The single canonical import is now Sigil:

```diff
- import { argon2Hash, argon2Verify } from '@c9up/ream/security/crypto'
+ import { Hash } from '@c9up/sigil'

- const hashed = await argon2Hash(password)
- const ok = await argon2Verify(password, hashed)
+ const hash = new Hash({ default: 'argon2', drivers: { argon2: { driver: 'argon2' } } })
+ const hashed = await hash.make(password)
+ const ok = await hash.verify(hashed, password) // verify(hash, value)
```

In a Ream application, prefer the container-resolved `Hash` (see Quick start) over constructing one inline.

## Migration from `@c9up/warden`'s internal hash

`@c9up/warden` historically exposed `hashPasswordArgon2` / `verifyPasswordArgon2` / `hashPasswordBcrypt` / `verifyPasswordBcrypt` on its `NativeWarden` interface — they were never wired into `SessionStrategy` (which delegates password verification to the caller; see `SessionStrategy.ts:33-37`) and had zero TS callers in the workspace. Story 40.3 removed them from the TS surface. The underlying Rust crate still ships those functions in the prebuilt `.node` artefact (a follow-up hardening story tracks their removal). If your application ever called them directly, switch to Sigil's `Hash` class.

## Public API

| Export | Type | Purpose |
|---|---|---|
| `Hash` | class | `new Hash(config)`. Instance methods: `make(value)`, `verify(hash, value)`, `use(name?)`. |
| `HashDriver` | interface | Implement to plug a custom driver. Required: `make`, `verify`. Returned by `Hash.prototype.use(name)`. |
| `HashConfig` | type | `{ default: string; drivers: Record<string, { driver: string; ...}> }`. |
| `defineConfig` | helper | Type-safe config authoring. |
| `SigilProvider` | provider | Registers `Hash` (and the `'hash'` token) in the Ream container. Imported via `@c9up/sigil/provider`. |

## Status

- argon2id, bcrypt, scrypt drivers — shipping.
- README + module docs (this story 40.1).
- Warden integration — story 40.3.
- NAPI binary CI matrix — story 40.4.

> Story 40.2 (originally scoped as "ream/crypto delegates to Sigil") is being re-evaluated: 40.1 deleted the throwing stubs in `@c9up/ream/security/crypto.ts` outright since they were never deployed, so there is no facade to wire. Note this is independent from `@c9up/warden`'s duplicate argon2 path, which story 40.3 still addresses.

## License

MIT
