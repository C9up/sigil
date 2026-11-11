# @c9up/sigil

> Canonical password hashing for the Ream ecosystem.

Multi-driver password hashing service backed by Rust NAPI. Built on the same model as `@adonisjs/hash` (v9): pluggable drivers, a single `Hash` class, fluent verification.

`ream add @c9up/sigil` installs it, registers the provider and writes
`config/hash.ts`. The rest of this page assumes that has run.

## Drivers

| Driver key | Algorithm | When to use |
|---|---|---|
| `argon2` *(default)* | argon2id | New applications. Memory-hard, side-channel resistant, OWASP-recommended for password storage. Defaults to **argon2id** (version 19), 64 MiB, 3 iterations, 4 lanes. Tunable via config: `variant`, `memory` (KiB, alias `memoryKib`), `iterations`, `parallelism`, `saltSize`, `hashLength`, and `secret` (a "pepper" not encoded in the hash — verification requires the same secret). |
| `bcrypt` | bcrypt | Interoperating with legacy systems (Rails, PHP, Java) that already store bcrypt hashes. `rounds` is configurable (default 12, minimum 10, maximum 16). Writes the standard MCF string (`$2b$12$…`), the form every bcrypt implementation reads. Verify also reads the PHC form `$bcrypt$v=98$r=10$<b64 salt>$<b64 digest>` that `@adonisjs/hash` stores; `needsReHash` answers true for it, so such a hash is rewritten as MCF on the user's next login. |
| `scrypt` | scrypt | Memory-hardness with a different parameter space than argon2. Work factor configurable via config: `cost` (N, default 16384), `blockSize` (r, default 8), `parallelization` (p, default 1), plus `keyLength` (64 to 128), `saltSize`, and `maxMemory` (default 32 MiB), which bounds verify as well as make. Writes the PHC form `$scrypt$n=…,r=…,p=…$<b64 salt>$<b64 hash>`, the one `@adonisjs/hash` writes too, so scrypt hashes verify in both directions. |

All drivers run through the dedicated `sigil-engine` Rust crate (the native half of `@c9up/sigil`) — no JavaScript or TypeScript fallback. This is intentional: password hashing must hit a vetted, constant-time native implementation.

`make` and `verify` return Promises, and the key derivation runs on the libuv thread pool, never on the event loop: a burst of concurrent logins slows those logins down, not every other request the process is serving. Concurrent derivations share the pool's threads (4 by default, `UV_THREADPOOL_SIZE` to change it).

### Verify cost limits

A hash carries its own cost, so whoever can write a stored hash decides how much work verifying it takes. `verify` refuses — returns `false` without deriving — a stored hash costing far more than any real configuration:

| Driver | Refused when |
|---|---|
| `argon2` | `m × t` (KiB × iterations) exceeds 2^20, about five times the defaults |
| `bcrypt` | the cost exceeds 16 |
| `scrypt` | `N × r × p` exceeds 2^22, or the working set `128 × r × (N + p + 2)` exceeds the configured `maxMemory` |

The same limits apply to the configuration: a driver configured above them throws when it is built, since its hashes would never verify.

## NAPI binding requirement

Sigil requires its native binding to be present at runtime. If the `.node` artifact is missing, the first call to `make()` / `verify()` throws `E_SIGIL_NAPI_REQUIRED` (`error.code === 'E_SIGIL_NAPI_REQUIRED'`):

```text
[E_SIGIL_NAPI_REQUIRED] The argon2 Rust engine is required but not loaded.
  Fix: cd packages/sigil && pnpm build:napi
```

The `argon2` token in the message is interpolated with the failing driver name (`argon2` / `bcrypt` / `scrypt`).

The published package ships prebuilt binaries for linux-x64-gnu, linux-arm64-gnu, darwin-x64, darwin-arm64 and win32-x64-msvc, so an install needs no Rust toolchain. Build it locally with `pnpm build:napi` from the package root.

## Quick start

`Hash` is a class — instantiate it with a config:

```ts
import { Hash } from '@c9up/sigil'

const hash = new Hash({
  default: 'argon2',
  list: {
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
  list: {
    argon2: { driver: 'argon2' },
    bcrypt: { driver: 'bcrypt', rounds: 12 },
    scrypt: { driver: 'scrypt', keyLength: 64, saltLength: 32 },
  },
})
```

Honored config keys. Every value is validated when the driver is built — at boot — and a value out of range or of the wrong type (`rounds: '12'` read from an environment variable) throws a `TypeError` there rather than at the first hash:

- `argon2` — `variant` (`'id'` default, `'i'`, `'d'`), `memory` (KiB, default 65536, at least 8 × `parallelism`), `iterations` (default 3, at least 2), `parallelism` (default 4), `saltSize` (8 to 48, default 16), `hashLength` (10 to 64, default 32), and `secret` (keyed hashing: a string, or a `Secret` such as `env.get('APP_KEY')` returns).
- `bcrypt` — `rounds` (10 to 16, default 12), `version` (`97` for `$2a$`, `98` for `$2b$` — the default — or `121` for `$2y$`), `saltSize` (16 only: the algorithm fixes it).
- `scrypt` — `cost` (N, a power of two, default 16384), `blockSize` (r, default 8), `parallelization` (p, default 1), `keyLength` (64 to 128, default 64), `saltSize` (alias `saltLength`, 8 to 1024, default 16), `maxMemory` (bytes, default 32 MiB, at least the working set `128 × r × (N + p + 2)`).

```ts
import { defineConfig, drivers } from '@c9up/sigil'
import env from '#start/env'

export default defineConfig({
  default: 'argon2',
  list: {
    argon2: drivers.argon2({ secret: env.get('APP_KEY') }),
  },
})
```

When `SigilProvider` boots without a `config/hash.ts`, the fallback is `argon2` with the recommended defaults.

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
+ const hash = new Hash({ default: 'argon2', list: { argon2: { driver: 'argon2' } } })
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
| `HashConfig` | type | `{ default: string; list: Record<string, { driver: string; ...}> }` (`drivers` is the older spelling of `list`). |
| `defineConfig` | helper | Type-safe config authoring. |
| `SigilProvider` | provider | Registers `Hash` (and the `'hash'` token) in the Ream container. Imported via `@c9up/sigil/provider`. |
| `SigilError` | class | Base of every error sigil raises; `error.code` is the `E_SIGIL_*` name of the subclass. |
| `E_SIGIL_NAPI_REQUIRED` | class | A driver ran without the native engine loaded. |
| `E_SIGIL_UNKNOWN_DRIVER` | class | A hasher in the config names a driver sigil does not have; thrown when `Hash` is built. |
| `E_SIGIL_NOT_BOOTED` | class | `@c9up/sigil/services/main` used before `SigilProvider` booted. |

## Status

- argon2id, bcrypt, scrypt drivers — shipping.
- Prebuilt native binaries for the five platforms listed above — shipping.

## License

MIT
