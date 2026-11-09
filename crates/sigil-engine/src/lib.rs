use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use base64::{
    alphabet,
    engine::general_purpose::{GeneralPurpose, NO_PAD, STANDARD_NO_PAD},
    Engine as _,
};
use password_hash::phc::Salt;

const MAX_PASSWORD_BYTES: usize = 1024;
const BCRYPT_MAX_BYTES: usize = 72;
const BCRYPT_MIN_COST: u32 = 10;

/// Bcrypt's own base64 alphabet (`./A-Za-z0-9`), unpadded — the encoding of the
/// salt and digest inside a `$2b$` string.
const BCRYPT_B64: GeneralPurpose = GeneralPurpose::new(&alphabet::BCRYPT, NO_PAD);

/// The Argon2 cost a hash gets when the application configures none: argon2id,
/// 64 MiB, 3 passes, 4 lanes — the defaults of `@adonisjs/hash`, so a hash
/// written by an application migrated from it is not re-hashed DOWNWARD on the
/// next login (the crate's own default, m=19456 t=2 p=1, is a third of it).
pub const ARGON2_DEFAULT_MEMORY_KIB: u32 = 65536;
pub const ARGON2_DEFAULT_ITERATIONS: u32 = 3;
pub const ARGON2_DEFAULT_PARALLELISM: u32 = 4;
/// Fewer than two passes is refused, at hash time, as it is upstream.
pub const ARGON2_MIN_ITERATIONS: u32 = 2;

/// Largest `m_cost * t_cost` (KiB times passes) a stored Argon2 hash may ask
/// for at verify time — and so the largest a configuration may produce.
///
/// The cost travels inside the hash, so whoever writes the hash chooses how
/// much work verifying it takes: unbounded, `m` runs to `u32::MAX` KiB (an
/// allocation that aborts the process) and `t` to `u32::MAX` passes. Measured,
/// m=262144 t=8 already took two seconds per attempt. The bound is set
/// against real configurations, like `MAX_SCRYPT_WORK`: the defaults above come
/// to 196608, so this is about five times them, and it caps the worst case
/// near a second and 1 GiB.
pub const MAX_ARGON2_WORK: u64 = 1 << 20;

/// Highest bcrypt cost a stored hash may name at verify time — and the highest
/// a configuration may use. Each step doubles the work; 16 is sixteen times the
/// default of 12 (about three seconds here), 31 would be half a day.
pub const MAX_BCRYPT_COST: u32 = 16;

/// Tunables for `argon2_hash`. Every cost parameter left unset takes the
/// defaults above.
///
/// `secret` is the optional "pepper" (`@adonisjs/hash` `secret`): a key that is
/// NOT encoded in the hash. Verifying a secret-peppered hash requires the same
/// secret — lose it and every hash it produced becomes unverifiable.
#[derive(Debug, Clone, Default)]
pub struct Argon2Options {
    /// Memory cost in KiB. Must be ≥ 8.
    pub memory_kib: Option<u32>,
    /// Time cost (iterations). Must be ≥ 2.
    pub iterations: Option<u32>,
    /// Parallelism (lanes). Must be ≥ 1.
    pub parallelism: Option<u32>,
    /// Secret pepper. Not stored in the hash; required identically at verify.
    pub secret: Option<Vec<u8>>,
    /// Argon2 variant: "d", "i", or "id" (Adonis `variant`). Default "id".
    pub variant: Option<String>,
    /// Output length in bytes (Adonis `hashLength`). Default 32.
    pub hash_length: Option<usize>,
    /// Salt size in bytes (Adonis `saltSize`). Default 16.
    pub salt_length: Option<usize>,
}

/// The Argon2 cost parameters a hash gets when the application configures none,
/// as `(memory_kib, iterations, parallelism)`.
pub fn argon2_default_params() -> (u32, u32, u32) {
    (
        ARGON2_DEFAULT_MEMORY_KIB,
        ARGON2_DEFAULT_ITERATIONS,
        ARGON2_DEFAULT_PARALLELISM,
    )
}

/// Whether an Argon2 memory/time pair stays within `MAX_ARGON2_WORK`.
fn argon2_work_allowed(memory_kib: u32, iterations: u32) -> bool {
    u64::from(memory_kib) * u64::from(iterations) <= MAX_ARGON2_WORK
}

/// Minimum salt accepted by the Argon2 spec; below it the hash is weakened.
const MIN_SALT_BYTES: usize = 8;
/// The PHC salt field caps at 64 encoded bytes, so raw salt is bounded too.
const MAX_SALT_BYTES: usize = 48;

/// Map the Adonis variant name onto the algorithm. An unknown name is an error
/// rather than a silent fall back to Argon2id: an app asking for argon2i and
/// getting argon2id would never find out.
fn resolve_variant(variant: Option<&str>) -> Result<Algorithm, String> {
    match variant {
        None | Some("id") => Ok(Algorithm::Argon2id),
        Some("i") => Ok(Algorithm::Argon2i),
        Some("d") => Ok(Algorithm::Argon2d),
        Some(other) => Err(format!(
            "Unknown Argon2 variant \"{}\" — expected \"d\", \"i\", or \"id\".",
            other
        )),
    }
}

fn build_params(opts: &Argon2Options) -> Result<Params, String> {
    let memory = opts.memory_kib.unwrap_or(ARGON2_DEFAULT_MEMORY_KIB);
    let iterations = opts.iterations.unwrap_or(ARGON2_DEFAULT_ITERATIONS);
    let parallelism = opts.parallelism.unwrap_or(ARGON2_DEFAULT_PARALLELISM);
    if iterations < ARGON2_MIN_ITERATIONS {
        return Err(format!(
            "Argon2 iterations must be at least {}, got {}.",
            ARGON2_MIN_ITERATIONS, iterations
        ));
    }
    // A hash this configuration produced must be one verify accepts.
    if !argon2_work_allowed(memory, iterations) {
        return Err(format!(
            "Argon2 memory * iterations must not exceed {}, got {} * {}.",
            MAX_ARGON2_WORK, memory, iterations
        ));
    }
    Params::new(memory, iterations, parallelism, opts.hash_length)
        .map_err(|e| format!("Argon2 params error: {}", e))
}

/// A salt of the requested size, or the crate default when none is asked for.
///
/// RAW bytes, not a B64 `SaltString`. password-hash 0.6 takes the salt as
/// `&[u8]` (`hash_password_with_salt`) and does its own encoding, where 0.5
/// wanted the encoded form — so the `SaltString::encode_b64` this used to call
/// is gone rather than renamed. Handing encoded text to something expecting
/// bytes is the mistake that produces a salt of the wrong length with no error
/// at all, which is why the tests assert the length rather than only that a
/// hash verifies.
fn build_salt(salt_length: Option<usize>) -> Result<Vec<u8>, String> {
    let len = match salt_length {
        Some(len) => {
            if !(MIN_SALT_BYTES..=MAX_SALT_BYTES).contains(&len) {
                return Err(format!(
                    "Argon2 saltSize must be between {} and {} bytes, got {}.",
                    MIN_SALT_BYTES, MAX_SALT_BYTES, len
                ));
            }
            len
        }
        None => Salt::RECOMMENDED_LENGTH,
    };
    let mut bytes = vec![0u8; len];
    getrandom::fill(&mut bytes).map_err(|e| format!("Argon2 salt error: {}", e))?;
    Ok(bytes)
}

/// Build an Argon2 hasher for `make`. Borrows `opts.secret` when present, so the
/// returned instance is tied to `opts`' lifetime.
fn build_argon2(opts: &Argon2Options) -> Result<Argon2<'_>, String> {
    let params = build_params(opts)?;
    let algorithm = resolve_variant(opts.variant.as_deref())?;
    match opts.secret.as_deref() {
        Some(secret) => Argon2::new_with_secret(secret, algorithm, Version::V0x13, params)
            .map_err(|e| format!("Argon2 secret error: {}", e)),
        None => Ok(Argon2::new(algorithm, Version::V0x13, params)),
    }
}

pub fn argon2_hash(password: &str, opts: Argon2Options) -> Result<String, String> {
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(format!(
            "Password exceeds maximum length of {} bytes",
            MAX_PASSWORD_BYTES
        ));
    }
    let argon2 = build_argon2(&opts)?;
    let salt = build_salt(opts.salt_length)?;
    argon2
        .hash_password_with_salt(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("Argon2 hash error: {}", e))
}

pub fn argon2_verify(password: &str, hash: &str, secret: Option<&[u8]>) -> bool {
    if password.len() > MAX_PASSWORD_BYTES {
        return false;
    }
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    // The hash names its own cost, so refuse one that asks for more work than
    // any real configuration would (see MAX_ARGON2_WORK) — before deriving.
    // A hash missing either parameter is malformed, not "use the defaults".
    let (Some(memory), Some(iterations)) = (
        parsed.params.get_decimal("m"),
        parsed.params.get_decimal("t"),
    ) else {
        return false;
    };
    if !argon2_work_allowed(memory, iterations) {
        return false;
    }
    // verify_password reads the m/t/p params + salt encoded in the hash string;
    // only the secret has to be supplied by the caller. Build the instance with
    // that secret (or none) and DEFAULT params — the params are overridden by
    // the values carried in the hash.
    // The ALGORITHM comes from the hash string too — a hash made with argon2i
    // must not be verified as argon2id, which would simply never match.
    let algorithm = match parsed.algorithm.as_str() {
        "argon2i" => Algorithm::Argon2i,
        "argon2d" => Algorithm::Argon2d,
        "argon2id" => Algorithm::Argon2id,
        _ => return false,
    };
    let argon2 = match secret {
        Some(secret) => {
            match Argon2::new_with_secret(secret, algorithm, Version::V0x13, Params::DEFAULT) {
                Ok(a) => a,
                Err(_) => return false,
            }
        }
        None => Argon2::new(algorithm, Version::V0x13, Params::DEFAULT),
    };
    argon2.verify_password(password.as_bytes(), &parsed).is_ok()
}

/// Bcrypt's salt is exactly 128 bits, by the algorithm. `saltSize` exists in
/// the Adonis config, so it is VALIDATED rather than ignored: any other value
/// would produce a hash no bcrypt implementation can read.
pub const BCRYPT_SALT_BYTES: usize = 16;

/// The `$2?$` prefix. Adonis spells it as a char code (97 = `a`, 98 = `b`),
/// so the same config value maps here. 121 (`$2y$`) is accepted too: it is the
/// same algorithm, and verify reads it.
///
/// 120 (`$2x$`) is refused. It marks hashes made by the crypt_blowfish
/// sign-extension bug, so nothing should produce it — and verify does not
/// accept it, so every hash made under that setting would never match again.
fn resolve_bcrypt_version(version: Option<u32>) -> Result<bcrypt::Version, String> {
    match version {
        None => Ok(bcrypt::Version::TwoB),
        Some(97) => Ok(bcrypt::Version::TwoA),
        Some(98) => Ok(bcrypt::Version::TwoB),
        Some(121) => Ok(bcrypt::Version::TwoY),
        Some(other) => Err(format!(
            "Unknown bcrypt version {} — expected 97 (2a), 98 (2b) or 121 (2y).",
            other
        )),
    }
}

pub fn bcrypt_hash(
    password: &str,
    rounds: u32,
    version: Option<u32>,
    salt_length: Option<usize>,
) -> Result<String, String> {
    if password.len() > BCRYPT_MAX_BYTES {
        return Err(format!(
            "Password exceeds bcrypt maximum of {} bytes",
            BCRYPT_MAX_BYTES
        ));
    }
    if rounds < BCRYPT_MIN_COST {
        return Err(format!(
            "Bcrypt cost {} is below the minimum of {} (OWASP recommendation)",
            rounds, BCRYPT_MIN_COST
        ));
    }
    // A hash this configuration produced must be one verify accepts.
    if rounds > MAX_BCRYPT_COST {
        return Err(format!(
            "Bcrypt cost {} is above the maximum of {}",
            rounds, MAX_BCRYPT_COST
        ));
    }
    if let Some(len) = salt_length {
        if len != BCRYPT_SALT_BYTES {
            return Err(format!(
                "Bcrypt saltSize must be {} bytes — the algorithm fixes it, and {} would produce an unreadable hash.",
                BCRYPT_SALT_BYTES, len
            ));
        }
    }
    let version = resolve_bcrypt_version(version)?;
    let mut salt = [0u8; BCRYPT_SALT_BYTES];
    getrandom::fill(&mut salt).map_err(|e| format!("Bcrypt salt error: {}", e))?;
    bcrypt::hash_with_salt(password, rounds, salt)
        .map(|parts| parts.format_for_version(version))
        .map_err(|e| format!("Bcrypt hash error: {}", e))
}

/// Verify against a bcrypt hash in either form it is stored in:
///
/// - MCF, `$2a$` / `$2b$` / `$2y$` — what this engine writes, and what every
///   other bcrypt implementation reads;
/// - PHC, `$bcrypt$v=98$r=10$<b64 salt>$<b64 digest>` — what `@adonisjs/hash`
///   writes, so an application migrated from it keeps its users.
///
/// Either way a cost above `MAX_BCRYPT_COST` is refused before deriving.
pub fn bcrypt_verify(password: &str, hash: &str) -> Result<bool, String> {
    if password.len() > BCRYPT_MAX_BYTES {
        return Err(format!(
            "Password exceeds bcrypt maximum of {} bytes",
            BCRYPT_MAX_BYTES
        ));
    }
    if hash.starts_with("$bcrypt$") {
        return Ok(bcrypt_phc_verify(password, hash));
    }
    // `$2b$12$…`: the cost is the third `$`-separated field. Anything that
    // does not parse is left to the crate, which reports it.
    if let Some(cost) = hash.split('$').nth(2).and_then(|c| c.parse::<u32>().ok()) {
        if cost > MAX_BCRYPT_COST {
            return Ok(false);
        }
    }
    bcrypt::verify(password, hash).map_err(|e| format!("Bcrypt verify error: {}", e))
}

/// The fields of a PHC bcrypt string that verifying it needs.
struct BcryptPhc {
    cost: u32,
    salt: [u8; BCRYPT_SALT_BYTES],
    digest: Vec<u8>,
}

/// Parse `$bcrypt$[v=<97|98>$]r=<cost>$<b64 salt>$<b64 digest>`, the form
/// `@adonisjs/hash` stores. A missing version means 97, as it does there.
fn parse_bcrypt_phc(hash: &str) -> Option<BcryptPhc> {
    let mut fields: Vec<&str> = hash.split('$').collect();
    // ["", "bcrypt", ("v=98",) "r=10", salt, digest]
    if fields.len() == 6 {
        let version: u32 = fields.remove(2).strip_prefix("v=")?.parse().ok()?;
        if version != 97 && version != 98 {
            return None;
        }
    }
    let ["", "bcrypt", params, salt, digest] = fields.as_slice() else {
        return None;
    };
    let cost: u32 = params.strip_prefix("r=")?.parse().ok()?;
    // 4 is bcrypt's own floor; a stored hash below the configured minimum still
    // verifies, so it can be upgraded on login rather than lock its owner out.
    if !(4..=MAX_BCRYPT_COST).contains(&cost) {
        return None;
    }
    // Bcrypt's salt is exactly 16 bytes; anything else is not a bcrypt hash.
    let salt: [u8; BCRYPT_SALT_BYTES] = STANDARD_NO_PAD.decode(salt).ok()?.try_into().ok()?;
    let digest = STANDARD_NO_PAD.decode(digest).ok()?;
    if digest.is_empty() {
        return None;
    }
    Some(BcryptPhc { cost, salt, digest })
}

fn bcrypt_phc_verify(password: &str, hash: &str) -> bool {
    let Some(BcryptPhc { cost, salt, digest }) = parse_bcrypt_phc(hash) else {
        return false;
    };
    let Ok(parts) = bcrypt::hash_with_salt(password, cost, salt) else {
        return false;
    };
    // The MCF string ends with the 23-byte digest in bcrypt's alphabet, the
    // last 31 characters. The version letter does not change the digest.
    let mcf = parts.format_for_version(bcrypt::Version::TwoB);
    let Some(encoded) = mcf.get(mcf.len().saturating_sub(31)..) else {
        return false;
    };
    let Ok(derived) = BCRYPT_B64.decode(encoded) else {
        return false;
    };
    subtle_eq(&derived, &digest)
}

/// Tunables for `scrypt_hash`. Mirrors `@adonisjs/hash` scrypt config names.
/// `None` falls back to the Adonis defaults (cost=16384, r=8, p=1, keyLen=64,
/// saltLen=16). `cost` (N) must be a power of two > 1.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScryptOptions {
    /// CPU/memory cost (N). Power of two > 1. Adonis `cost`. Default 16384.
    pub cost: Option<u32>,
    /// Block size (r). Adonis `blockSize`. Default 8.
    pub block_size: Option<u32>,
    /// Parallelization (p). Adonis `parallelization`. Default 1.
    pub parallelization: Option<u32>,
    /// Derived key length in bytes. Adonis `keyLength`. Default 64.
    pub key_length: Option<usize>,
    /// Salt size in bytes. Adonis `saltSize`. Default 16.
    pub salt_length: Option<usize>,
    /// Largest working set, in bytes, a derivation may take. Adonis
    /// `maxMemory`. Default 32 MiB.
    pub max_memory: Option<u64>,
}

/// `maxMemory` when none is configured — 32 MiB, as upstream and as Node's
/// `crypto.scrypt`.
pub const SCRYPT_DEFAULT_MAX_MEMORY: u64 = 32 * 1024 * 1024;

/// Bytes a scrypt derivation allocates: `128 * r * (N + p + 2)`. This is the
/// figure Node's `crypto.scrypt` (OpenSSL) compares to `maxmem`, so a
/// configuration or a stored hash is refused here exactly where it is refused
/// there.
pub fn scrypt_memory(cost: u32, r: u32, p: u32) -> u64 {
    128 * u64::from(r) * (u64::from(cost) + u64::from(p) + 2)
}

/// Accepted derived-key lengths, in bytes — the `keyLength` range of
/// `@adonisjs/hash`, whose 128-byte hashes must verify here.
const SCRYPT_KEY_LENGTH: std::ops::RangeInclusive<usize> = 64..=128;
/// Accepted salt sizes, in bytes.
const SCRYPT_SALT_LENGTH: std::ops::RangeInclusive<usize> = 8..=1024;

pub fn scrypt_hash(password: &str, opts: ScryptOptions) -> Result<String, String> {
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(format!(
            "Password exceeds maximum length of {} bytes",
            MAX_PASSWORD_BYTES
        ));
    }
    let cost = opts.cost.unwrap_or(16384);
    let r = opts.block_size.unwrap_or(8);
    let p = opts.parallelization.unwrap_or(1);
    let key_len = opts.key_length.unwrap_or(64);
    let salt_len = opts.salt_length.unwrap_or(16);
    let max_memory = opts.max_memory.unwrap_or(SCRYPT_DEFAULT_MAX_MEMORY);
    if !cost.is_power_of_two() || cost < 2 {
        return Err(format!(
            "Scrypt cost must be a power of two greater than 1 (got {})",
            cost
        ));
    }
    if !SCRYPT_KEY_LENGTH.contains(&key_len) {
        return Err(format!(
            "Scrypt keyLength must be between {} and {} bytes, got {}.",
            SCRYPT_KEY_LENGTH.start(),
            SCRYPT_KEY_LENGTH.end(),
            key_len
        ));
    }
    if !SCRYPT_SALT_LENGTH.contains(&salt_len) {
        return Err(format!(
            "Scrypt saltSize must be between {} and {} bytes, got {}.",
            SCRYPT_SALT_LENGTH.start(),
            SCRYPT_SALT_LENGTH.end(),
            salt_len
        ));
    }
    // A hash this configuration produced must be one verify accepts.
    if u64::from(cost) * u64::from(r) * u64::from(p) > MAX_SCRYPT_WORK {
        return Err(format!(
            "Scrypt cost * blockSize * parallelization must not exceed {}",
            MAX_SCRYPT_WORK
        ));
    }
    if scrypt_memory(cost, r, p) > max_memory {
        return Err(format!(
            "Scrypt working set of {} bytes exceeds maxMemory of {} bytes; raise maxMemory or lower cost/blockSize",
            scrypt_memory(cost, r, p),
            max_memory
        ));
    }
    let log_n = cost.trailing_zeros() as u8;
    // `Params::new`, not `new_with_output_len`: the latter caps the output at
    // the PHC limit of 64 bytes, while the low-level `scrypt` call below takes
    // its length from the buffer and a 128-byte key is legitimate.
    let params =
        scrypt::Params::new(log_n, r, p).map_err(|e| format!("Scrypt params error: {}", e))?;
    let mut salt = vec![0u8; salt_len];
    getrandom::fill(&mut salt).map_err(|e| format!("RNG error: {}", e))?;
    let mut key = vec![0u8; key_len];
    scrypt::scrypt(password.as_bytes(), &salt, &params, &mut key)
        .map_err(|e| format!("Scrypt error: {}", e))?;
    // PHC format matching @adonisjs/hash for cross-verify interop:
    //   $scrypt$n=<cost>,r=<r>,p=<p>$<b64 salt>$<b64 hash>
    // The work parameters travel WITH the hash (self-describing) — a future
    // change to the default cost never invalidates a stored hash, and an Adonis
    // scrypt hash verifies here unchanged (and vice-versa).
    Ok(format!(
        "$scrypt$n={},r={},p={}${}${}",
        cost,
        r,
        p,
        STANDARD_NO_PAD.encode(&salt),
        STANDARD_NO_PAD.encode(&key)
    ))
}

/// The five fields of a PHC scrypt string, named rather than positional — a
/// five-tuple of `(u32, u32, u32, Vec<u8>, Vec<u8>)` says nothing about which
/// cost parameter is which at the call site.
struct ScryptHash {
    cost: u32,
    r: u32,
    p: u32,
    salt: Vec<u8>,
    stored_key: Vec<u8>,
}

/// Parse the Adonis-parity PHC scrypt string
/// `$scrypt$n=<cost>,r=<r>,p=<p>$<b64 salt>$<b64 hash>`.
fn parse_scrypt_hash(hash: &str) -> Option<ScryptHash> {
    let mut parts = hash.split('$');
    // Leading `$` yields an empty first segment.
    if !parts.next()?.is_empty() {
        return None;
    }
    if parts.next()? != "scrypt" {
        return None;
    }
    let params_seg = parts.next()?;
    let salt = STANDARD_NO_PAD.decode(parts.next()?).ok()?;
    let stored_key = STANDARD_NO_PAD.decode(parts.next()?).ok()?;
    if parts.next().is_some() {
        return None;
    }
    let mut cost: Option<u32> = None;
    let mut r: Option<u32> = None;
    let mut p: Option<u32> = None;
    for kv in params_seg.split(',') {
        let (k, v) = kv.split_once('=')?;
        let n: u32 = v.parse().ok()?;
        match k {
            "n" => cost = Some(n),
            "r" => r = Some(n),
            "p" => p = Some(n),
            _ => return None,
        }
    }
    Some(ScryptHash {
        cost: cost?,
        r: r?,
        p: p?,
        salt,
        stored_key,
    })
}

/// Largest `N * r * p` a stored scrypt hash may ask for at verify time.
///
/// scrypt's cost travels inside the hash, so whoever writes the hash chooses
/// how much work verifying it takes: memory is `128 * N * r` bytes and time
/// grows with `N * r * p`. Without a bound, a single altered row turns every
/// login attempt on that account into tens of seconds of CPU and gigabytes of
/// memory — measured here, n=2^24 ran for roughly half a minute where the
/// default takes 33ms. This is the same threat the empty-key guard below
/// already answers: a stored hash is not necessarily one we wrote.
///
/// The bound is set against real configurations, not against the attack. The
/// defaults come to 2^17, and OWASP's strongest scrypt recommendation
/// (N=2^17, r=8, p=1) to 2^20 — so this is four times the strongest setting
/// anyone should be running, and caps the worst case near a second and half a
/// gigabyte. It bounds the escalation; it cannot make verifying a deliberately
/// expensive configuration cheap, because that cost is the point of one.
pub const MAX_SCRYPT_WORK: u64 = 1 << 22;

/// Verify against a PHC scrypt hash, re-deriving with the parameters the hash
/// carries. `max_memory` is the configured `maxMemory` (default 32 MiB): a hash
/// whose working set exceeds it is refused before deriving, as upstream refuses
/// it — on top of the `MAX_SCRYPT_WORK` bound, which holds whatever the
/// configuration says.
pub fn scrypt_verify(password: &str, hash: &str, max_memory: Option<u64>) -> bool {
    if password.len() > MAX_PASSWORD_BYTES {
        return false;
    }
    let Some(ScryptHash {
        cost,
        r,
        p,
        salt,
        stored_key,
    }) = parse_scrypt_hash(hash)
    else {
        return false;
    };
    // The key length comes from the stored hash itself, within the range make
    // accepts (64 to 128 bytes, as upstream verifies too). A short key is not
    // a weaker hash, it is a guessable one: an empty key matched anything, and
    // a one-byte key matches one wrong password in 256. The salt is held to
    // the range make accepts as well. Fail closed.
    let key_len = stored_key.len();
    if !SCRYPT_KEY_LENGTH.contains(&key_len) || !SCRYPT_SALT_LENGTH.contains(&salt.len()) {
        return false;
    }
    if !cost.is_power_of_two() || cost < 2 {
        return false;
    }
    // The hash names its own cost, so refuse one that asks for more work than
    // any real configuration would (see MAX_SCRYPT_WORK).
    if u64::from(cost) * u64::from(r) * u64::from(p) > MAX_SCRYPT_WORK {
        return false;
    }
    if scrypt_memory(cost, r, p) > max_memory.unwrap_or(SCRYPT_DEFAULT_MAX_MEMORY) {
        return false;
    }
    let log_n = cost.trailing_zeros() as u8;
    // Re-derive with the params ENCODED IN THE HASH, not the current default.
    // The key length is the buffer's, so a 128-byte key verifies too.
    let Ok(params) = scrypt::Params::new(log_n, r, p) else {
        return false;
    };
    let mut derived = vec![0u8; key_len];
    if scrypt::scrypt(password.as_bytes(), &salt, &params, &mut derived).is_err() {
        return false;
    }
    subtle_eq(&derived, &stored_key)
}

fn subtle_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_argon2() -> Argon2Options {
        Argon2Options::default()
    }

    #[test]
    fn argon2_round_trip() {
        let hash = argon2_hash("hunter2", default_argon2()).unwrap();
        assert!(hash.starts_with("$argon2"));
        assert!(argon2_verify("hunter2", &hash, None));
        assert!(!argon2_verify("wrong", &hash, None));
    }

    #[test]
    fn argon2_random_salts() {
        let h1 = argon2_hash("password", default_argon2()).unwrap();
        let h2 = argon2_hash("password", default_argon2()).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn argon2_honors_custom_params() {
        let opts = Argon2Options {
            memory_kib: Some(32 * 1024),
            iterations: Some(3),
            parallelism: Some(2),
            secret: None,
            ..Default::default()
        };
        let hash = argon2_hash("password", opts).unwrap();
        assert!(hash.contains("m=32768"));
        assert!(hash.contains("t=3"));
        assert!(hash.contains("p=2"));
        assert!(argon2_verify("password", &hash, None));
    }

    #[test]
    fn argon2_rejects_invalid_params() {
        let bad = Argon2Options {
            memory_kib: Some(1), // below crate minimum (8)
            iterations: None,
            parallelism: None,
            secret: None,
            ..Default::default()
        };
        assert!(argon2_hash("password", bad).is_err());
    }

    #[test]
    fn argon2_invalid_hash() {
        assert!(!argon2_verify("password", "not_a_valid_hash", None));
    }

    #[test]
    fn argon2_secret_pepper_round_trip() {
        let secret = b"pepper-key".to_vec();
        let opts = Argon2Options {
            secret: Some(secret.clone()),
            ..Argon2Options::default()
        };
        let hash = argon2_hash("hunter2", opts).unwrap();
        // The secret is NOT encoded in the hash.
        assert!(hash.starts_with("$argon2"));
        // Correct secret verifies.
        assert!(argon2_verify("hunter2", &hash, Some(&secret)));
        // Wrong / missing secret fails.
        assert!(!argon2_verify("hunter2", &hash, Some(b"other-key")));
        assert!(!argon2_verify("hunter2", &hash, None));
    }

    #[test]
    fn bcrypt_round_trip() {
        let hash = bcrypt_hash("hunter2", 10, None, None).unwrap();
        assert!(hash.starts_with("$2b$"));
        assert!(bcrypt_verify("hunter2", &hash).unwrap());
        assert!(!bcrypt_verify("wrong", &hash).unwrap());
    }

    #[test]
    fn bcrypt_rejects_low_cost() {
        assert!(bcrypt_hash("password", 4, None, None).is_err());
    }

    #[test]
    fn bcrypt_rejects_oversized_password() {
        let long = "A".repeat(73);
        assert!(bcrypt_hash(&long, 10, None, None).is_err());
        assert!(bcrypt_verify(&long, "$2b$10$fake").is_err());
    }

    #[test]
    fn scrypt_round_trip() {
        let hash = scrypt_hash("hunter2", ScryptOptions::default()).unwrap();
        // Adonis-parity PHC prefix carries the work params.
        assert!(hash.starts_with("$scrypt$n=16384,r=8,p=1$"));
        assert!(scrypt_verify("hunter2", &hash, None));
        assert!(!scrypt_verify("wrong", &hash, None));
    }

    #[test]
    fn scrypt_honors_custom_cost() {
        let opts = ScryptOptions {
            cost: Some(1024),
            block_size: Some(8),
            parallelization: Some(2),
            ..ScryptOptions::default()
        };
        let hash = scrypt_hash("password", opts).unwrap();
        assert!(hash.starts_with("$scrypt$n=1024,r=8,p=2$"));
        assert!(scrypt_verify("password", &hash, None));
    }

    #[test]
    fn scrypt_rejects_non_power_of_two_cost() {
        let opts = ScryptOptions {
            cost: Some(3000),
            ..ScryptOptions::default()
        };
        assert!(scrypt_hash("password", opts).is_err());
    }

    #[test]
    fn scrypt_verify_survives_keylen_config_change() {
        // The stored key length is authoritative — a hash produced under
        // keyLength 64 must still verify regardless of the current config.
        let hash = scrypt_hash(
            "password",
            ScryptOptions {
                key_length: Some(64),
                ..ScryptOptions::default()
            },
        )
        .unwrap();
        assert!(scrypt_verify("password", &hash, None));
        assert!(!scrypt_verify("wrong", &hash, None));
    }

    #[test]
    fn scrypt_rejects_empty_stored_key() {
        // A crafted hash with an empty key field must NOT trivially match.
        let salt = STANDARD_NO_PAD.encode(b"0123456789abcdef");
        let hash = format!("$scrypt$n=16384,r=8,p=1${}$", salt);
        assert!(!scrypt_verify("anything", &hash, None));
    }

    #[test]
    fn scrypt_verify_reads_params_from_hash() {
        // A hash derived with deliberately low params must still verify —
        // proving verify reads n/r/p from the string instead of assuming the
        // current default cost.
        let salt = b"0123456789abcdef";
        let params = scrypt::Params::new_with_output_len(10, 8, 1, 64).unwrap();
        let mut key = vec![0u8; 64];
        scrypt::scrypt(b"hunter2", salt, &params, &mut key).unwrap();
        let hash = format!(
            "$scrypt$n=1024,r=8,p=1${}${}",
            STANDARD_NO_PAD.encode(salt),
            STANDARD_NO_PAD.encode(&key)
        );
        assert!(scrypt_verify("hunter2", &hash, None));
        assert!(!scrypt_verify("wrong", &hash, None));
    }

    #[test]
    fn scrypt_rejects_malformed_hash() {
        // Legacy `salt:key` (no params), the old `scrypt$ln=` format, and
        // garbage must all fail closed.
        assert!(!scrypt_verify("password", "deadbeef:cafebabe", None));
        assert!(!scrypt_verify("password", "not-a-hash", None));
        assert!(!scrypt_verify(
            "password",
            "scrypt$ln=14$r=8$p=1$aa$bb",
            None
        ));
    }

    #[test]
    fn argon2_honours_the_requested_variant() {
        // The bug this covers: an app asking for argon2i silently got argon2id.
        for (variant, prefix) in [("i", "$argon2i$"), ("d", "$argon2d$"), ("id", "$argon2id$")] {
            let opts = Argon2Options {
                variant: Some(variant.to_string()),
                ..Default::default()
            };
            let hash = argon2_hash("hunter2", opts).unwrap();
            assert!(hash.starts_with(prefix), "{} produced {}", variant, hash);
            // And it verifies — the algorithm is read back from the hash.
            assert!(argon2_verify("hunter2", &hash, None));
            assert!(!argon2_verify("wrong", &hash, None));
        }
    }

    #[test]
    fn argon2_rejects_an_unknown_variant() {
        let opts = Argon2Options {
            variant: Some("z".into()),
            ..Default::default()
        };
        assert!(argon2_hash("hunter2", opts).is_err());
    }

    #[test]
    fn argon2_honours_the_requested_output_length() {
        let opts = Argon2Options {
            hash_length: Some(64),
            ..Default::default()
        };
        let hash = argon2_hash("hunter2", opts).unwrap();
        let encoded = hash.rsplit('$').next().unwrap();
        // 64 raw bytes is 86 base64 characters without padding.
        assert_eq!(encoded.len(), 86, "{}", hash);
        assert!(argon2_verify("hunter2", &hash, None));
    }

    #[test]
    fn argon2_honours_the_requested_salt_size() {
        let opts = Argon2Options {
            salt_length: Some(32),
            ..Default::default()
        };
        let hash = argon2_hash("hunter2", opts).unwrap();
        let salt = hash.split('$').nth(4).unwrap();
        // 32 raw bytes is 43 base64 characters without padding.
        assert_eq!(salt.len(), 43, "{}", hash);
        assert!(argon2_verify("hunter2", &hash, None));
    }

    #[test]
    fn argon2_rejects_a_salt_outside_the_safe_range() {
        for len in [4usize, 64] {
            let opts = Argon2Options {
                salt_length: Some(len),
                ..Default::default()
            };
            assert!(argon2_hash("hunter2", opts).is_err(), "len {}", len);
        }
    }

    #[test]
    fn bcrypt_honours_the_requested_version() {
        for (version, prefix) in [(97u32, "$2a$"), (98, "$2b$"), (121, "$2y$")] {
            let hash = bcrypt_hash("hunter2", 10, Some(version), None).unwrap();
            assert!(hash.starts_with(prefix), "{} produced {}", version, hash);
            assert!(bcrypt_verify("hunter2", &hash).unwrap());
        }
    }

    #[test]
    fn bcrypt_rejects_a_salt_size_the_algorithm_cannot_produce() {
        // Better than accepting it and emitting a hash nothing can read.
        assert!(bcrypt_hash("hunter2", 10, None, Some(32)).is_err());
        assert!(bcrypt_hash("hunter2", 10, None, Some(16)).is_ok());
    }

    #[test]
    fn bcrypt_rejects_an_unknown_version() {
        assert!(bcrypt_hash("hunter2", 10, Some(42), None).is_err());
    }

    #[test]
    fn bcrypt_refuses_the_2x_version() {
        // `$2x$` is the crypt_blowfish-bug marker, and verify does not read
        // it: every account made under it could never log in again.
        assert!(bcrypt_hash("hunter2", 10, Some(120), None).is_err());
    }

    #[test]
    fn the_argon2_work_cap_is_inclusive() {
        assert!(argon2_work_allowed(1 << 19, 2));
        assert!(!argon2_work_allowed((1 << 19) + 1, 2));
        assert!(!argon2_work_allowed(u32::MAX, u32::MAX));
    }

    #[test]
    fn scrypt_honours_a_128_byte_key() {
        let opts = ScryptOptions {
            key_length: Some(128),
            ..ScryptOptions::default()
        };
        let hash = scrypt_hash("hunter2", opts).unwrap();
        let key = STANDARD_NO_PAD
            .decode(hash.rsplit('$').next().unwrap())
            .unwrap();
        assert_eq!(key.len(), 128);
        assert!(scrypt_verify("hunter2", &hash, None));
        assert!(!scrypt_verify("wrong", &hash, None));
    }

    /// A correctly derived scrypt hash with the given salt and key lengths.
    fn scrypt_with_lengths(password: &str, salt_len: usize, key_len: usize) -> String {
        let salt = vec![7u8; salt_len];
        let params = scrypt::Params::new(10, 8, 1).unwrap();
        let mut key = vec![0u8; key_len];
        scrypt::scrypt(password.as_bytes(), &salt, &params, &mut key).unwrap();
        format!(
            "$scrypt$n=1024,r=8,p=1${}${}",
            STANDARD_NO_PAD.encode(&salt),
            STANDARD_NO_PAD.encode(&key)
        )
    }

    #[test]
    fn scrypt_verify_refuses_a_stored_key_outside_64_to_128_bytes() {
        // Correct derivations with the right password: only the length is
        // wrong. A one-byte key would match one wrong password in 256.
        for key_len in [1usize, 32, 63, 129] {
            let hash = scrypt_with_lengths("hunter2", 16, key_len);
            assert!(!scrypt_verify("hunter2", &hash, None), "key {}", key_len);
        }
        for key_len in [64usize, 128] {
            let hash = scrypt_with_lengths("hunter2", 16, key_len);
            assert!(scrypt_verify("hunter2", &hash, None), "key {}", key_len);
        }
    }

    #[test]
    fn scrypt_verify_refuses_a_stored_salt_outside_8_to_1024_bytes() {
        for salt_len in [4usize, 1025] {
            let hash = scrypt_with_lengths("hunter2", salt_len, 64);
            assert!(!scrypt_verify("hunter2", &hash, None), "salt {}", salt_len);
        }
        let hash = scrypt_with_lengths("hunter2", 8, 64);
        assert!(scrypt_verify("hunter2", &hash, None));
    }

    #[test]
    fn scrypt_rejects_a_key_length_outside_the_range() {
        for len in [32usize, 129] {
            let opts = ScryptOptions {
                key_length: Some(len),
                ..ScryptOptions::default()
            };
            assert!(scrypt_hash("hunter2", opts).is_err(), "len {}", len);
        }
    }

    #[test]
    fn bcrypt_phc_rejects_malformed_strings() {
        let salt = STANDARD_NO_PAD.encode([7u8; 16]);
        let digest = STANDARD_NO_PAD.encode([9u8; 23]);
        for hash in [
            // unknown version
            format!("$bcrypt$v=120$r=10${salt}${digest}"),
            // cost below bcrypt's floor, and above the cap
            format!("$bcrypt$v=98$r=3${salt}${digest}"),
            format!("$bcrypt$v=98$r=31${salt}${digest}"),
            // salt that is not 16 bytes
            format!(
                "$bcrypt$v=98$r=10${}${digest}",
                STANDARD_NO_PAD.encode([7u8; 8])
            ),
            // empty digest
            format!("$bcrypt$v=98$r=10${salt}$"),
            // missing cost, unknown parameter, extra field
            format!("$bcrypt$v=98${salt}${digest}"),
            format!("$bcrypt$v=98$x=10${salt}${digest}"),
            format!("$bcrypt$v=98$r=10${salt}${digest}$extra"),
        ] {
            assert_eq!(bcrypt_verify("hunter2", &hash), Ok(false), "{}", hash);
        }
    }
}

/// Hashes written by the crate versions this shipped with, kept as literals so
/// a dependency bump cannot silently stop verifying them.
///
/// This is the failure that matters when a password-hashing crate moves: a
/// format or a default changes, every stored password stops matching, and
/// nothing says so — the other tests hash and verify in the same process with
/// the same new code, so they never meet a hash written by the old one.
///
/// Generated by `vector_dump` below, against argon2 0.5 / password-hash 0.5 /
/// bcrypt 0.16 / scrypt as of that version. Regenerating them would defeat the
/// point: if a bump stops these verifying, that is the bug, not the vector.
#[cfg(test)]
mod stored_hash_compatibility {
    use super::*;

    const PASSWORD: &str = "correct horse battery staple";
    const ARGON2: &str = "$argon2id$v=19$m=19456,t=2,p=1$pl/vS1MLvCPhYG1DepHagg$Sv6FvOhPCgtYiQLFw6m2UptaXQSlFR6h5OJKbUXSHcA";
    const SCRYPT: &str = "$scrypt$n=16384,r=8,p=1$+YFfPVMiON8a17zrAt1FiA$m5q0g7mkBrr9NwGvpViDAvywDuHOKgQIoVAfPJ0alM7rk9H5m+4FGFmT8nHwQi+9DwCyJ9EGWQ+loE2h4xP9Gw";
    const BCRYPT: &str = "$2b$10$5waPGhJBcNCNG9IG.htEAedKAJECRTX0t/xxKFCPNswVo0516yxq6";

    #[test]
    fn a_generated_salt_has_the_length_that_was_asked_for() {
        // The failure the stored-hash vectors CANNOT catch. They prove an old
        // hash still verifies; they say nothing about a new one being weak.
        // password-hash 0.6 takes the salt as raw bytes where 0.5 wanted the
        // B64 form, and handing one to the other produces a salt of the wrong
        // length with no error anywhere — every new password quietly weaker.
        //
        // The PHC string carries the salt B64-encoded, so the check decodes it
        // back and compares byte counts.
        use base64::engine::general_purpose::STANDARD_NO_PAD;
        use base64::Engine;

        let salt_of = |hash: &str| -> usize {
            let encoded = hash.split('$').nth(4).expect("PHC has a salt field");
            STANDARD_NO_PAD
                .decode(encoded)
                .expect("the salt field is B64")
                .len()
        };

        for requested in [MIN_SALT_BYTES, 16, 24, MAX_SALT_BYTES] {
            let hash = argon2_hash(
                PASSWORD,
                Argon2Options {
                    salt_length: Some(requested),
                    ..Argon2Options::default()
                },
            )
            .expect("hashes");
            assert_eq!(
                salt_of(&hash),
                requested,
                "a saltSize of {requested} must produce {requested} bytes of salt"
            );
            assert!(argon2_verify(PASSWORD, &hash, None));
        }

        // The default is the crate's recommendation, not something shorter.
        let hash = argon2_hash(PASSWORD, Argon2Options::default()).expect("hashes");
        assert!(
            salt_of(&hash) >= MIN_SALT_BYTES,
            "the default salt must not be shorter than the floor we accept"
        );

        // Two hashes of the same password must not share a salt.
        let a = argon2_hash(PASSWORD, Argon2Options::default()).expect("hashes");
        let b = argon2_hash(PASSWORD, Argon2Options::default()).expect("hashes");
        assert_ne!(a, b, "the salt must be random per hash");
    }

    #[test]
    fn argon2_still_verifies_a_stored_hash() {
        assert!(
            argon2_verify(PASSWORD, ARGON2, None),
            "stored argon2 hash no longer verifies"
        );
        assert!(!argon2_verify("wrong password", ARGON2, None));
    }

    #[test]
    fn scrypt_still_verifies_a_stored_hash() {
        assert!(
            scrypt_verify(PASSWORD, SCRYPT, None),
            "stored scrypt hash no longer verifies"
        );
        assert!(!scrypt_verify("wrong password", SCRYPT, None));
    }

    /// Written by `@adonisjs/hash` 10.1.1 (bcrypt 6, argon2 0.44, Node
    /// crypto), from the same password, with its default configuration unless
    /// named otherwise. An application migrated from it keeps these rows.
    const ADONIS_BCRYPT_V98_R10: &str =
        "$bcrypt$v=98$r=10$GUO2Wb6qbX++g+Rj7TMw/A$vKswmGJAaU23gK55NxkYg6Uumeo9a8A";
    const ADONIS_BCRYPT_V97_R11: &str =
        "$bcrypt$v=97$r=11$sy4yaS9zT8A/fr/YNcrXSQ$lrslf78zvt2SBEpxJpZxs6lAJH/SLRQ";
    const ADONIS_ARGON2: &str = "$argon2id$v=19$m=65536,t=3,p=4$apabyr1nIDcGd/NrAV/4rg$vurldQTOttPRWlO2VVrPfWFBToJxQNXSQoY0L1P6Gsw";
    const ADONIS_SCRYPT_KEY_128: &str = "$scrypt$n=16384,r=8,p=1$dkKkDneyGYkDJrGJytFqiA$1OZPKHHUfoBuF61xlTDRbGw4rclzgdEhxyNKbeqVc23WfVaZ/p8xC++IrVU8H+lhhcFqKJK9up3PpFWSAbd9758ujFXeXu1nJGzKEhqJ89ziwgzZYNY0GOQljTzAShxN7VgHBsgZg8l68EZusxQQaftfiXw/fkcInvSdS+XuXGw";

    #[test]
    fn bcrypt_verifies_a_hash_stored_by_adonis() {
        for hash in [ADONIS_BCRYPT_V98_R10, ADONIS_BCRYPT_V97_R11] {
            assert_eq!(bcrypt_verify(PASSWORD, hash), Ok(true), "{}", hash);
            assert_eq!(bcrypt_verify("wrong password", hash), Ok(false), "{}", hash);
        }
    }

    #[test]
    fn bcrypt_verifies_an_adonis_hash_without_a_version() {
        // Older upstream strings carry no `v=`; it then means 97.
        let unversioned = ADONIS_BCRYPT_V97_R11.replace("$v=97", "");
        assert_eq!(bcrypt_verify(PASSWORD, &unversioned), Ok(true));
    }

    #[test]
    fn bcrypt_refuses_an_adonis_hash_with_an_altered_digest() {
        let altered = ADONIS_BCRYPT_V98_R10.replace("vKsw", "vKsx");
        assert_eq!(bcrypt_verify(PASSWORD, &altered), Ok(false));
    }

    #[test]
    fn argon2_verifies_a_hash_stored_by_adonis() {
        assert!(argon2_verify(PASSWORD, ADONIS_ARGON2, None));
        assert!(!argon2_verify("wrong password", ADONIS_ARGON2, None));
    }

    #[test]
    fn scrypt_verifies_a_128_byte_key_stored_by_adonis() {
        assert!(scrypt_verify(PASSWORD, ADONIS_SCRYPT_KEY_128, None));
        assert!(!scrypt_verify(
            "wrong password",
            ADONIS_SCRYPT_KEY_128,
            None
        ));
    }

    #[test]
    fn bcrypt_still_verifies_a_stored_hash() {
        assert!(
            bcrypt_verify(PASSWORD, BCRYPT).expect("bcrypt verifies"),
            "stored bcrypt hash no longer verifies"
        );
        assert!(!bcrypt_verify("wrong password", BCRYPT).expect("bcrypt verifies"));
    }
}

#[cfg(test)]
mod vector_dump {
    use super::*;
    /// Prints hashes made by the CURRENT crate versions. Run with
    /// `cargo test -p sigil-engine vector_dump -- --nocapture --ignored`.
    #[test]
    #[ignore]
    fn dump() {
        let pw = "correct horse battery staple";
        println!(
            "ARGON2 {}",
            argon2_hash(pw, Argon2Options::default()).unwrap()
        );
        println!(
            "SCRYPT {}",
            scrypt_hash(pw, ScryptOptions::default()).unwrap()
        );
        println!("BCRYPT {}", bcrypt_hash(pw, 10, None, None).unwrap());
    }
}
