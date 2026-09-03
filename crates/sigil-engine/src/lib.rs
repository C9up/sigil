use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use password_hash::phc::Salt;

const MAX_PASSWORD_BYTES: usize = 1024;
const BCRYPT_MAX_BYTES: usize = 72;
const BCRYPT_MIN_COST: u32 = 10;

/// Tunables for `argon2_hash`. When no memory/time/parallelism is set and no
/// secret is provided, this falls back to `Argon2::default()` (Argon2id,
/// m=19456 KiB, t=2, p=1 — OWASP minimum).
///
/// `secret` is the optional "pepper" (`@adonisjs/hash` `secret`): a key that is
/// NOT encoded in the hash. Verifying a secret-peppered hash requires the same
/// secret — lose it and every hash it produced becomes unverifiable.
#[derive(Debug, Clone, Default)]
pub struct Argon2Options {
    /// Memory cost in KiB. Must be ≥ 8.
    pub memory_kib: Option<u32>,
    /// Time cost (iterations). Must be ≥ 1.
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

/// The Argon2 cost parameters a hash gets when the application configures none.
///
/// Read from the crate rather than restated, because `needsReHash` has to
/// compare a stored hash against what hashing it TODAY would produce. Writing
/// the numbers down in TypeScript would make that comparison right until the
/// day the crate raises its defaults — which is the day it most needs to be.
pub fn argon2_default_params() -> (u32, u32, u32) {
    let p = Params::DEFAULT;
    (p.m_cost(), p.t_cost(), p.p_cost())
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
    let any_set = opts.memory_kib.is_some()
        || opts.iterations.is_some()
        || opts.parallelism.is_some()
        || opts.hash_length.is_some();
    if !any_set {
        return Ok(Params::DEFAULT);
    }
    let default = Params::DEFAULT;
    Params::new(
        opts.memory_kib.unwrap_or(default.m_cost()),
        opts.iterations.unwrap_or(default.t_cost()),
        opts.parallelism.unwrap_or(default.p_cost()),
        opts.hash_length,
    )
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
/// so the same config value maps here.
fn resolve_bcrypt_version(version: Option<u32>) -> Result<bcrypt::Version, String> {
    match version {
        None => Ok(bcrypt::Version::TwoB),
        Some(97) => Ok(bcrypt::Version::TwoA),
        Some(98) => Ok(bcrypt::Version::TwoB),
        Some(120) => Ok(bcrypt::Version::TwoX),
        Some(121) => Ok(bcrypt::Version::TwoY),
        Some(other) => Err(format!(
            "Unknown bcrypt version {} — expected 97 (2a), 98 (2b), 120 (2x) or 121 (2y).",
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

pub fn bcrypt_verify(password: &str, hash: &str) -> Result<bool, String> {
    if password.len() > BCRYPT_MAX_BYTES {
        return Err(format!(
            "Password exceeds bcrypt maximum of {} bytes",
            BCRYPT_MAX_BYTES
        ));
    }
    bcrypt::verify(password, hash).map_err(|e| format!("Bcrypt verify error: {}", e))
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
}

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
    if !cost.is_power_of_two() || cost < 2 {
        return Err(format!(
            "Scrypt cost must be a power of two greater than 1 (got {})",
            cost
        ));
    }
    let log_n = cost.trailing_zeros() as u8;
    let params = scrypt::Params::new_with_output_len(log_n, r, p, key_len)
        .map_err(|e| format!("Scrypt params error: {}", e))?;
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
const MAX_SCRYPT_WORK: u64 = 1 << 22;

pub fn scrypt_verify(password: &str, hash: &str) -> bool {
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
    // Derive the key length from the stored hash itself. Guard an empty key so a
    // crafted `…$salt$` hash (key_len 0) can't trivially match via an
    // empty-vs-empty comparison. Fail closed.
    let key_len = stored_key.len();
    if key_len == 0 {
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
    let log_n = cost.trailing_zeros() as u8;
    // Re-derive with the params ENCODED IN THE HASH, not the current default.
    let Ok(params) = scrypt::Params::new_with_output_len(log_n, r, p, key_len) else {
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
        assert!(scrypt_verify("hunter2", &hash));
        assert!(!scrypt_verify("wrong", &hash));
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
        assert!(scrypt_verify("password", &hash));
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
        assert!(scrypt_verify("password", &hash));
        assert!(!scrypt_verify("wrong", &hash));
    }

    #[test]
    fn scrypt_rejects_empty_stored_key() {
        // A crafted hash with an empty key field must NOT trivially match.
        let salt = STANDARD_NO_PAD.encode(b"0123456789abcdef");
        let hash = format!("$scrypt$n=16384,r=8,p=1${}$", salt);
        assert!(!scrypt_verify("anything", &hash));
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
        assert!(scrypt_verify("hunter2", &hash));
        assert!(!scrypt_verify("wrong", &hash));
    }

    #[test]
    fn scrypt_rejects_malformed_hash() {
        // Legacy `salt:key` (no params), the old `scrypt$ln=` format, and
        // garbage must all fail closed.
        assert!(!scrypt_verify("password", "deadbeef:cafebabe"));
        assert!(!scrypt_verify("password", "not-a-hash"));
        assert!(!scrypt_verify("password", "scrypt$ln=14$r=8$p=1$aa$bb"));
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
            scrypt_verify(PASSWORD, SCRYPT),
            "stored scrypt hash no longer verifies"
        );
        assert!(!scrypt_verify("wrong password", SCRYPT));
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
