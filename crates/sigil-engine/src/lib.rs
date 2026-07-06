use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use password_hash::{rand_core::OsRng as PwOsRng, SaltString};

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
}

fn build_params(opts: &Argon2Options) -> Result<Params, String> {
    let any_set =
        opts.memory_kib.is_some() || opts.iterations.is_some() || opts.parallelism.is_some();
    if !any_set {
        return Ok(Params::DEFAULT);
    }
    let default = Params::DEFAULT;
    Params::new(
        opts.memory_kib.unwrap_or(default.m_cost()),
        opts.iterations.unwrap_or(default.t_cost()),
        opts.parallelism.unwrap_or(default.p_cost()),
        None,
    )
    .map_err(|e| format!("Argon2 params error: {}", e))
}

/// Build an Argon2 hasher for `make`. Borrows `opts.secret` when present, so the
/// returned instance is tied to `opts`' lifetime.
fn build_argon2(opts: &Argon2Options) -> Result<Argon2<'_>, String> {
    let params = build_params(opts)?;
    match opts.secret.as_deref() {
        Some(secret) => {
            Argon2::new_with_secret(secret, Algorithm::Argon2id, Version::V0x13, params)
                .map_err(|e| format!("Argon2 secret error: {}", e))
        }
        None => Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params)),
    }
}

pub fn argon2_hash(password: &str, opts: Argon2Options) -> Result<String, String> {
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(format!("Password exceeds maximum length of {} bytes", MAX_PASSWORD_BYTES));
    }
    let argon2 = build_argon2(&opts)?;
    let salt = SaltString::generate(&mut PwOsRng);
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("Argon2 hash error: {}", e))
}

pub fn argon2_verify(password: &str, hash: &str, secret: Option<&[u8]>) -> bool {
    if password.len() > MAX_PASSWORD_BYTES {
        return false;
    }
    let Ok(parsed) = PasswordHash::new(hash) else { return false };
    // verify_password reads the m/t/p params + salt encoded in the hash string;
    // only the secret has to be supplied by the caller. Build the instance with
    // that secret (or none) and DEFAULT params — the params are overridden by
    // the values carried in the hash.
    let argon2 = match secret {
        Some(secret) => {
            match Argon2::new_with_secret(
                secret,
                Algorithm::Argon2id,
                Version::V0x13,
                Params::DEFAULT,
            ) {
                Ok(a) => a,
                Err(_) => return false,
            }
        }
        None => Argon2::default(),
    };
    argon2.verify_password(password.as_bytes(), &parsed).is_ok()
}

pub fn bcrypt_hash(password: &str, rounds: u32) -> Result<String, String> {
    if password.len() > BCRYPT_MAX_BYTES {
        return Err(format!("Password exceeds bcrypt maximum of {} bytes", BCRYPT_MAX_BYTES));
    }
    if rounds < BCRYPT_MIN_COST {
        return Err(format!(
            "Bcrypt cost {} is below the minimum of {} (OWASP recommendation)",
            rounds, BCRYPT_MIN_COST
        ));
    }
    bcrypt::hash(password, rounds).map_err(|e| format!("Bcrypt hash error: {}", e))
}

pub fn bcrypt_verify(password: &str, hash: &str) -> Result<bool, String> {
    if password.len() > BCRYPT_MAX_BYTES {
        return Err(format!("Password exceeds bcrypt maximum of {} bytes", BCRYPT_MAX_BYTES));
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
        return Err(format!("Password exceeds maximum length of {} bytes", MAX_PASSWORD_BYTES));
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
    let params =
        scrypt::Params::new(log_n, r, p, key_len).map_err(|e| format!("Scrypt params error: {}", e))?;
    let mut salt = vec![0u8; salt_len];
    getrandom::getrandom(&mut salt).map_err(|e| format!("RNG error: {}", e))?;
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

/// Parse the Adonis-parity PHC scrypt string
/// `$scrypt$n=<cost>,r=<r>,p=<p>$<b64 salt>$<b64 hash>`.
fn parse_scrypt_hash(hash: &str) -> Option<(u32, u32, u32, Vec<u8>, Vec<u8>)> {
    let mut parts = hash.split('$');
    // Leading `$` yields an empty first segment.
    if parts.next()? != "" {
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
    Some((cost?, r?, p?, salt, stored_key))
}

pub fn scrypt_verify(password: &str, hash: &str) -> bool {
    if password.len() > MAX_PASSWORD_BYTES {
        return false;
    }
    let Some((cost, r, p, salt, stored_key)) = parse_scrypt_hash(hash) else { return false };
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
    let log_n = cost.trailing_zeros() as u8;
    // Re-derive with the params ENCODED IN THE HASH, not the current default.
    let Ok(params) = scrypt::Params::new(log_n, r, p, key_len) else { return false };
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
        let hash = bcrypt_hash("hunter2", 10).unwrap();
        assert!(hash.starts_with("$2b$"));
        assert!(bcrypt_verify("hunter2", &hash).unwrap());
        assert!(!bcrypt_verify("wrong", &hash).unwrap());
    }

    #[test]
    fn bcrypt_rejects_low_cost() {
        assert!(bcrypt_hash("password", 4).is_err());
    }

    #[test]
    fn bcrypt_rejects_oversized_password() {
        let long = "A".repeat(73);
        assert!(bcrypt_hash(&long, 10).is_err());
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
        let params = scrypt::Params::new(10, 8, 1, 64).unwrap();
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
}
