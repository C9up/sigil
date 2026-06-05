use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use password_hash::{rand_core::OsRng as PwOsRng, SaltString};

const MAX_PASSWORD_BYTES: usize = 1024;
const BCRYPT_MAX_BYTES: usize = 72;
const BCRYPT_MIN_COST: u32 = 10;

/// Tunables for `argon2_hash`. `None` falls back to `Argon2::default()`
/// (Argon2id, m=19456 KiB, t=2, p=1 — OWASP minimum).
#[derive(Debug, Clone, Copy)]
pub struct Argon2Options {
    /// Memory cost in KiB. Must be ≥ 8.
    pub memory_kib: Option<u32>,
    /// Time cost (iterations). Must be ≥ 1.
    pub iterations: Option<u32>,
    /// Parallelism (lanes). Must be ≥ 1.
    pub parallelism: Option<u32>,
}

fn build_argon2(opts: Argon2Options) -> Result<Argon2<'static>, String> {
    let any_set = opts.memory_kib.is_some()
        || opts.iterations.is_some()
        || opts.parallelism.is_some();
    if !any_set {
        return Ok(Argon2::default());
    }
    let default = Params::DEFAULT;
    let params = Params::new(
        opts.memory_kib.unwrap_or(default.m_cost()),
        opts.iterations.unwrap_or(default.t_cost()),
        opts.parallelism.unwrap_or(default.p_cost()),
        None,
    )
    .map_err(|e| format!("Argon2 params error: {}", e))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

pub fn argon2_hash(password: &str, opts: Argon2Options) -> Result<String, String> {
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(format!("Password exceeds maximum length of {} bytes", MAX_PASSWORD_BYTES));
    }
    let argon2 = build_argon2(opts)?;
    let salt = SaltString::generate(&mut PwOsRng);
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("Argon2 hash error: {}", e))
}

pub fn argon2_verify(password: &str, hash: &str) -> bool {
    if password.len() > MAX_PASSWORD_BYTES {
        return false;
    }
    let Ok(parsed) = PasswordHash::new(hash) else { return false };
    // verify_password reads the params encoded in the hash string — caller
    // doesn't need to pass them. Use the default Argon2 instance.
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
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

pub fn scrypt_hash(password: &str, salt_len: usize, key_len: usize) -> Result<String, String> {
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(format!("Password exceeds maximum length of {} bytes", MAX_PASSWORD_BYTES));
    }
    let mut salt = vec![0u8; salt_len];
    getrandom::getrandom(&mut salt).map_err(|e| format!("RNG error: {}", e))?;
    let params = scrypt::Params::recommended();
    let mut key = vec![0u8; key_len];
    scrypt::scrypt(password.as_bytes(), &salt, &params, &mut key)
        .map_err(|e| format!("Scrypt error: {}", e))?;
    // Self-describing format: the work parameters travel WITH the hash, like
    // the PHC strings argon2/bcrypt emit. The previous `salt:key` form stored
    // none, so `verify` had to assume `Params::recommended()` — meaning a
    // future bump of the scrypt crate's recommendation would silently make
    // every stored hash unverifiable. Encoding ln/r/p pins each hash to the
    // params it was actually derived with.
    Ok(format!(
        "scrypt$ln={}$r={}$p={}${}${}",
        params.log_n(),
        params.r(),
        params.p(),
        hex::encode(&salt),
        hex::encode(&key)
    ))
}

/// Parse the self-describing scrypt format `scrypt$ln=<n>$r=<n>$p=<n>$<salt_hex>$<key_hex>`.
fn parse_scrypt_hash(hash: &str) -> Option<(u8, u32, u32, Vec<u8>, Vec<u8>)> {
    let mut parts = hash.split('$');
    if parts.next()? != "scrypt" {
        return None;
    }
    let log_n: u8 = parts.next()?.strip_prefix("ln=")?.parse().ok()?;
    let r: u32 = parts.next()?.strip_prefix("r=")?.parse().ok()?;
    let p: u32 = parts.next()?.strip_prefix("p=")?.parse().ok()?;
    let salt = hex::decode(parts.next()?).ok()?;
    let stored_key = hex::decode(parts.next()?).ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((log_n, r, p, salt, stored_key))
}

pub fn scrypt_verify(password: &str, hash: &str, key_len: usize) -> bool {
    if password.len() > MAX_PASSWORD_BYTES {
        return false;
    }
    let Some((log_n, r, p, salt, stored_key)) = parse_scrypt_hash(hash) else { return false };
    if stored_key.len() != key_len {
        return false;
    }
    // Re-derive with the params ENCODED IN THE HASH, not the current
    // recommendation — that's the whole point of storing them.
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

    const DEFAULT_ARGON2: Argon2Options = Argon2Options {
        memory_kib: None,
        iterations: None,
        parallelism: None,
    };

    #[test]
    fn argon2_round_trip() {
        let hash = argon2_hash("hunter2", DEFAULT_ARGON2).unwrap();
        assert!(hash.starts_with("$argon2"));
        assert!(argon2_verify("hunter2", &hash));
        assert!(!argon2_verify("wrong", &hash));
    }

    #[test]
    fn argon2_random_salts() {
        let h1 = argon2_hash("password", DEFAULT_ARGON2).unwrap();
        let h2 = argon2_hash("password", DEFAULT_ARGON2).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn argon2_honors_custom_params() {
        // Custom params must produce a parseable hash and verify against
        // itself. The encoded params in the hash string drive `verify`, so
        // we don't have to thread the options through.
        let opts = Argon2Options {
            memory_kib: Some(32 * 1024),
            iterations: Some(3),
            parallelism: Some(2),
        };
        let hash = argon2_hash("password", opts).unwrap();
        assert!(hash.contains("m=32768"));
        assert!(hash.contains("t=3"));
        assert!(hash.contains("p=2"));
        assert!(argon2_verify("password", &hash));
    }

    #[test]
    fn argon2_rejects_invalid_params() {
        let bad = Argon2Options {
            memory_kib: Some(1), // below crate minimum (8)
            iterations: None,
            parallelism: None,
        };
        assert!(argon2_hash("password", bad).is_err());
    }

    #[test]
    fn argon2_invalid_hash() {
        assert!(!argon2_verify("password", "not_a_valid_hash"));
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
        let hash = scrypt_hash("hunter2", 32, 64).unwrap();
        // Self-describing PHC-style prefix carries the work params.
        assert!(hash.starts_with("scrypt$ln="));
        assert!(scrypt_verify("hunter2", &hash, 64));
        assert!(!scrypt_verify("wrong", &hash, 64));
    }

    #[test]
    fn scrypt_wrong_key_len() {
        let hash = scrypt_hash("password", 32, 64).unwrap();
        assert!(!scrypt_verify("password", &hash, 32));
    }

    #[test]
    fn scrypt_verify_reads_params_from_hash() {
        // A hash derived with NON-recommended (deliberately low) params must
        // still verify — proving verify reads ln/r/p from the string instead
        // of assuming the current `Params::recommended()`. This is the exact
        // breakage the old `salt:key` format would have suffered on a crate
        // recommendation bump.
        let salt = b"0123456789abcdef";
        let params = scrypt::Params::new(14, 8, 1, 64).unwrap();
        let mut key = vec![0u8; 64];
        scrypt::scrypt(b"hunter2", salt, &params, &mut key).unwrap();
        let hash = format!(
            "scrypt$ln=14$r=8$p=1${}${}",
            hex::encode(salt),
            hex::encode(&key)
        );
        assert!(scrypt_verify("hunter2", &hash, 64));
        assert!(!scrypt_verify("wrong", &hash, 64));
    }

    #[test]
    fn scrypt_rejects_malformed_hash() {
        // Legacy `salt:key` (no params) and garbage must fail closed.
        assert!(!scrypt_verify("password", "deadbeef:cafebabe", 64));
        assert!(!scrypt_verify("password", "not-a-hash", 64));
    }
}
