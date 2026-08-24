use napi::bindgen_prelude::*;
use napi_derive::napi;
use std::panic::catch_unwind;

fn wrap<T, F>(f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> std::result::Result<T, String> + std::panic::UnwindSafe,
{
    match catch_unwind(f) {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(Error::from_reason(e)),
        Err(_) => Err(Error::from_reason("Internal panic in sigil engine")),
    }
}

#[napi(object)]
pub struct Argon2Options {
    /// Memory cost in KiB. ≥ 8.
    pub memory_kib: Option<u32>,
    /// Time cost (iterations). ≥ 1.
    pub iterations: Option<u32>,
    /// Parallelism (lanes). ≥ 1.
    pub parallelism: Option<u32>,
    /// Secret pepper. Not stored in the hash; required identically at verify.
    pub secret: Option<Buffer>,
    /// Variant: "d", "i" or "id" (Adonis `variant`). Default "id".
    pub variant: Option<String>,
    /// Output length in bytes (Adonis `hashLength`). Default 32.
    pub hash_length: Option<u32>,
    /// Salt size in bytes (Adonis `saltSize`). Default 16.
    pub salt_length: Option<u32>,
}

#[napi(object)]
pub struct ScryptOptions {
    /// CPU/memory cost (N). Power of two > 1. Default 16384.
    pub cost: Option<u32>,
    /// Block size (r). Default 8.
    pub block_size: Option<u32>,
    /// Parallelization (p). Default 1.
    pub parallelization: Option<u32>,
    /// Derived key length in bytes. Default 64.
    pub key_length: Option<u32>,
    /// Salt size in bytes. Default 16.
    pub salt_length: Option<u32>,
}

#[napi]
pub fn argon2_hash(password: String, options: Option<Argon2Options>) -> Result<String> {
    // Convert the Buffer to an owned Vec BEFORE the unwind-safe closure — the
    // napi Buffer is not UnwindSafe.
    let opts = options
        .map(|o| sigil_engine::Argon2Options {
            memory_kib: o.memory_kib,
            iterations: o.iterations,
            parallelism: o.parallelism,
            secret: o.secret.map(|b| b.to_vec()),
            variant: o.variant,
            hash_length: o.hash_length.map(|v| v as usize),
            salt_length: o.salt_length.map(|v| v as usize),
        })
        .unwrap_or_default();
    wrap(move || sigil_engine::argon2_hash(&password, opts))
}

#[napi]
pub fn argon2_verify(password: String, hash: String, secret: Option<Buffer>) -> Result<bool> {
    let secret_vec = secret.map(|b| b.to_vec());
    Ok(sigil_engine::argon2_verify(
        &password,
        &hash,
        secret_vec.as_deref(),
    ))
}

#[napi]
pub fn bcrypt_hash(
    password: String,
    rounds: Option<u32>,
    version: Option<u32>,
    salt_length: Option<u32>,
) -> Result<String> {
    wrap(move || {
        sigil_engine::bcrypt_hash(
            &password,
            rounds.unwrap_or(12),
            version,
            salt_length.map(|v| v as usize),
        )
    })
}

#[napi]
pub fn bcrypt_verify(password: String, hash: String) -> Result<bool> {
    wrap(|| sigil_engine::bcrypt_verify(&password, &hash))
}

#[napi]
pub fn scrypt_hash(password: String, options: Option<ScryptOptions>) -> Result<String> {
    let opts = options
        .map(|o| sigil_engine::ScryptOptions {
            cost: o.cost,
            block_size: o.block_size,
            parallelization: o.parallelization,
            key_length: o.key_length.map(|v| v as usize),
            salt_length: o.salt_length.map(|v| v as usize),
        })
        .unwrap_or_default();
    wrap(move || sigil_engine::scrypt_hash(&password, opts))
}

#[napi]
pub fn scrypt_verify(password: String, hash: String) -> Result<bool> {
    Ok(sigil_engine::scrypt_verify(&password, &hash))
}
