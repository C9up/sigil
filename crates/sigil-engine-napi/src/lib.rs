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
}

#[napi]
pub fn argon2_hash(password: String, options: Option<Argon2Options>) -> Result<String> {
    wrap(move || {
        let opts = options
            .map(|o| sigil_engine::Argon2Options {
                memory_kib: o.memory_kib,
                iterations: o.iterations,
                parallelism: o.parallelism,
            })
            .unwrap_or(sigil_engine::Argon2Options {
                memory_kib: None,
                iterations: None,
                parallelism: None,
            });
        sigil_engine::argon2_hash(&password, opts)
    })
}

#[napi]
pub fn argon2_verify(password: String, hash: String) -> Result<bool> {
    Ok(sigil_engine::argon2_verify(&password, &hash))
}

#[napi]
pub fn bcrypt_hash(password: String, rounds: Option<u32>) -> Result<String> {
    wrap(|| sigil_engine::bcrypt_hash(&password, rounds.unwrap_or(12)))
}

#[napi]
pub fn bcrypt_verify(password: String, hash: String) -> Result<bool> {
    wrap(|| sigil_engine::bcrypt_verify(&password, &hash))
}

#[napi]
pub fn scrypt_hash(password: String, salt_len: Option<u32>, key_len: Option<u32>) -> Result<String> {
    wrap(|| sigil_engine::scrypt_hash(
        &password,
        salt_len.unwrap_or(32) as usize,
        key_len.unwrap_or(64) as usize,
    ))
}

#[napi]
pub fn scrypt_verify(password: String, hash: String, key_len: Option<u32>) -> Result<bool> {
    Ok(sigil_engine::scrypt_verify(
        &password,
        &hash,
        key_len.unwrap_or(64) as usize,
    ))
}
