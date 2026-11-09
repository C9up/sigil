//! The N-API surface of `sigil-engine`.
//!
//! Every hash and verify runs as an `AsyncTask`: the key derivation is
//! computed on the libuv thread pool and the JavaScript side gets a Promise.
//! Run on the calling thread, it froze the event loop for its whole duration —
//! N concurrent logins meant N times the KDF cost during which the process
//! served nothing at all, to anyone.
//!
//! Arguments are copied into owned values (the password `String`, the secret
//! `Buffer` into a `Vec`) before the task is scheduled: nothing borrowed from
//! the JavaScript heap crosses to the worker thread.

use napi::bindgen_prelude::*;
use napi::{Env, Task};
use napi_derive::napi;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// One unit of engine work, run on the thread pool.
type Job<T> = Box<dyn FnOnce() -> std::result::Result<T, String> + Send>;

/// Run a job, turning both an engine error and a panic into a JavaScript
/// exception rather than unwinding across the FFI boundary.
fn run<T>(job: Option<Job<T>>) -> Result<T> {
    let job = job.ok_or_else(|| Error::from_reason("sigil engine task already ran"))?;
    match catch_unwind(AssertUnwindSafe(job)) {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(Error::from_reason(e)),
        Err(_) => Err(Error::from_reason("Internal panic in sigil engine")),
    }
}

/// A hash computation; resolves to the encoded hash.
pub struct HashTask {
    job: Option<Job<String>>,
}

#[napi]
impl Task for HashTask {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> Result<Self::Output> {
        run(self.job.take())
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

/// A verification; resolves to whether the value matched.
pub struct VerifyTask {
    job: Option<Job<bool>>,
}

#[napi]
impl Task for VerifyTask {
    type Output = bool;
    type JsValue = bool;

    fn compute(&mut self) -> Result<Self::Output> {
        run(self.job.take())
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

fn hash_task(
    job: impl FnOnce() -> std::result::Result<String, String> + Send + 'static,
) -> AsyncTask<HashTask> {
    AsyncTask::new(HashTask {
        job: Some(Box::new(job)),
    })
}

fn verify_task(
    job: impl FnOnce() -> std::result::Result<bool, String> + Send + 'static,
) -> AsyncTask<VerifyTask> {
    AsyncTask::new(VerifyTask {
        job: Some(Box::new(job)),
    })
}

#[napi(object)]
pub struct Argon2Options {
    /// Memory cost in KiB. ≥ 8 × parallelism.
    pub memory_kib: Option<u32>,
    /// Time cost (iterations). ≥ 2.
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

/// The Argon2 cost parameters used when the application configures none.
#[napi(object)]
pub struct Argon2Defaults {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

#[napi]
pub fn argon2_defaults() -> Argon2Defaults {
    let (memory_kib, iterations, parallelism) = sigil_engine::argon2_default_params();
    Argon2Defaults {
        memory_kib,
        iterations,
        parallelism,
    }
}

/// The most work a stored hash may ask for at verify time, per algorithm —
/// and so the most a configuration may produce.
#[napi(object)]
pub struct CostLimits {
    /// Argon2 `memory (KiB) * iterations`.
    pub max_argon2_work: u32,
    /// Bcrypt cost (log2 of the rounds).
    pub max_bcrypt_cost: u32,
    /// Scrypt `cost * blockSize * parallelization`.
    pub max_scrypt_work: u32,
}

#[napi]
pub fn cost_limits() -> Result<CostLimits> {
    let narrow =
        |v: u64| u32::try_from(v).map_err(|_| Error::from_reason("sigil cost limit exceeds u32"));
    Ok(CostLimits {
        max_argon2_work: narrow(sigil_engine::MAX_ARGON2_WORK)?,
        max_bcrypt_cost: sigil_engine::MAX_BCRYPT_COST,
        max_scrypt_work: narrow(sigil_engine::MAX_SCRYPT_WORK)?,
    })
}

#[napi(object)]
pub struct ScryptOptions {
    /// CPU/memory cost (N). Power of two > 1. Default 16384.
    pub cost: Option<u32>,
    /// Block size (r). Default 8.
    pub block_size: Option<u32>,
    /// Parallelization (p). Default 1.
    pub parallelization: Option<u32>,
    /// Derived key length in bytes, 64 to 128. Default 64.
    pub key_length: Option<u32>,
    /// Salt size in bytes. Default 16.
    pub salt_length: Option<u32>,
    /// Largest working set in bytes, `128 * r * (N + p + 2)`. Default 32 MiB.
    pub max_memory: Option<u32>,
}

#[napi]
pub fn argon2_hash(password: String, options: Option<Argon2Options>) -> AsyncTask<HashTask> {
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
    hash_task(move || sigil_engine::argon2_hash(&password, opts))
}

#[napi]
pub fn argon2_verify(
    password: String,
    hash: String,
    secret: Option<Buffer>,
) -> AsyncTask<VerifyTask> {
    let secret = secret.map(|b| b.to_vec());
    verify_task(move || {
        Ok(sigil_engine::argon2_verify(
            &password,
            &hash,
            secret.as_deref(),
        ))
    })
}

#[napi]
pub fn bcrypt_hash(
    password: String,
    rounds: Option<u32>,
    version: Option<u32>,
    salt_length: Option<u32>,
) -> AsyncTask<HashTask> {
    hash_task(move || {
        sigil_engine::bcrypt_hash(
            &password,
            rounds.unwrap_or(12),
            version,
            salt_length.map(|v| v as usize),
        )
    })
}

#[napi]
pub fn bcrypt_verify(password: String, hash: String) -> AsyncTask<VerifyTask> {
    verify_task(move || sigil_engine::bcrypt_verify(&password, &hash))
}

#[napi]
pub fn scrypt_hash(password: String, options: Option<ScryptOptions>) -> AsyncTask<HashTask> {
    let opts = options
        .map(|o| sigil_engine::ScryptOptions {
            cost: o.cost,
            block_size: o.block_size,
            parallelization: o.parallelization,
            key_length: o.key_length.map(|v| v as usize),
            salt_length: o.salt_length.map(|v| v as usize),
            max_memory: o.max_memory.map(u64::from),
        })
        .unwrap_or_default();
    hash_task(move || sigil_engine::scrypt_hash(&password, opts))
}

/// `max_memory` is the configured `maxMemory`: a stored hash whose working set
/// exceeds it is refused before deriving. Default 32 MiB.
#[napi]
pub fn scrypt_verify(
    password: String,
    hash: String,
    max_memory: Option<u32>,
) -> AsyncTask<VerifyTask> {
    verify_task(move || {
        Ok(sigil_engine::scrypt_verify(
            &password,
            &hash,
            max_memory.map(u64::from),
        ))
    })
}
