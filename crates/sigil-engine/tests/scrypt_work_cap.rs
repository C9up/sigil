//! A stored scrypt hash names its own cost, so it decides how much work
//! verifying it takes — and a hash is not necessarily one we wrote.
//!
//! Memory is `128 * r * (N + p + 2)` bytes and time grows with `N * r * p`.
//! Unbounded, one altered row makes every login attempt on that account cost
//! tens of seconds and gigabytes: measured, n=2^24 ran about half a minute where
//! the default takes 33ms. Two bounds apply: the configured `maxMemory`
//! (default 32 MiB), and a work cap set against real configurations — four
//! times OWASP's strongest scrypt recommendation — which holds whatever the
//! configuration says.

use sigil_engine::{scrypt_hash, scrypt_memory, scrypt_verify, ScryptOptions};
use std::time::Instant;

const MIB: u64 = 1024 * 1024;

/// A hash shaped exactly like a real one — 16-byte salt, 64-byte key — with
/// only the cost raised, so nothing but the cost can be why it is refused.
fn forged(n: u32, r: u32, p: u32) -> String {
    // 64 bytes as unpadded base64; the final `A` keeps the unused bits zero.
    let key = format!("{}A", "a".repeat(85));
    format!("$scrypt$n={n},r={r},p={p}$c2FsdHNhbHRzYWx0c2FsdA${key}")
}

#[test]
fn refuses_a_hash_demanding_absurd_work() {
    let start = Instant::now();
    // Even with the memory bound lifted, the work cap holds.
    assert!(!scrypt_verify(
        "guess",
        &forged(1 << 24, 8, 1),
        Some(u64::from(u32::MAX))
    ));
    // Refused on inspection, not after deriving: the point is the work avoided.
    assert!(
        start.elapsed().as_millis() < 50,
        "took {:?} — the cost was paid before being refused",
        start.elapsed()
    );
}

#[test]
fn the_cap_reads_every_parameter() {
    // r and p multiply the work just as N does, so a modest N with an absurd
    // block size must be refused too.
    assert!(!scrypt_verify("guess", &forged(16384, 100_000, 1), None));
    assert!(!scrypt_verify("guess", &forged(16384, 8, 100_000), None));
}

#[test]
fn refuses_a_hash_whose_working_set_exceeds_max_memory() {
    // n=2^18, r=8 is 256 MiB: within the work cap, eight times the default
    // maxMemory. Refused before deriving, not after.
    let start = Instant::now();
    assert!(!scrypt_verify("guess", &forged(1 << 18, 8, 1), None));
    assert!(
        start.elapsed().as_millis() < 50,
        "took {:?} — the derivation ran before being refused",
        start.elapsed()
    );
}

#[test]
fn the_memory_bound_is_the_one_node_applies() {
    // 128 * r * (N + p + 2): the default configuration fits in 32 MiB, and
    // doubling N does not — which is where `crypto.scrypt` refuses it too.
    assert_eq!(scrypt_memory(16384, 8, 1), 16_780_288);
    assert!(scrypt_memory(1 << 15, 8, 1) > 32 * MIB);
}

#[test]
fn a_raised_max_memory_lets_the_bigger_hash_verify() {
    let opts = ScryptOptions {
        cost: Some(1 << 15),
        max_memory: Some(64 * MIB),
        ..Default::default()
    };
    let hash = scrypt_hash("secret", opts).expect("hashes under the raised bound");

    assert!(scrypt_verify("secret", &hash, Some(64 * MIB)));
    // The same hash under the default bound is refused, even with the right
    // password.
    assert!(!scrypt_verify("secret", &hash, None));
}

#[test]
fn make_refuses_a_configuration_over_max_memory() {
    let opts = ScryptOptions {
        cost: Some(1 << 15),
        ..Default::default()
    };
    assert!(scrypt_hash("secret", opts).is_err());
}

#[test]
fn make_refuses_a_configuration_over_the_work_cap() {
    // Otherwise make would write a hash verify then refuses, forever.
    let opts = ScryptOptions {
        cost: Some(1 << 20),
        block_size: Some(8),
        max_memory: Some(u64::from(u32::MAX)),
        ..Default::default()
    };
    assert!(scrypt_hash("secret", opts).is_err());
}

#[test]
fn still_verifies_what_it_produces() {
    // The other half: the bounds must not refuse an ordinary hash.
    let hash = scrypt_hash("secret", ScryptOptions::default()).expect("hashes");

    assert!(scrypt_verify("secret", &hash, None));
    assert!(!scrypt_verify("wrong", &hash, None));
}

#[test]
fn still_verifies_a_deliberately_strong_configuration() {
    // OWASP's strongest scrypt recommendation must keep working, once
    // maxMemory is raised to fit it.
    let opts = ScryptOptions {
        cost: Some(1 << 17),
        block_size: Some(8),
        parallelization: Some(1),
        max_memory: Some(256 * MIB),
        ..Default::default()
    };
    let hash = scrypt_hash("secret", opts).expect("hashes");

    assert!(scrypt_verify("secret", &hash, Some(256 * MIB)));
}
