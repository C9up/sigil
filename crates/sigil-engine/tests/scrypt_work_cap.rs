//! A stored scrypt hash names its own cost, so it decides how much work
//! verifying it takes — and a hash is not necessarily one we wrote.
//!
//! Memory is `128 * N * r` bytes and time grows with `N * r * p`. Unbounded,
//! one altered row makes every login attempt on that account cost tens of
//! seconds and gigabytes: measured, n=2^24 ran about half a minute where the
//! default takes 33ms. The cap is set against real configurations — four times
//! OWASP's strongest scrypt recommendation — so it refuses the escalation
//! without refusing anything anyone would deploy.

use sigil_engine::{scrypt_hash, scrypt_verify, ScryptOptions};
use std::time::Instant;

/// A hash shaped exactly like a real one, with only the cost raised.
fn forged(n: u32, r: u32, p: u32) -> String {
    format!("$scrypt$n={n},r={r},p={p}$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaA")
}

#[test]
fn refuses_a_hash_demanding_absurd_work() {
    let start = Instant::now();
    assert!(!scrypt_verify("guess", &forged(1 << 24, 8, 1)));
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
    assert!(!scrypt_verify("guess", &forged(16384, 100_000, 1)));
    assert!(!scrypt_verify("guess", &forged(16384, 8, 100_000)));
}

#[test]
fn still_verifies_what_it_produces() {
    // The other half: the cap must not refuse an ordinary hash.
    let hash = scrypt_hash("secret", ScryptOptions::default()).expect("hashes");

    assert!(scrypt_verify("secret", &hash));
    assert!(!scrypt_verify("wrong", &hash));
}

#[test]
fn still_verifies_a_deliberately_strong_configuration() {
    // OWASP's strongest scrypt recommendation must keep working.
    let opts = ScryptOptions {
        cost: Some(1 << 17),
        block_size: Some(8),
        parallelization: Some(1),
        ..Default::default()
    };
    let hash = scrypt_hash("secret", opts).expect("hashes");

    assert!(scrypt_verify("secret", &hash));
}
