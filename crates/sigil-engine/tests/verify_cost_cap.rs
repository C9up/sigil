//! Argon2 and bcrypt hashes name their own cost, exactly as scrypt hashes do,
//! so the same rule applies: a stored hash asking for far more work than any
//! real configuration is refused before deriving — and no configuration may
//! produce a hash that verify would then refuse.
//!
//! Measured before the cap: `m=262144,t=8` took two seconds per attempt and
//! `$2b$16$` close to three, and `$2b$31$` is 2^15 times that.

use sigil_engine::{
    argon2_hash, argon2_verify, bcrypt_hash, bcrypt_verify, Argon2Options, MAX_BCRYPT_COST,
};
use std::time::{Duration, Instant};

/// A real hash with its cost field rewritten, as an altered row would be.
fn with_argon2_cost(hash: &str, m: u32, t: u32) -> String {
    let mut fields: Vec<String> = hash.split('$').map(str::to_string).collect();
    fields[3] = format!("m={m},t={t},p=1");
    fields.join("$")
}

fn with_bcrypt_cost(hash: &str, cost: u32) -> String {
    format!("{}{:02}{}", &hash[..4], cost, &hash[6..])
}

fn assert_fast(start: Instant) {
    assert!(
        start.elapsed() < Duration::from_millis(50),
        "took {:?} — the cost was paid before being refused",
        start.elapsed()
    );
}

fn small_argon2() -> Argon2Options {
    Argon2Options {
        memory_kib: Some(1024),
        iterations: Some(2),
        parallelism: Some(1),
        ..Default::default()
    }
}

#[test]
fn argon2_refuses_a_hash_demanding_absurd_work() {
    let hash = argon2_hash("secret", small_argon2()).expect("hashes");
    for (m, t) in [(262_144, 8), (u32::MAX, 1), (1024, u32::MAX)] {
        let forged = with_argon2_cost(&hash, m, t);
        let start = Instant::now();
        assert!(!argon2_verify("secret", &forged, None), "m={m} t={t}");
        assert_fast(start);
    }
}

#[test]
fn argon2_refuses_a_hash_without_its_cost() {
    let hash = argon2_hash("secret", small_argon2()).expect("hashes");
    let mut fields: Vec<&str> = hash.split('$').collect();
    fields[3] = "p=1";
    assert!(!argon2_verify("secret", &fields.join("$"), None));
}

#[test]
fn argon2_make_refuses_a_configuration_over_the_cap() {
    let over = Argon2Options {
        memory_kib: Some(1 << 19),
        iterations: Some(3),
        ..Default::default()
    };
    assert!(argon2_hash("secret", over).is_err());
}

#[test]
fn argon2_still_verifies_the_defaults() {
    let hash = argon2_hash("secret", Argon2Options::default()).expect("hashes");
    assert!(hash.contains("m=65536,t=3,p=4"), "{hash}");
    assert!(argon2_verify("secret", &hash, None));
}

#[test]
fn argon2_refuses_fewer_than_two_iterations() {
    let one = Argon2Options {
        iterations: Some(1),
        ..small_argon2()
    };
    assert!(argon2_hash("secret", one).is_err());
}

#[test]
fn bcrypt_refuses_a_hash_demanding_absurd_work() {
    let hash = bcrypt_hash("secret", 10, None, None).expect("hashes");
    for cost in [MAX_BCRYPT_COST + 1, 20, 31] {
        let forged = with_bcrypt_cost(&hash, cost);
        let start = Instant::now();
        assert_eq!(bcrypt_verify("secret", &forged), Ok(false), "cost {cost}");
        assert_fast(start);
    }
}

#[test]
fn bcrypt_make_refuses_a_cost_over_the_cap() {
    assert!(bcrypt_hash("secret", MAX_BCRYPT_COST + 1, None, None).is_err());
}

#[test]
fn bcrypt_still_verifies_an_ordinary_hash() {
    let hash = bcrypt_hash("secret", 12, None, None).expect("hashes");
    assert_eq!(bcrypt_verify("secret", &hash), Ok(true));
    assert_eq!(bcrypt_verify("wrong", &hash), Ok(false));
}
