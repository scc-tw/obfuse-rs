//! Compile-time encryption logic.
//!
//! This module handles encryption at compile time within the proc-macro.
//! It supports both random key generation (using `getrandom`) and
//! deterministic key generation (using seeded RNG).

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

// Algorithm-specific constants
#[cfg(feature = "aes-256-gcm")]
pub const KEY_SIZE: usize = 32;
#[cfg(feature = "aes-256-gcm")]
pub const NONCE_SIZE: usize = 12;

#[cfg(all(feature = "aes-128-gcm", not(feature = "aes-256-gcm")))]
pub const KEY_SIZE: usize = 16;
#[cfg(all(feature = "aes-128-gcm", not(feature = "aes-256-gcm")))]
pub const NONCE_SIZE: usize = 12;

#[cfg(all(
    feature = "chacha20-poly1305",
    not(any(feature = "aes-256-gcm", feature = "aes-128-gcm"))
))]
pub const KEY_SIZE: usize = 32;
#[cfg(all(
    feature = "chacha20-poly1305",
    not(any(feature = "aes-256-gcm", feature = "aes-128-gcm"))
))]
pub const NONCE_SIZE: usize = 12;

#[cfg(all(
    feature = "xor",
    not(any(
        feature = "aes-256-gcm",
        feature = "aes-128-gcm",
        feature = "chacha20-poly1305"
    ))
))]
pub const KEY_SIZE: usize = 32;
#[cfg(all(
    feature = "xor",
    not(any(
        feature = "aes-256-gcm",
        feature = "aes-128-gcm",
        feature = "chacha20-poly1305"
    ))
))]
pub const NONCE_SIZE: usize = 12;

// Fallback for when no feature is enabled (will cause compile error in core)
#[cfg(not(any(
    feature = "aes-256-gcm",
    feature = "aes-128-gcm",
    feature = "chacha20-poly1305",
    feature = "xor"
)))]
pub const KEY_SIZE: usize = 32;
#[cfg(not(any(
    feature = "aes-256-gcm",
    feature = "aes-128-gcm",
    feature = "chacha20-poly1305",
    feature = "xor"
)))]
pub const NONCE_SIZE: usize = 12;

/// Encrypts plaintext at compile time.
///
/// # Arguments
/// * `plaintext` - The string bytes to encrypt
/// * `seed` - Optional seed for deterministic key generation
///
/// # Returns
/// Tuple of (ciphertext, key, nonce)
pub fn encrypt(
    plaintext: &[u8],
    seed: Option<String>,
) -> (Vec<u8>, [u8; KEY_SIZE], [u8; NONCE_SIZE]) {
    let (key, nonce) = generate_key_nonce(seed);
    let ciphertext = encrypt_with_algorithm(plaintext, &key, &nonce);
    (ciphertext, key, nonce)
}

/// Generates key and nonce, either randomly or from seed.
fn generate_key_nonce(seed: Option<String>) -> ([u8; KEY_SIZE], [u8; NONCE_SIZE]) {
    match seed {
        Some(seed_str) => generate_deterministic(seed_str),
        None => generate_random(),
    }
}

/// Generates random key and nonce using system entropy.
fn generate_random() -> ([u8; KEY_SIZE], [u8; NONCE_SIZE]) {
    let mut key = [0u8; KEY_SIZE];
    let mut nonce = [0u8; NONCE_SIZE];

    getrandom::getrandom(&mut key).expect("Failed to generate random key");
    getrandom::getrandom(&mut nonce).expect("Failed to generate random nonce");

    (key, nonce)
}

/// Generates deterministic key and nonce from a seed string.
fn generate_deterministic(seed: String) -> ([u8; KEY_SIZE], [u8; NONCE_SIZE]) {
    // Create a 32-byte seed for ChaCha20 from the string
    let seed_bytes = create_seed_bytes(&seed);
    let mut rng = ChaCha20Rng::from_seed(seed_bytes);

    let mut key = [0u8; KEY_SIZE];
    let mut nonce = [0u8; NONCE_SIZE];

    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut nonce);

    (key, nonce)
}

/// Creates a 32-byte seed from a string using simple hashing.
fn create_seed_bytes(seed: &str) -> [u8; 32] {
    let mut result = [0u8; 32];
    let seed_bytes = seed.as_bytes();

    // Simple deterministic mixing (not cryptographic, just for seed derivation)
    for (i, &byte) in seed_bytes.iter().enumerate() {
        result[i % 32] ^= byte;
        // Mix with position to avoid collisions
        result[(i + 7) % 32] =
            result[(i + 7) % 32].wrapping_add(byte.wrapping_mul((i as u8).wrapping_add(1)));
    }

    // Additional mixing passes for better distribution
    for _ in 0..3 {
        for i in 0..32 {
            result[i] = result[i]
                .wrapping_add(result[(i + 13) % 32])
                .wrapping_mul(result[(i + 7) % 32].wrapping_add(1));
        }
    }

    result
}

/// Encrypts plaintext using the selected algorithm.
#[cfg(feature = "aes-256-gcm")]
fn encrypt_with_algorithm(
    plaintext: &[u8],
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
) -> Vec<u8> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};

    let cipher = Aes256Gcm::new_from_slice(key).expect("Invalid key size");
    let nonce = Nonce::from_slice(nonce);

    cipher.encrypt(nonce, plaintext).expect("Encryption failed")
}

#[cfg(all(feature = "aes-128-gcm", not(feature = "aes-256-gcm")))]
fn encrypt_with_algorithm(
    plaintext: &[u8],
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
) -> Vec<u8> {
    use aes_gcm::{Aes128Gcm, KeyInit, Nonce, aead::Aead};

    let cipher = Aes128Gcm::new_from_slice(key).expect("Invalid key size");
    let nonce = Nonce::from_slice(nonce);

    cipher.encrypt(nonce, plaintext).expect("Encryption failed")
}

#[cfg(all(
    feature = "chacha20-poly1305",
    not(any(feature = "aes-256-gcm", feature = "aes-128-gcm"))
))]
fn encrypt_with_algorithm(
    plaintext: &[u8],
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
) -> Vec<u8> {
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::Aead};

    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("Invalid key size");
    let nonce = Nonce::from_slice(nonce);

    cipher.encrypt(nonce, plaintext).expect("Encryption failed")
}

#[cfg(all(
    feature = "xor",
    not(any(
        feature = "aes-256-gcm",
        feature = "aes-128-gcm",
        feature = "chacha20-poly1305"
    ))
))]
fn encrypt_with_algorithm(
    plaintext: &[u8],
    key: &[u8; KEY_SIZE],
    _nonce: &[u8; NONCE_SIZE],
) -> Vec<u8> {
    plaintext
        .iter()
        .enumerate()
        .map(|(i, &byte)| byte ^ key[i % KEY_SIZE])
        .collect()
}

// Fallback when no feature is enabled
#[cfg(not(any(
    feature = "aes-256-gcm",
    feature = "aes-128-gcm",
    feature = "chacha20-poly1305",
    feature = "xor"
)))]
fn encrypt_with_algorithm(
    _plaintext: &[u8],
    _key: &[u8; KEY_SIZE],
    _nonce: &[u8; NONCE_SIZE],
) -> Vec<u8> {
    panic!("No encryption algorithm feature enabled")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_same_seed() {
        let (key1, nonce1) = generate_deterministic("test_seed".to_string());
        let (key2, nonce2) = generate_deterministic("test_seed".to_string());

        assert_eq!(key1, key2);
        assert_eq!(nonce1, nonce2);
    }

    #[test]
    fn test_deterministic_different_seeds() {
        let (key1, _) = generate_deterministic("seed_a".to_string());
        let (key2, _) = generate_deterministic("seed_b".to_string());

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_random_is_different() {
        let (key1, _) = generate_random();
        let (key2, _) = generate_random();

        // Very unlikely to be equal
        assert_ne!(key1, key2);
    }
}
