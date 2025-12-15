//! XOR cipher decryption implementation.
//!
//! This is a simple obfuscation method, NOT cryptographically secure.
//! Use only when performance is critical and strong security is not required.

use crate::ObfuseError;

/// Key size for XOR cipher (32 bytes for consistency).
pub const KEY_SIZE: usize = 32;

/// Nonce size for XOR cipher (not used, but kept for API consistency).
pub const NONCE_SIZE: usize = 12;

/// Decrypts ciphertext using XOR cipher.
///
/// # Arguments
/// * `ciphertext` - The XOR-encrypted data
/// * `key` - Encryption key (bytes are cycled if shorter than ciphertext)
/// * `_nonce` - Unused, kept for API consistency
///
/// # Returns
/// Decrypted plaintext bytes.
///
/// # Security Warning
/// XOR cipher provides NO authentication. Use AEAD ciphers for real security.
pub fn decrypt(
    ciphertext: &[u8],
    key: &[u8; KEY_SIZE],
    _nonce: &[u8; NONCE_SIZE],
) -> Result<Box<[u8]>, ObfuseError> {
    let plaintext: Vec<u8> = ciphertext
        .iter()
        .enumerate()
        .map(|(i, &byte)| byte ^ key[i % KEY_SIZE])
        .collect();

    Ok(plaintext.into_boxed_slice())
}
