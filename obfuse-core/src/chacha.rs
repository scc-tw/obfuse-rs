//! ChaCha20-Poly1305 decryption implementation.

use crate::ObfuseError;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};

/// Key size for ChaCha20-Poly1305 (32 bytes).
pub const KEY_SIZE: usize = 32;

/// Nonce size for ChaCha20-Poly1305 (12 bytes).
pub const NONCE_SIZE: usize = 12;

/// Decrypts ciphertext using ChaCha20-Poly1305.
///
/// # Arguments
/// * `ciphertext` - The encrypted data with authentication tag
/// * `key` - 32-byte encryption key
/// * `nonce` - 12-byte nonce
///
/// # Returns
/// Decrypted plaintext bytes or an error.
pub fn decrypt(
    ciphertext: &[u8],
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
) -> Result<Box<[u8]>, ObfuseError> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|_| ObfuseError::AuthenticationFailed)?;
    let nonce = Nonce::from_slice(nonce);

    cipher
        .decrypt(nonce, ciphertext)
        .map(Vec::into_boxed_slice)
        .map_err(|_| ObfuseError::AuthenticationFailed)
}
