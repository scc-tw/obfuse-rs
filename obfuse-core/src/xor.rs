//! XOR cipher decryption implementation with MBA obfuscation.
//!
//! This module uses Mixed Boolean-Arithmetic (MBA) transformations to obfuscate
//! the XOR decryption logic, making it significantly harder for decompilers
//! like IDA's Hex-Rays to simplify the code.
//!
//! # Security Warning
//! XOR cipher provides NO authentication. Use AEAD ciphers for real security.

use crate::ObfuseError;
use crate::mba;

/// Key size for XOR cipher (32 bytes for consistency).
pub const KEY_SIZE: usize = 32;

/// Nonce size for XOR cipher (not used, but kept for API consistency).
pub const NONCE_SIZE: usize = 12;

/// Decrypts ciphertext using MBA-obfuscated XOR cipher.
///
/// This implementation uses Mixed Boolean-Arithmetic transformations
/// to make the decryption logic extremely difficult to reverse engineer.
/// The XOR operation `a ^ b` is replaced with complex MBA expressions
/// that are mathematically equivalent but resist decompiler simplification.
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
#[allow(clippy::unnecessary_wraps)] // Result needed for API consistency with AEAD ciphers
pub fn decrypt(
    ciphertext: &[u8],
    key: &[u8; KEY_SIZE],
    _nonce: &[u8; NONCE_SIZE],
) -> Result<Box<[u8]>, ObfuseError> {
    // Use MBA-obfuscated XOR decryption
    let plaintext = mba::mba_decrypt_xor(ciphertext, key, KEY_SIZE);
    Ok(plaintext.into_boxed_slice())
}
