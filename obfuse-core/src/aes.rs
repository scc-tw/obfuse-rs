//! AES-GCM decryption implementations.

use crate::ObfuseError;

#[cfg(feature = "aes-256-gcm")]
pub use aes256::*;

#[cfg(all(feature = "aes-128-gcm", not(feature = "aes-256-gcm")))]
pub use aes128::*;

#[cfg(feature = "aes-256-gcm")]
mod aes256 {
    use super::*;
    use aes_gcm::{
        Aes256Gcm, KeyInit, Nonce,
        aead::Aead,
    };

    /// Key size for AES-256-GCM (32 bytes).
    pub const KEY_SIZE: usize = 32;

    /// Nonce size for AES-GCM (12 bytes).
    pub const NONCE_SIZE: usize = 12;

    /// Decrypts ciphertext using AES-256-GCM.
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
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ObfuseError::AuthenticationFailed)?;
        let nonce = Nonce::from_slice(nonce);

        cipher
            .decrypt(nonce, ciphertext)
            .map(|v| v.into_boxed_slice())
            .map_err(|_| ObfuseError::AuthenticationFailed)
    }
}

#[cfg(all(feature = "aes-128-gcm", not(feature = "aes-256-gcm")))]
mod aes128 {
    use super::*;
    use aes_gcm::{
        Aes128Gcm, KeyInit, Nonce,
        aead::Aead,
    };

    /// Key size for AES-128-GCM (16 bytes).
    pub const KEY_SIZE: usize = 16;

    /// Nonce size for AES-GCM (12 bytes).
    pub const NONCE_SIZE: usize = 12;

    /// Decrypts ciphertext using AES-128-GCM.
    pub fn decrypt(
        ciphertext: &[u8],
        key: &[u8; KEY_SIZE],
        nonce: &[u8; NONCE_SIZE],
    ) -> Result<Box<[u8]>, ObfuseError> {
        let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| ObfuseError::AuthenticationFailed)?;
        let nonce = Nonce::from_slice(nonce);

        cipher
            .decrypt(nonce, ciphertext)
            .map(|v| v.into_boxed_slice())
            .map_err(|_| ObfuseError::AuthenticationFailed)
    }
}
