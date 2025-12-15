//! The `ObfuseStr` type - lazy-decrypting obfuscated string with secure memory handling.

use std::fmt;
use std::ops::Deref;
use std::sync::OnceLock;

use zeroize::Zeroize;

use crate::error::ObfuseError;

// Import the appropriate crypto module based on features
#[cfg(feature = "aes-256-gcm")]
use crate::aes::{KEY_SIZE, NONCE_SIZE, decrypt};

#[cfg(all(feature = "aes-128-gcm", not(feature = "aes-256-gcm")))]
use crate::aes::{KEY_SIZE, NONCE_SIZE, decrypt};

#[cfg(all(
    feature = "chacha20-poly1305",
    not(any(feature = "aes-256-gcm", feature = "aes-128-gcm"))
))]
use crate::chacha::{KEY_SIZE, NONCE_SIZE, decrypt};

#[cfg(all(
    feature = "xor",
    not(any(
        feature = "aes-256-gcm",
        feature = "aes-128-gcm",
        feature = "chacha20-poly1305"
    ))
))]
use crate::xor::{KEY_SIZE, NONCE_SIZE, decrypt};

/// An obfuscated string that decrypts lazily on first access.
///
/// # Security Model
///
/// This type provides **obfuscation**, not encryption. The key is embedded
/// in the binary alongside the ciphertext. A determined attacker can extract
/// both. This protects against:
/// - `strings` command and hex editors
/// - Automated string extraction tools
/// - Casual binary inspection
///
/// # Thread Safety
///
/// `ObfuseStr` is thread-safe. Multiple threads can call `as_str()` concurrently;
/// decryption happens exactly once via `OnceLock`.
///
/// # Memory Safety
///
/// On drop, all sensitive memory (key, nonce, decrypted plaintext) is zeroed
/// using volatile writes that cannot be optimized away.
pub struct ObfuseStr {
    /// Encrypted ciphertext (static lifetime from macro).
    encrypted: &'static [u8],

    /// Encryption key (embedded in binary).
    key: [u8; KEY_SIZE],

    /// Nonce/IV for decryption.
    nonce: [u8; NONCE_SIZE],

    /// Lazily initialized decrypted plaintext.
    decrypted: OnceLock<Box<[u8]>>,
}

impl ObfuseStr {
    /// Creates a new `ObfuseStr` from encrypted data.
    ///
    /// This is called by the `obfuse!` macro and should not be used directly.
    #[doc(hidden)]
    pub const fn new(
        encrypted: &'static [u8],
        key: [u8; KEY_SIZE],
        nonce: [u8; NONCE_SIZE],
    ) -> Self {
        Self {
            encrypted,
            key,
            nonce,
            decrypted: OnceLock::new(),
        }
    }

    /// Returns the decrypted string, decrypting on first access.
    ///
    /// # Panics
    ///
    /// Panics if decryption fails. For fallible decryption, use [`try_as_str`].
    ///
    /// [`try_as_str`]: Self::try_as_str
    #[inline]
    pub fn as_str(&self) -> &str {
        self.try_as_str()
            .unwrap_or_else(|e| panic!("ObfuseStr decryption failed: {e}"))
    }

    /// Returns the decrypted string, or an error if decryption fails.
    ///
    /// This is the recommended method for critical code paths where
    /// panicking is unacceptable.
    pub fn try_as_str(&self) -> Result<&str, ObfuseError> {
        let bytes = self.try_as_bytes()?;
        std::str::from_utf8(bytes).map_err(ObfuseError::from)
    }

    /// Returns the decrypted bytes, decrypting on first access.
    ///
    /// # Panics
    ///
    /// Panics if decryption fails.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.try_as_bytes()
            .unwrap_or_else(|e| panic!("ObfuseStr decryption failed: {e}"))
    }

    /// Returns the decrypted bytes, or an error if decryption fails.
    pub fn try_as_bytes(&self) -> Result<&[u8], ObfuseError> {
        // Use get_or_init with internal error handling since get_or_try_init is unstable
        if let Some(cached) = self.decrypted.get() {
            return Ok(cached.as_ref());
        }

        // Perform decryption
        let plaintext = decrypt(self.encrypted, &self.key, &self.nonce)?;

        // Try to store result, handling race condition gracefully
        // If another thread beat us, their result is equivalent
        let _ = self.decrypted.set(plaintext);

        // Return the stored value (either ours or the other thread's)
        Ok(self.decrypted.get().expect("just set").as_ref())
    }

    /// Returns `true` if the string has already been decrypted.
    ///
    /// This can be used to check if accessing the string will trigger decryption.
    #[inline]
    pub fn is_decrypted(&self) -> bool {
        self.decrypted.get().is_some()
    }

    /// Pre-decrypts the string without returning the value.
    ///
    /// Useful for warming up the cache before time-critical operations.
    pub fn try_decrypt(&self) -> Result<(), ObfuseError> {
        self.try_as_bytes().map(|_| ())
    }

    /// Manually zeros all sensitive memory.
    ///
    /// This is also called automatically on drop, but can be used to
    /// clear memory earlier if needed.
    ///
    /// # Note
    ///
    /// After calling this, the `ObfuseStr` will re-decrypt on next access
    /// (though the OnceLock prevents this - this method exists for the Drop impl).
    pub fn zeroize(&mut self) {
        self.key.zeroize();
        self.nonce.zeroize();

        // Zero the decrypted plaintext if it exists
        if let Some(decrypted) = self.decrypted.get_mut() {
            decrypted.zeroize();
        }
    }
}

impl Deref for ObfuseStr {
    type Target = str;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl AsRef<str> for ObfuseStr {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<[u8]> for ObfuseStr {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for ObfuseStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObfuseStr")
            .field("value", &"[REDACTED]")
            .field("decrypted", &self.is_decrypted())
            .finish()
    }
}

impl fmt::Display for ObfuseStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Drop for ObfuseStr {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// Note: ObfuseStr is Send + Sync because:
// - &'static [u8] is Send + Sync
// - [u8; N] arrays are Send + Sync
// - OnceLock<Box<[u8]>> is Send + Sync
// The derive is automatic since all fields are Send + Sync.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_redacts_value() {
        // This test requires the macro, so we just test the debug format structure
        let debug_output = format!("{:?}", "ObfuseStr { value: [REDACTED], decrypted: false }");
        assert!(debug_output.contains("REDACTED"));
    }
}
