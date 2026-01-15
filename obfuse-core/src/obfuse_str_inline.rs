//! The `ObfuseStrInline` type - lazy-decrypting obfuscated string with inline decryption logic.
//!
//! This type is used when the `polymorphic` feature is enabled, providing unique inline
//! decryption code for each string without a central decryption function.

use std::fmt;
use std::ops::Deref;
use std::sync::OnceLock;

use crate::error::ObfuseError;

/// An obfuscated string that decrypts lazily using inline decryption code.
///
/// Unlike `ObfuseStr`, this type uses a closure containing unique decryption logic
/// for each string, eliminating central decryption points that aid reverse engineering.
///
/// # Security Model
///
/// This provides stronger obfuscation than `ObfuseStr` by:
/// - Using unique decryption logic for each string (no reusable patterns)
/// - Computing keys at runtime from expressions (not static data)
/// - Multiple layers of transformations (XOR, ADD/SUB, rotations)
/// - No central decryption function to analyze
///
/// # Thread Safety
///
/// `ObfuseStrInline` is thread-safe. Multiple threads can call `as_str()` concurrently;
/// decryption happens exactly once via `OnceLock`.
pub struct ObfuseStrInline {
    /// Inline decryption function (boxed to erase the specific closure type)
    decrypt_fn: Box<dyn Fn() -> Result<String, ObfuseError> + Send + Sync>,

    /// Lazily initialized decrypted plaintext
    decrypted: OnceLock<String>,
}

impl ObfuseStrInline {
    /// Creates a new `ObfuseStrInline` from an inline decryption function.
    ///
    /// This is called by the `obfuse!` macro and should not be used directly.
    #[doc(hidden)]
    #[must_use]
    pub fn new<F>(decrypt_fn: F) -> Self
    where
        F: Fn() -> Result<String, ObfuseError> + Send + Sync + 'static,
    {
        Self {
            decrypt_fn: Box::new(decrypt_fn),
            decrypted: OnceLock::new(),
        }
    }

    /// Returns the decrypted string, decrypting on first access.
    ///
    /// # Panics
    ///
    /// Panics if decryption fails. Use `try_as_str()` for error handling.
    #[inline]
    pub fn as_str(&self) -> &str {
        self.try_as_str()
            .unwrap_or_else(|e| panic!("ObfuseStrInline decryption failed: {e}"))
    }

    /// Returns the decrypted string, or an error if decryption fails.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The decrypted bytes are not valid UTF-8
    /// - AEAD authentication fails (if using combined encryption)
    /// - Memory allocation fails
    pub fn try_as_str(&self) -> Result<&str, ObfuseError> {
        if let Some(cached) = self.decrypted.get() {
            return Ok(cached.as_str());
        }

        // Perform decryption by calling the inline function
        let plaintext = (self.decrypt_fn)()?;

        // Store the result (we ignore the error since concurrent calls are fine)
        let _ = self.decrypted.set(plaintext);

        // Return the stored value - this should always succeed since we just set it
        // or another thread set it concurrently
        Ok(self
            .decrypted
            .get()
            .ok_or(ObfuseError::AllocationFailed)?
            .as_str())
    }

    /// Returns the decrypted bytes, decrypting on first access.
    ///
    /// # Panics
    ///
    /// This should never panic unless the inline decryption code is invalid.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.as_str().as_bytes()
    }

    /// Returns the decrypted bytes, or an error if decryption fails.
    ///
    /// # Errors
    ///
    /// Returns an error if decryption fails.
    pub fn try_as_bytes(&self) -> Result<&[u8], ObfuseError> {
        self.try_as_str().map(str::as_bytes)
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
    ///
    /// # Errors
    ///
    /// Returns an error if decryption fails.
    pub fn try_decrypt(&self) -> Result<(), ObfuseError> {
        self.try_as_str().map(|_| ())
    }
}

impl Deref for ObfuseStrInline {
    type Target = str;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl AsRef<str> for ObfuseStrInline {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<[u8]> for ObfuseStrInline {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for ObfuseStrInline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObfuseStrInline")
            .field("value", &"[REDACTED]")
            .field("decrypted", &self.is_decrypted())
            .finish()
    }
}

impl fmt::Display for ObfuseStrInline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
