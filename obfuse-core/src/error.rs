//! Error types for ObfuseStr decryption operations.

use std::fmt;

/// Errors that can occur during ObfuseStr decryption.
#[derive(Debug)]
pub enum ObfuseError {
    /// Memory allocation failed during decryption (OOM).
    AllocationFailed,

    /// AEAD authentication tag verification failed.
    /// Indicates ciphertext tampering or algorithm mismatch.
    AuthenticationFailed,

    /// Decrypted bytes are not valid UTF-8.
    InvalidUtf8(std::str::Utf8Error),
}

impl fmt::Display for ObfuseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AllocationFailed => write!(f, "memory allocation failed during decryption"),
            Self::AuthenticationFailed => {
                write!(f, "authentication failed - ciphertext may be corrupted")
            }
            Self::InvalidUtf8(e) => write!(f, "decrypted data is not valid UTF-8: {e}"),
        }
    }
}

impl std::error::Error for ObfuseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidUtf8(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::str::Utf8Error> for ObfuseError {
    fn from(e: std::str::Utf8Error) -> Self {
        Self::InvalidUtf8(e)
    }
}
