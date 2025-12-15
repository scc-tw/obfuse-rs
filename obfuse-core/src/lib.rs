//! Core runtime logic for obfuse string obfuscation.
//!
//! This crate provides the runtime decryption logic and the `ObfuseStr` type.
//! It is used internally by the `obfuse` crate and should not be used directly.
//!
//! # Feature Flags
//!
//! Exactly one encryption algorithm must be enabled:
//!
//! - `aes-256-gcm` (default) - AES-256 in GCM mode
//! - `aes-128-gcm` - AES-128 in GCM mode
//! - `chacha20-poly1305` - ChaCha20-Poly1305 AEAD
//! - `xor` - Simple XOR cipher (fast, less secure)

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

mod error;
mod obfuse_str;

// Only compile the module that's actually selected (mutually exclusive features)
#[cfg(any(
    feature = "aes-256-gcm",
    all(feature = "aes-128-gcm", not(feature = "aes-256-gcm"))
))]
mod aes;

#[cfg(all(
    feature = "chacha20-poly1305",
    not(any(feature = "aes-256-gcm", feature = "aes-128-gcm"))
))]
mod chacha;

#[cfg(all(
    feature = "xor",
    not(any(
        feature = "aes-256-gcm",
        feature = "aes-128-gcm",
        feature = "chacha20-poly1305"
    ))
))]
mod xor;

pub use error::ObfuseError;
pub use obfuse_str::ObfuseStr;

// Re-export constants for use by the macro crate
#[cfg(feature = "aes-256-gcm")]
pub use aes::{KEY_SIZE, NONCE_SIZE};

#[cfg(all(feature = "aes-128-gcm", not(feature = "aes-256-gcm")))]
pub use aes::{KEY_SIZE, NONCE_SIZE};

#[cfg(all(
    feature = "chacha20-poly1305",
    not(any(feature = "aes-256-gcm", feature = "aes-128-gcm"))
))]
pub use chacha::{KEY_SIZE, NONCE_SIZE};

#[cfg(all(
    feature = "xor",
    not(any(
        feature = "aes-256-gcm",
        feature = "aes-128-gcm",
        feature = "chacha20-poly1305"
    ))
))]
pub use xor::{KEY_SIZE, NONCE_SIZE};

// Compile-time check: ensure at least one algorithm is enabled
#[cfg(not(any(
    feature = "aes-256-gcm",
    feature = "aes-128-gcm",
    feature = "chacha20-poly1305",
    feature = "xor"
)))]
compile_error!(
    "At least one encryption algorithm feature must be enabled: \
     aes-256-gcm, aes-128-gcm, chacha20-poly1305, or xor"
);
