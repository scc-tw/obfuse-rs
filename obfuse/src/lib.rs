//! Compile-time string obfuscation with runtime decryption and secure memory wiping.
//!
//! # Overview
//!
//! `obfuse` provides compile-time string encryption with lazy runtime decryption.
//! Strings are encrypted during compilation and embedded in the binary as ciphertext.
//! They are decrypted only when accessed at runtime.
//!
//! # Security Warning
//!
//! This is **obfuscation**, not encryption. The encryption key is embedded in the
//! binary alongside the ciphertext. A determined attacker can extract both.
//!
//! **Appropriate uses:**
//! - Preventing casual inspection of binaries (`strings` command, hex editors)
//! - Stopping automated string extraction tools
//! - Basic protection against unsophisticated reverse engineering
//!
//! **NOT appropriate for:**
//! - Protecting highly sensitive secrets (use proper secrets management)
//! - Compliance requirements (PCI-DSS, HIPAA, SOC2, etc.)
//! - Scenarios where key extraction would be catastrophic
//!
//! # Features
//!
//! Exactly one encryption algorithm must be enabled (mutually exclusive):
//!
//! - `aes-256-gcm` (default) - AES-256 in GCM mode (strongest)
//! - `aes-128-gcm` - AES-128 in GCM mode
//! - `chacha20-poly1305` - ChaCha20-Poly1305 AEAD
//! - `xor` - Simple XOR cipher (fast, weakest)
//!
//! # Usage
//!
//! ## Basic Usage
//!
//! ```ignore
//! use obfuse::obfuse;
//!
//! fn main() {
//!     // String is encrypted at compile time
//!     let secret = obfuse!("my secret API key");
//!
//!     // Decrypted only when accessed
//!     println!("Secret: {}", secret.as_str());
//!
//!     // Memory is securely wiped when `secret` goes out of scope
//! }
//! ```
//!
//! ## Deterministic Mode (for Testing/CI)
//!
//! ```ignore
//! use obfuse::obfuse;
//!
//! fn main() {
//!     // Same seed = same encryption = reproducible builds
//!     let secret = obfuse!("my secret", seed = "test_seed");
//!     println!("{}", secret.as_str());
//! }
//! ```
//!
//! ## Error Handling
//!
//! ```ignore
//! use obfuse::{obfuse, ObfuseError};
//!
//! fn main() {
//!     let secret = obfuse!("sensitive data");
//!
//!     match secret.try_as_str() {
//!         Ok(s) => println!("Secret: {s}"),
//!         Err(ObfuseError::AllocationFailed) => {
//!             eprintln!("Out of memory during decryption");
//!         }
//!         Err(ObfuseError::AuthenticationFailed) => {
//!             eprintln!("Decryption failed - binary may be corrupted");
//!         }
//!         Err(ObfuseError::InvalidUtf8(e)) => {
//!             eprintln!("Invalid UTF-8: {e}");
//!         }
//!     }
//! }
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

// Re-export the macro
pub use obfuse_macros::obfuse;

// Re-export core types
pub use obfuse_core::{ObfuseError, ObfuseStr};
