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
#[cfg(not(feature = "polymorphic"))]
pub use obfuse_core::{ObfuseError, ObfuseStr};

#[cfg(feature = "polymorphic")]
pub use obfuse_core::{ObfuseError, ObfuseStr, ObfuseStrInline};

/// Obfuscated `OBFUSE_RS_ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_1FAEFB6177B4672DEE07F9D3AFC62588CCD2631EDCF22E8CCC1FB35B501C9C86` embedded in binary for verification (AES-256-GCM, seed: `binary_check`).
#[cfg(all(not(feature = "polymorphic"), feature = "aes-256-gcm"))]
#[used]
#[doc(hidden)]
pub static _OBFUSCATED_OBFUSE_RS_ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_1FAEFB6177B4672DEE07F9D3AFC62588CCD2631EDCF22E8CCC1FB35B501C9C86: ObfuseStr = ObfuseStr::new(
    &[
        191, 47, 90, 80, 182, 56, 49, 242, 70, 249, 36, 0, 46, 200, 150, 61, 3, 27, 228, 22, 78,
        223,
    ],
    [
        85, 34, 130, 22, 245, 213, 28, 10, 57, 101, 209, 200, 44, 4, 188, 15, 8, 122, 114, 203,
        227, 70, 167, 28, 103, 106, 87, 120, 27, 230, 98, 214,
    ],
    [200, 209, 234, 6, 37, 145, 138, 206, 150, 161, 229, 250],
);

/// Plaintext `OBFUSE_RS_ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_1FAEFB6177B4672DEE07F9D3AFC62588CCD2631EDCF22E8CCC1FB35B501C9C86` embedded in binary for verification contrast.
#[cfg(all(not(feature = "polymorphic"), feature = "aes-256-gcm"))]
#[used]
#[doc(hidden)]
pub static _PLAINTEXT_OBFUSE_RS_ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_1FAEFB6177B4672DEE07F9D3AFC62588CCD2631EDCF22E8CCC1FB35B501C9C86: &str = "OBFUSE_RS_ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_1FAEFB6177B4672DEE07F9D3AFC62588CCD2631EDCF22E8CCC1FB35B501C9C86";

/// Binary verification function: decrypts obfuscated `OBFUSE_RS_ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_1FAEFB6177B4672DEE07F9D3AFC62588CCD2631EDCF22E8CCC1FB35B501C9C86` and returns it alongside plaintext.
#[cfg(all(not(feature = "polymorphic"), feature = "aes-256-gcm"))]
#[doc(hidden)]
#[allow(dead_code)]
#[inline(never)]
pub fn _OBFUSE_RS_ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_1FAEFB6177B4672DEE07F9D3AFC62588CCD2631EDCF22E8CCC1FB35B501C9C86()
-> (&'static str, &'static str) {
    (_OBFUSCATED_OBFUSE_RS_ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_1FAEFB6177B4672DEE07F9D3AFC62588CCD2631EDCF22E8CCC1FB35B501C9C86.as_str(), _PLAINTEXT_OBFUSE_RS_ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_1FAEFB6177B4672DEE07F9D3AFC62588CCD2631EDCF22E8CCC1FB35B501C9C86)
}

#[cfg(all(not(feature = "polymorphic"), feature = "aes-256-gcm"))]
#[used]
#[doc(hidden)]
#[allow(dead_code)]
static _OBFUSE_RS_ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_1FAEFB6177B4672DEE07F9D3AFC62588CCD2631EDCF22E8CCC1FB35B501C9C86_FN: fn() -> (&'static str, &'static str) = _OBFUSE_RS_ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_1FAEFB6177B4672DEE07F9D3AFC62588CCD2631EDCF22E8CCC1FB35B501C9C86;
