# obfuse-rs Architecture

## Overview

**Purpose**: Compile-time string obfuscation with runtime decryption and secure memory wiping.
**Type**: Rust library with procedural macros
**License**: MIT
**Rust**: Edition 2024, rust-version 1.91

## Workspace Structure

```
obfuse-rs/
├── Cargo.toml              # Workspace root
├── obfuse/                 # Public facade (users import this)
│   └── src/lib.rs          # Re-exports macro and ObfuseStr
├── obfuse-macros/          # Procedural macro crate
│   └── src/lib.rs          # obfuse! macro implementation
└── obfuse-core/            # Runtime logic
    └── src/
        ├── lib.rs          # Module exports
        ├── obfuse_str.rs   # ObfuseStr type
        ├── error.rs        # ObfuseError
        ├── aes.rs          # AES-GCM decryption
        ├── chacha.rs       # ChaCha20-Poly1305 decryption
        └── xor.rs          # XOR decryption
```

## Feature Flags

| Feature | Algorithm | Key Size | Default |
|---------|-----------|----------|---------|
| `aes-256-gcm` | AES-256-GCM | 32 bytes | Yes |
| `aes-128-gcm` | AES-128-GCM | 16 bytes | No |
| `chacha20-poly1305` | ChaCha20-Poly1305 | 32 bytes | No |
| `xor` | XOR cipher | variable | No |

Features are mutually exclusive.

## Core Types

### ObfuseStr

```rust
pub struct ObfuseStr {
    encrypted: &'static [u8],
    key: [u8; KEY_SIZE],           // Key always embedded
    nonce: [u8; NONCE_SIZE],
    decrypted: OnceLock<Box<[u8]>>,
}

impl ObfuseStr {
    pub fn as_str(&self) -> &str;
    pub fn try_as_str(&self) -> Result<&str, ObfuseError>;
    pub fn as_bytes(&self) -> &[u8];
    pub fn try_as_bytes(&self) -> Result<&[u8], ObfuseError>;
    pub fn is_decrypted(&self) -> bool;
    pub fn try_decrypt(&self) -> Result<(), ObfuseError>;
    pub fn zeroize(&mut self);
}
```

### ObfuseError

```rust
pub enum ObfuseError {
    AllocationFailed,                    // OOM
    AuthenticationFailed,                // AEAD tag mismatch
    InvalidUtf8(std::str::Utf8Error),   // Bad UTF-8
}
```

### Macro

```rust
// Random key (production) - different each compile
obfuse!("literal") -> ObfuseStr

// Deterministic key (testing/CI) - reproducible
obfuse!("literal", seed = "test_seed") -> ObfuseStr
```

Both produce same `ObfuseStr` type, same runtime behavior (auto-decrypt).

## Dependencies (Latest Dec 2024)

| Package | Version | Purpose |
|---------|---------|---------|
| aes-gcm | 0.10.3 | AES-GCM AEAD |
| chacha20poly1305 | 0.10.1 | ChaCha20-Poly1305 |
| zeroize | 1.8.1 | Secure memory zeroing |
| getrandom | 0.2.15 | Compile-time entropy (random mode) |
| rand | 0.8.5 | Seeded RNG (deterministic mode) |
| syn | 2.0.90 | Proc-macro parsing |
| quote | 1.0.37 | Proc-macro codegen |
| proc-macro2 | 1.0.92 | Proc-macro utilities |

## Security Model

**This is OBFUSCATION, not real encryption.**

Binary always contains: `(ciphertext, key, nonce)` -> Key extractable by attacker

### Build Modes

| Mode | Key Generation | Use Case |
|------|---------------|----------|
| Random (default) | `getrandom` each compile | Production - unique per build |
| Seeded | Deterministic from seed | Testing/CI - reproducible |

Both modes embed key in binary. Seed only affects reproducibility, not security.

### Threat Model

**Protects against**: `strings`, hex editors, casual binary inspection
**Does NOT protect against**: Determined attackers, debuggers, RE tools

For real secrets: Use runtime secrets management (env vars, Vault, etc.)

## Implementation Notes

1. **Thread Safety**: Use `OnceLock` for lazy decryption cache
2. **Memory Zeroing**: Use `zeroize` crate + volatile writes on Drop
3. **Compile-time RNG**: Use `getrandom` for random mode, `rand` with seed for deterministic
4. **Debug Trait**: Implement as `ObfuseStr([REDACTED])`

## Implementation Checklist

### Core
- [x] Create workspace with 3 crates
- [x] Implement ObfuseStr with OnceLock
- [x] Implement ObfuseError
- [x] Add zeroize on Drop
- [x] Add Debug trait (redacted)

### Macro
- [x] Implement obfuse! proc-macro (random mode)
- [x] Add seed parameter support (deterministic mode)
- [x] Compile-time encryption logic

### Algorithms
- [x] AES-256-GCM encryption/decryption
- [x] AES-128-GCM encryption/decryption
- [x] ChaCha20-Poly1305 encryption/decryption
- [x] XOR encryption/decryption

### Testing
- [x] Unit tests for each algorithm
- [x] Test random mode (non-deterministic)
- [x] Test seed mode (deterministic/reproducible)
- [x] Integration tests (21 tests passing)
