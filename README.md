# obfuse-rs

Compile-time string encryption for Rust with runtime decryption and secure memory wiping.

> **Security Notice**: This library provides **string obfuscation**, not military-grade encryption. The encryption key is embedded in the binary alongside the ciphertext. A determined attacker with access to your binary can extract both.
>
> **Appropriate uses:**
> - Preventing casual inspection of binaries (`strings` command, hex editors)
> - Stopping automated string extraction tools
> - Basic protection against unsophisticated reverse engineering
>
> **NOT appropriate for:**
> - Protecting highly sensitive secrets (use proper secrets management)
> - Compliance requirements (PCI-DSS, HIPAA, SOC2, etc.)
> - Scenarios where key extraction would be catastrophic

## Features

- **Compile-time encryption**: Strings are encrypted during compilation, never stored in plaintext in binaries
- **Multiple encryption algorithms**: Choose via Cargo features
  - `aes-256-gcm` (default) - AES-256 in GCM mode
  - `aes-128-gcm` - AES-128 in GCM mode
  - `chacha20-poly1305` - ChaCha20-Poly1305 AEAD
  - `xor` - Simple XOR (fast, less secure, good for obfuscation)
- **Secure memory handling**: Volatile zeroing of sensitive data on drop
- **Zero-copy decryption**: Decrypt only when accessed
- **No runtime dependencies**: Encryption happens at compile time

## Binary Size Impact

Adding `obfuse` to your project has minimal overhead:

| Binary Type | Size | Delta |
|-------------|------|-------|
| Baseline (no obfuse) | 131 KB | - |
| With obfuse | 158 KB | **+27 KB** |

**Breakdown:**
- **Library overhead**: ~27 KB (one-time cost for crypto + zeroize)
- **Per-string overhead**: ~68 bytes (32B key + 12B nonce + 16B tag + 8B cache)

### Performance

| Operation | Time |
|-----------|------|
| First access (decryption) | ~500 ns |
| Cached access | ~10 ns |
| Plain string access | ~1 ns |

Decryption is lazy and cached - subsequent accesses are nearly free.


## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
obfuse = "0.1"
```

### Selecting Encryption Algorithm

By default, `aes-256-gcm` is used. To use a different algorithm:

```toml
# Use AES-128
[dependencies]
obfuse = { version = "0.1", default-features = false, features = ["aes-128-gcm"] }

# Use ChaCha20-Poly1305
[dependencies]
obfuse = { version = "0.1", default-features = false, features = ["chacha20-poly1305"] }

# Use XOR (fast obfuscation, not cryptographically secure)
[dependencies]
obfuse = { version = "0.1", default-features = false, features = ["xor"] }
```

## Usage

### Basic Usage

```rust
use obfuse::obfuse;

fn main() {
    // String is encrypted at compile time
    let secret = obfuse!("my secret API key");

    // Decrypted only when accessed
    println!("Secret: {}", secret.as_str());

    // Memory is securely wiped when `secret` goes out of scope
}
```

### With Explicit Type

```rust
use obfuse::{obfuse, ObfuseStr};

fn main() {
    let secret: ObfuseStr = obfuse!("database password");

    // Use the decrypted string
    connect_to_database(secret.as_str());

    // `secret` is automatically zeroed on drop
}
```

### Lazy Decryption

```rust
use obfuse::obfuse;

fn main() {
    let secret = obfuse!("sensitive data");

    // String remains encrypted until first access
    if should_use_secret() {
        // Decryption happens here
        use_secret(secret.as_str());
    }
    // If condition is false, string is never decrypted
}
```

### Error Handling

For defensive programming, use the fallible API:

```rust
use obfuse::{obfuse, ObfuseStrError};

fn main() {
    let secret = obfuse!("sensitive data");

    // Fallible decryption - recommended for critical code paths
    match secret.try_as_str() {
        Ok(s) => println!("Secret: {s}"),
        Err(ObfuseStrError::AllocationFailed) => {
            eprintln!("Out of memory during decryption");
        }
        Err(ObfuseStrError::AuthenticationFailed) => {
            eprintln!("Decryption failed - binary may be corrupted");
        }
        Err(ObfuseStrError::InvalidUtf8(e)) => {
            eprintln!("Invalid UTF-8: {e}");
        }
    }
}
```

Or with `?` operator:

```rust
use obfuse::{obfuse, ObfuseStrError};

fn get_secret() -> Result<String, ObfuseStrError> {
    let secret = obfuse!("my secret");
    Ok(secret.try_as_str()?.to_string())
}
```

## How It Works

1. **Compile Time**: The `obfuse!` macro:
   - Generates a random encryption key and nonce
   - Encrypts the string literal using the selected algorithm
   - Embeds encrypted bytes, key, and nonce in the binary

2. **Runtime**: The `ObfuseStr` type:
   - Stores encrypted data until accessed
   - Decrypts on first call to `as_str()` or `Deref`
   - Caches decrypted value for subsequent accesses

3. **Drop**: When `ObfuseStr` is dropped:
   - Uses `std::ptr::write_volatile` to zero all sensitive memory
   - Zeros: encryption key, nonce, and decrypted plaintext
   - Prevents compiler from optimizing away the zeroing

## Build Modes: Random vs Deterministic

This library supports two build modes for different use cases:

### Default: Random Key (Recommended for Production)

```rust
// Random key generated each compile - different binary every build
let secret = obfuse!("my secret");
println!("{}", secret.as_str());  // Auto-decrypts
```

```
Build 1: key = [0xab, 0xcd, ...] (random)
Build 2: key = [0x12, 0x34, ...] (different random)
Build 3: key = [0x9f, 0xe2, ...] (different random)
```

**Benefits**:
- Each build produces unique encryption
- Harder for attackers to create universal decryption tools
- Best obfuscation for production binaries

### With Seed: Deterministic Key (For Testing/CI)

```rust
// Same seed = same key = reproducible output
let secret = obfuse!("my secret", seed = "test_seed_123");
println!("{}", secret.as_str());  // Auto-decrypts (same as random mode)
```

```
Build 1 (seed="test"): key = [0xaa, 0xbb, ...] (deterministic)
Build 2 (seed="test"): key = [0xaa, 0xbb, ...] (same!)
Build 3 (seed="prod"): key = [0xcc, 0xdd, ...] (different seed = different key)
```

**Benefits**:
- Reproducible builds for CI/CD pipelines
- Testable encrypted output
- Debugging with known encryption state

### Which Mode Should You Use?

| Use Case | Recommended |
|----------|-------------|
| Production builds | `obfuse!("...")` (random) |
| Unit tests | `obfuse!("...", seed = "test")` |
| CI/CD pipelines | `obfuse!("...", seed = "ci")` |
| Debugging encryption issues | `obfuse!("...", seed = "debug")` |

### Important: Both Modes Are Obfuscation

```
┌─────────────────────────────────────────────────────┐
│            Your Binary (Both Modes)                 │
├─────────────────────────────────────────────────────┤
│  Encrypted Data: [0x4a, 0x7f, 0x2c, ...]           │
│  Encryption Key: [0xab, 0xcd, 0xef, ...]  ← HERE   │
│  Nonce:          [0x11, 0x22, 0x33, ...]           │
└─────────────────────────────────────────────────────┘
        Key is ALWAYS embedded in binary
        This is OBFUSCATION, not real encryption
```

For real secret protection, use runtime secrets management (environment variables, Vault, AWS Secrets Manager).

## Security Considerations

### What This Protects Against

- Static binary analysis (strings command, hex editors)
- Simple memory dumps of unaccessed secrets
- Accidental logging of encrypted values

### What This Does NOT Protect Against

- Runtime memory inspection while string is in use
- Sophisticated reverse engineering
- Side-channel attacks
- Compromised systems with debugging access

### Best Practices

1. **Minimize lifetime**: Keep `ObfuseStr` in scope only while needed
2. **Avoid cloning**: Don't clone decrypted strings unnecessarily
3. **Use strong algorithms**: Prefer `aes-256-gcm` or `chacha20-poly1305` for real security
4. **Defense in depth**: Use as one layer of protection, not the only one

## API Reference

### `obfuse!` Macro

```rust
// Random key (production)
obfuse!("string literal") -> ObfuseStr

// Deterministic key (testing/CI)
obfuse!("string literal", seed = "your_seed") -> ObfuseStr
```

Encrypts a string literal at compile time.

- **Without seed**: Random key each compile (non-reproducible)
- **With seed**: Deterministic key derived from seed (reproducible)

### `ObfuseStr` Type

```rust
impl ObfuseStr {
    /// Returns the decrypted string, decrypting on first access.
    /// Panics with detailed message on error.
    pub fn as_str(&self) -> &str;

    /// Fallible version - returns Result instead of panicking.
    /// Recommended for critical code paths.
    pub fn try_as_str(&self) -> Result<&str, ObfuseStrError>;

    /// Returns the decrypted string as bytes.
    pub fn as_bytes(&self) -> &[u8];

    /// Fallible version of as_bytes().
    pub fn try_as_bytes(&self) -> Result<&[u8], ObfuseStrError>;

    /// Returns true if the string has been decrypted.
    pub fn is_decrypted(&self) -> bool;

    /// Pre-decrypt without returning the value.
    pub fn try_decrypt(&self) -> Result<(), ObfuseStrError>;

    /// Manually zero memory (also happens automatically on drop).
    pub fn zeroize(&mut self);
}

impl Deref for ObfuseStr {
    type Target = str;
    fn deref(&self) -> &str; // Triggers decryption, panics on error
}

impl Drop for ObfuseStr {
    fn drop(&mut self); // Volatile zeroing of all sensitive data
}
```

### `ObfuseStrError` Type

```rust
/// Errors that can occur during ObfuseStr decryption
#[derive(Debug)]
pub enum ObfuseStrError {
    /// Memory allocation failed during decryption (OOM)
    AllocationFailed,

    /// AEAD authentication tag verification failed.
    /// Indicates ciphertext tampering or algorithm mismatch.
    AuthenticationFailed,

    /// Decrypted bytes are not valid UTF-8
    InvalidUtf8(std::str::Utf8Error),
}

impl std::fmt::Display for ObfuseStrError { /* ... */ }
impl std::error::Error for ObfuseStrError { /* ... */ }
```

## Project Structure

```
obfuse-rs/
├── Cargo.toml              # Workspace configuration
├── README.md
├── obfuse/               # Main library crate (re-exports)
│   ├── Cargo.toml
│   └── src/lib.rs
├── obfuse-macros/        # Procedural macro crate
│   ├── Cargo.toml
│   └── src/lib.rs
└── obfuse-core/          # Core encryption/decryption logic
    ├── Cargo.toml
    └── src/
        ├── lib.rs
        ├── obfuse_str.rs    # ObfuseStr type implementation
        ├── aes.rs          # AES encryption
        ├── chacha.rs       # ChaCha20 encryption
        └── xor.rs          # XOR encryption
```

## Building

```bash
# Build with default features (AES-256-GCM)
cargo build

# Build with specific algorithm
cargo build --no-default-features --features chacha20-poly1305

# Run tests
cargo test

# Run tests for specific algorithm
cargo test --no-default-features --features aes-128-gcm
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Please read the contributing guidelines first.

## Acknowledgments

- [aes-gcm](https://crates.io/crates/aes-gcm) - AES-GCM implementation
- [chacha20poly1305](https://crates.io/crates/chacha20poly1305) - ChaCha20-Poly1305 implementation
- [zeroize](https://crates.io/crates/zeroize) - Secure memory zeroing patterns
