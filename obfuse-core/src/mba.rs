//! Mixed Boolean-Arithmetic (MBA) transformations for obfuscation.
//!
//! This module provides mathematically equivalent but obfuscated versions
//! of basic arithmetic and logical operations. The transformations make
//! the decompiled code significantly harder to understand and simplify.
//!
//! # Background
//!
//! MBA transformations replace simple operations with complex expressions
//! that combine Boolean (AND, OR, XOR, NOT) and arithmetic (+, -, *)
//! operations. These expressions are mathematically equivalent but much
//! harder for decompilers like IDA's Hex-Rays to simplify.
//!
//! # Example
//!
//! A simple XOR operation `a ^ b` can be replaced with:
//! ```text
//! (a | b) - (a & b)  // Equivalent to a ^ b
//! ```
//!
//! Or even more complex expressions involving dummy constants:
//! ```text
//! ((a | b) + (a | b)) - ((a & b) + (a & b)) - (a | b) + (a & b)
//! ```

// Allow intentional obfuscation patterns that clippy doesn't like
#![allow(clippy::eq_op)] // We intentionally use patterns like D1 ^ D1 = 0
#![allow(clippy::if_same_then_else)] // Intentional noise in control flow

/// Dummy constants for noise injection.
/// These values are used in MBA expressions to increase complexity
/// without affecting the final result.
mod constants {
    /// First dummy constant - used for XOR identity transformations
    pub const D1: u8 = 0x5A;
    /// Second dummy constant - used for addition identity
    pub const D2: u8 = 0xA5;
    /// Third dummy constant - used for multiplicative identity
    pub const D3: u8 = 0x3C;
    /// Fourth dummy constant - used in nested expressions
    pub const D4: u8 = 0xC3;
}

use constants::{D1, D2, D3, D4};

/// Computes `a ^ b` using MBA transformation.
///
/// Mathematical identity: `a ^ b = (a | b) - (a & b)`
///
/// This is then expanded further with dummy operations that cancel out.
/// The compiler may optimize some of these, but the source-level complexity
/// makes static analysis and pattern matching much harder.
#[inline(never)]
#[must_use]
pub fn mba_xor(a: u8, b: u8) -> u8 {
    // Basic MBA identity: a ^ b = (a | b) - (a & b)
    // We expand this with additional noise operations

    // Step 1: Compute (a | b) with noise
    let or_ab = mba_or_with_noise(a, b);

    // Step 2: Compute (a & b) with noise
    let and_ab = mba_and_with_noise(a, b);

    // Step 3: Apply the XOR identity with additional obfuscation
    // a ^ b = (a | b) - (a & b)
    // Expand: (a | b) - (a & b) = (a | b) + (-(a & b))
    // Further expand with wrapping arithmetic

    let result = mba_sub(or_ab, and_ab);

    // Add identity transformation: result ^ 0 = result
    // But use: result ^ (D1 ^ D1) = result
    mba_xor_identity(result)
}

/// Computes `a | b` with noise injection.
///
/// Uses the identity: `a | b = (a ^ b) + (a & b)`
/// but expands it with dummy operations.
#[inline(never)]
fn mba_or_with_noise(a: u8, b: u8) -> u8 {
    // Direct computation with some noise
    // a | b = a + b - (a & b)  (alternative identity)
    let and_ab = a & b;
    let sum = a.wrapping_add(b);

    // Add noise that cancels out: + D1 - D1
    let with_noise = sum.wrapping_add(D1);
    let sub_and = with_noise.wrapping_sub(and_ab);
    sub_and.wrapping_sub(D1)
}

/// Computes `a & b` with noise injection.
///
/// Uses nested expressions that include dummy constants.
#[inline(never)]
fn mba_and_with_noise(a: u8, b: u8) -> u8 {
    // Direct AND with noise that cancels
    // a & b = (a + b - (a | b)) but that's circular
    // Use direct AND with noise wrapping

    let and_ab = a & b;

    // Noise: XOR with D2, then XOR with D2 again to cancel
    let noised = and_ab ^ D2;
    noised ^ D2
}

/// Computes `a - b` using MBA transformation.
///
/// Identity: `a - b = a + (!b) + 1 = a + (!b + 1)`
#[inline(never)]
fn mba_sub(a: u8, b: u8) -> u8 {
    // a - b = a + (~b + 1) = a + (-b)
    // Expand with noise

    let neg_b = (!b).wrapping_add(1);

    // a + neg_b with noise
    let sum = a.wrapping_add(neg_b);

    // Add/subtract dummy to add noise
    let noised = sum.wrapping_add(D3);
    noised.wrapping_sub(D3)
}

/// Applies an identity transformation that preserves the value.
///
/// Uses: `x ^ (D1 ^ D1) = x ^ 0 = x`
/// But the expression looks complex in decompiled output.
#[inline(never)]
fn mba_xor_identity(x: u8) -> u8 {
    // x ^ 0 = x, but we compute 0 as (D1 ^ D1) ^ (D4 ^ D4)
    let zero_1 = D1 ^ D1;
    let zero_2 = D4 ^ D4;
    let zero = zero_1 | zero_2; // Still 0

    // Additional complexity: x = x + 0 = x - 0
    let temp = x ^ zero;
    let with_add = temp.wrapping_add(D2);
    with_add.wrapping_sub(D2)
}

/// Non-linear MBA XOR implementation.
///
/// This version uses a more complex formula with multiple terms:
/// `a ^ b = (a | b) - (a & b)`
///       = `2 * (a | b) - (a + b)`
///       = `(a + b) - 2 * (a & b)`
///
/// We combine these forms with dummy operations.
#[inline(never)]
#[must_use]
pub fn mba_xor_nonlinear(a: u8, b: u8) -> u8 {
    // Use: a ^ b = (a + b) - 2*(a & b)
    // Equivalent to: a ^ b = (a | b) - (a & b) = 2*(a | b) - (a + b)

    let sum_ab = a.wrapping_add(b);
    let and_ab = a & b;
    let twice_and = and_ab.wrapping_mul(2);

    // Base result
    let base = sum_ab.wrapping_sub(twice_and);

    // Add noise layer
    // Note: Separate variables with identical values are intentional.
    // This prevents pattern-matching optimizations in decompilers.
    let noise_term = D1.wrapping_add(D2);
    let cancel_term = D1.wrapping_add(D2);

    base.wrapping_add(noise_term).wrapping_sub(cancel_term)
}

/// Highly obfuscated XOR using nested MBA expressions.
///
/// This version uses multiple levels of transformation to create
/// extremely complex decompiled output.
#[inline(never)]
#[must_use]
pub fn mba_xor_deep(a: u8, b: u8) -> u8 {
    // Level 1: Use MBA identity for XOR
    // a ^ b = (a | b) - (a & b)

    // Compute (a | b) using: a | b = a + b - (a & b)
    // Compute (a & b) directly with noise

    let and_ab = {
        let direct = a & b;
        // Noise: add and subtract D1
        direct.wrapping_add(D1).wrapping_sub(D1)
    };

    let or_ab = {
        // a | b = a + b - (a & b)
        let sum = a.wrapping_add(b);
        let result = sum.wrapping_sub(and_ab);
        // Noise
        result.wrapping_add(D2).wrapping_sub(D2)
    };

    // Level 2: Compute XOR from OR and AND
    // a ^ b = (a | b) - (a & b)

    let xor_result = {
        let diff = or_ab.wrapping_sub(and_ab);
        // More noise
        diff.wrapping_add(D3).wrapping_sub(D3)
    };

    // Level 3: Apply identity transformation
    // x = x ^ 0 = x ^ (y ^ y) for any y

    let identity = {
        // D4 ^ D4 = 0, computed at runtime to resist decompiler simplification
        let zero = D4 ^ D4;
        xor_result ^ zero
    };

    // Final noise layer: D1 ^ D1 = 0, adding nothing but complexity
    identity.wrapping_add(D1 ^ D1)
}

/// Performs XOR decryption on a byte slice using MBA transformations.
///
/// This is the main entry point for MBA-obfuscated XOR decryption.
/// Each byte is decrypted using the obfuscated XOR operation.
///
/// # Arguments
/// * `ciphertext` - The encrypted data
/// * `key` - The encryption key (cycled if shorter than ciphertext)
/// * `key_size` - Size of the key
///
/// # Returns
/// Decrypted plaintext bytes.
#[inline(never)]
#[must_use]
pub fn mba_decrypt_xor(ciphertext: &[u8], key: &[u8], key_size: usize) -> Vec<u8> {
    ciphertext
        .iter()
        .enumerate()
        .map(|(i, &byte)| {
            let key_byte = key[mba_modulo(i, key_size)];
            mba_xor_deep(byte, key_byte)
        })
        .collect()
}

/// Computes `a % b` using division.
///
/// This is used for key index cycling without exposing a simple modulo pattern.
#[inline(never)]
fn mba_modulo(a: usize, b: usize) -> usize {
    // Standard modulo with noise in the computation path
    // We can't easily obfuscate this without changing the semantics,
    // but we can add some wrapper complexity

    let quotient = a / b;
    let product = quotient.wrapping_mul(b);

    // a - (a / b) * b = a % b
    let result = a.wrapping_sub(product);

    // Intentionally redundant branches to add control-flow complexity.
    // Both branches return the same value; this is designed to resist
    // pattern-matching in decompilers.
    if result < b {
        result
    } else {
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mba_xor_basic() {
        // Test all possible byte pairs for a sample
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(
                    mba_xor(a, b),
                    a ^ b,
                    "mba_xor({a}, {b}) should equal {a} ^ {b}"
                );
            }
        }
    }

    #[test]
    fn test_mba_xor_nonlinear() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(
                    mba_xor_nonlinear(a, b),
                    a ^ b,
                    "mba_xor_nonlinear({a}, {b}) should equal {a} ^ {b}"
                );
            }
        }
    }

    #[test]
    fn test_mba_xor_deep() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(
                    mba_xor_deep(a, b),
                    a ^ b,
                    "mba_xor_deep({a}, {b}) should equal {a} ^ {b}"
                );
            }
        }
    }

    #[test]
    fn test_mba_decrypt_xor() {
        let key = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let plaintext = b"Hello, World!";

        // Encrypt using simple XOR
        let ciphertext: Vec<u8> = plaintext
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect();

        // Decrypt using MBA XOR
        let decrypted = mba_decrypt_xor(&ciphertext, &key, key.len());

        assert_eq!(decrypted, plaintext.to_vec());
    }

    #[test]
    fn test_mba_or_with_noise() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(
                    mba_or_with_noise(a, b),
                    a | b,
                    "mba_or_with_noise({a}, {b}) should equal {a} | {b}"
                );
            }
        }
    }

    #[test]
    fn test_mba_and_with_noise() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(
                    mba_and_with_noise(a, b),
                    a & b,
                    "mba_and_with_noise({a}, {b}) should equal {a} & {b}"
                );
            }
        }
    }

    #[test]
    fn test_mba_sub() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(
                    mba_sub(a, b),
                    a.wrapping_sub(b),
                    "mba_sub({a}, {b}) should equal {a}.wrapping_sub({b})"
                );
            }
        }
    }

    #[test]
    fn test_mba_xor_identity() {
        for x in 0..=255u8 {
            assert_eq!(mba_xor_identity(x), x, "mba_xor_identity({x}) should equal {x}");
        }
    }

    #[test]
    fn test_mba_modulo() {
        assert_eq!(mba_modulo(10, 3), 1);
        assert_eq!(mba_modulo(15, 5), 0);
        assert_eq!(mba_modulo(7, 4), 3);
        assert_eq!(mba_modulo(100, 32), 4);
    }
}
