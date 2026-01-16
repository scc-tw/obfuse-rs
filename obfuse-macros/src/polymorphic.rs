//! Polymorphic decryption code generation.
//!
//! This module generates unique, inline decryption code for each obfuscated string,
//! eliminating the central decryption point and making reverse engineering harder.

use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

#[cfg(feature = "control-flow-flatten")]
use crate::control_flow_flatten::{CffConfig, StateMachineBuilder};

/// Types of transformation operations available for decryption
#[derive(Debug, Clone, Copy)]
enum Transform {
    Xor,
    Add,
    Sub,
    RotateLeft,
    RotateRight,
}

impl Transform {
    /// Get a random transformation type
    fn random(rng: &mut impl Rng) -> Self {
        match rng.random_range(0..5) {
            0 => Transform::Xor,
            1 => Transform::Add,
            2 => Transform::Sub,
            3 => Transform::RotateLeft,
            _ => Transform::RotateRight,
        }
    }
}

/// A single layer of transformation in the decryption pipeline
pub(crate) struct TransformLayer {
    transform: Transform,
    /// Constants used for key derivation (to avoid static keys)
    key_constants: Vec<u8>,
}

/// Generates polymorphic inline decryption code
pub struct PolymorphicGenerator {
    rng: ChaCha20Rng,
}

impl PolymorphicGenerator {
    /// Create a new generator with optional seed for deterministic generation
    pub fn new(seed: Option<&str>) -> Self {
        let rng = if let Some(seed_str) = seed {
            let seed_bytes = create_seed_bytes(seed_str);
            ChaCha20Rng::from_seed(seed_bytes)
        } else {
            // Use system entropy for random seed
            let mut seed_bytes = [0u8; 32];
            getrandom::fill(&mut seed_bytes).expect("Failed to generate random seed");
            ChaCha20Rng::from_seed(seed_bytes)
        };

        Self { rng }
    }

    /// Generate inline decryption code for plaintext
    ///
    /// Returns (ciphertext, inline_decryption_code)
    pub fn generate(&mut self, plaintext: &[u8]) -> (Vec<u8>, TokenStream2) {
        // Determine number of transformation layers (2-4 layers)
        let num_layers = self.rng.random_range(2..=4);

        // Generate transformation layers
        let mut layers = Vec::new();
        for _ in 0..num_layers {
            layers.push(self.generate_layer());
        }

        // Encrypt the plaintext using the layers
        let ciphertext = self.encrypt_with_layers(plaintext, &layers);

        // Generate inline decryption code
        let decryption_code = self.generate_inline_decryption(&ciphertext, &layers);

        (ciphertext, decryption_code)
    }

    /// Generate a single transformation layer
    fn generate_layer(&mut self) -> TransformLayer {
        let transform = Transform::random(&mut self.rng);

        // Generate 4-8 random constants for key derivation
        let num_constants = self.rng.random_range(4..=8);
        let mut key_constants = Vec::new();
        for _ in 0..num_constants {
            key_constants.push(self.rng.random());
        }

        TransformLayer {
            transform,
            key_constants,
        }
    }

    /// Encrypt plaintext using transformation layers
    fn encrypt_with_layers(&mut self, plaintext: &[u8], layers: &[TransformLayer]) -> Vec<u8> {
        let mut data = plaintext.to_vec();

        // Apply each layer in forward order during encryption
        for layer in layers {
            data = self.apply_transform(&data, layer, false);
        }

        data
    }

    /// Apply a transformation layer to data
    fn apply_transform(&mut self, data: &[u8], layer: &TransformLayer, reverse: bool) -> Vec<u8> {
        // Derive a key from the constants at "compile time"
        let key = self.derive_key(&layer.key_constants);

        data.iter()
            .enumerate()
            .map(|(i, &byte)| {
                let key_byte = key[i % key.len()];
                match (layer.transform, reverse) {
                    (Transform::Xor, _) => byte ^ key_byte,
                    (Transform::Add, false) => byte.wrapping_add(key_byte),
                    (Transform::Add, true) => byte.wrapping_sub(key_byte),
                    (Transform::Sub, false) => byte.wrapping_sub(key_byte),
                    (Transform::Sub, true) => byte.wrapping_add(key_byte),
                    (Transform::RotateLeft, false) => byte.rotate_left(key_byte as u32 % 8),
                    (Transform::RotateLeft, true) => byte.rotate_right(key_byte as u32 % 8),
                    (Transform::RotateRight, false) => byte.rotate_right(key_byte as u32 % 8),
                    (Transform::RotateRight, true) => byte.rotate_left(key_byte as u32 % 8),
                }
            })
            .collect()
    }

    /// Derive a key from constants (this simulates what will happen at runtime)
    fn derive_key(&self, constants: &[u8]) -> Vec<u8> {
        // Create a simple derived key - this is what we'll generate code to compute at runtime
        let mut key = Vec::new();
        for i in 0..32 {
            let mut val = constants[i % constants.len()];
            // Mix in other constants
            for (j, &c) in constants.iter().enumerate() {
                val = val.wrapping_add(c.rotate_left(j as u32));
            }
            key.push(val);
        }
        key
    }

    /// Generate inline decryption code as token stream, dispatching to the correct implementation.
    fn generate_inline_decryption(
        &mut self,
        ciphertext: &[u8],
        layers: &[TransformLayer],
    ) -> TokenStream2 {
        #[cfg(feature = "control-flow-flatten")]
        {
            self.generate_flattened_decryption(ciphertext, layers)
        }

        #[cfg(not(feature = "control-flow-flatten"))]
        {
            self.generate_linear_decryption(ciphertext, layers)
        }
    }

    /// Generates the original linear decryption code.
    #[cfg(not(feature = "control-flow-flatten"))]
    fn generate_linear_decryption(
        &mut self,
        ciphertext: &[u8],
        layers: &[TransformLayer],
    ) -> TokenStream2 {
        let ct_bytes = ciphertext.iter().map(|b| quote! { #b });

        let mut layer_code = Vec::new();
        for layer in layers.iter().rev() {
            let code = self.generate_layer_code(layer);
            layer_code.push(code);
        }

        quote! {
            ::obfuse::ObfuseStrInline::new(|| -> ::std::result::Result<::std::string::String, ::obfuse::ObfuseError> {
                let mut data: ::std::vec::Vec<u8> = vec![#(#ct_bytes),*];
                #(#layer_code)*
                ::std::string::String::from_utf8(data)
                    .map_err(|e| ::obfuse::ObfuseError::InvalidUtf8(e.utf8_error()))
            })
        }
    }

    /// Generates flattened decryption code with a state machine.
    #[cfg(feature = "control-flow-flatten")]
    fn generate_flattened_decryption(
        &mut self,
        ciphertext: &[u8],
        layers: &[TransformLayer],
    ) -> TokenStream2 {
        // CRITICAL: Pre-generate ALL layer code BEFORE creating the builder
        // This avoids borrow checker conflict: we need `self` for generate_layer_code()
        // but later we need `&mut self.rng` for the builder methods.
        let layer_codes: Vec<(usize, TokenStream2)> = layers
            .iter()
            .enumerate()
            .rev() // Reverse order for decryption
            .map(|(i, layer)| (i, self.generate_layer_code(layer)))
            .collect();

        let config = CffConfig::default();
        let mut builder = StateMachineBuilder::new(config);

        builder.add_init_block();

        for (layer_idx, layer_code) in layer_codes {
            builder.add_layer_block(layer_idx, layer_code);
        }

        builder.add_finalize_block();

        for _ in 0..config.fake_block_count {
            builder.add_dead_block(&mut self.rng);
        }

        builder.connect_with_predicates(&mut self.rng);
        builder.build(ciphertext, &mut self.rng)
    }

    /// Generate code for a single layer's decryption
    fn generate_layer_code(&mut self, layer: &TransformLayer) -> TokenStream2 {
        // Generate key derivation code
        let key_derivation = self.generate_key_derivation_code(&layer.key_constants);

        // Generate transformation code based on type
        let transform_code = match layer.transform {
            Transform::Xor => quote! {
                data = data.iter().enumerate().map(|(i, &byte)| {
                    byte ^ key[i % key.len()]
                }).collect();
            },
            Transform::Add => quote! {
                data = data.iter().enumerate().map(|(i, &byte)| {
                    byte.wrapping_sub(key[i % key.len()])
                }).collect();
            },
            Transform::Sub => quote! {
                data = data.iter().enumerate().map(|(i, &byte)| {
                    byte.wrapping_add(key[i % key.len()])
                }).collect();
            },
            Transform::RotateLeft => quote! {
                data = data.iter().enumerate().map(|(i, &byte)| {
                    byte.rotate_right((key[i % key.len()] as u32) % 8)
                }).collect();
            },
            Transform::RotateRight => quote! {
                data = data.iter().enumerate().map(|(i, &byte)| {
                    byte.rotate_left((key[i % key.len()] as u32) % 8)
                }).collect();
            },
        };

        quote! {
            {
                let key = #key_derivation;
                #transform_code
            }
        }
    }

    /// Generate runtime key derivation code from constants
    fn generate_key_derivation_code(&self, constants: &[u8]) -> TokenStream2 {
        // Generate the constants array
        let const_bytes = constants.iter().map(|b| quote! { #b });

        quote! {
            {
                const CONSTANTS: &[u8] = &[#(#const_bytes),*];
                let mut key = Vec::new();
                for i in 0..32 {
                    let mut val = CONSTANTS[i % CONSTANTS.len()];
                    for (j, &c) in CONSTANTS.iter().enumerate() {
                        val = val.wrapping_add(c.rotate_left(j as u32));
                    }
                    key.push(val);
                }
                key
            }
        }
    }
}

/// Creates a 32-byte seed from a string using simple hashing.
fn create_seed_bytes(seed: &str) -> [u8; 32] {
    let mut result = [0u8; 32];
    let seed_bytes = seed.as_bytes();

    for (i, &byte) in seed_bytes.iter().enumerate() {
        result[i % 32] ^= byte;
        #[allow(clippy::cast_possible_truncation)]
        let pos_factor = (i as u8).wrapping_add(1);
        result[(i + 7) % 32] = result[(i + 7) % 32].wrapping_add(byte.wrapping_mul(pos_factor));
    }

    for _ in 0..3 {
        for i in 0..32 {
            result[i] = result[i]
                .wrapping_add(result[(i + 13) % 32])
                .wrapping_mul(result[(i + 7) % 32].wrapping_add(1));
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polymorphic_generation() {
        let mut generator = PolymorphicGenerator::new(Some("test_seed"));
        let plaintext = b"Hello, World!";
        let (ciphertext, _code) = generator.generate(plaintext);

        // Ciphertext should be different from plaintext
        assert_ne!(ciphertext.as_slice(), plaintext);
    }

    #[test]
    fn test_deterministic_generation() {
        let mut gen1 = PolymorphicGenerator::new(Some("test_seed"));
        let mut gen2 = PolymorphicGenerator::new(Some("test_seed"));

        let plaintext = b"Hello, World!";
        let (ct1, _) = gen1.generate(plaintext);
        let (ct2, _) = gen2.generate(plaintext);

        // Same seed should produce same ciphertext
        assert_eq!(ct1, ct2);
    }

    #[test]
    fn test_different_seeds_produce_different_output() {
        let mut gen1 = PolymorphicGenerator::new(Some("seed1"));
        let mut gen2 = PolymorphicGenerator::new(Some("seed2"));

        let plaintext = b"Hello, World!";
        let (ct1, _) = gen1.generate(plaintext);
        let (ct2, _) = gen2.generate(plaintext);

        // Different seeds should produce different ciphertext
        assert_ne!(ct1, ct2);
    }
}
