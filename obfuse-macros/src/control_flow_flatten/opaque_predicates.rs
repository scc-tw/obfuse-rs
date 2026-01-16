use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use rand::Rng;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PredicateType {
    ConsecutiveProduct,
    QuadraticIdentity,
    XorSelf,
    BitAndSelf,
    SquareNonNegative,
    SumSameParity,
}

pub struct OpaquePredicate {
    pub predicate_type: PredicateType,
    pub constants: Vec<u64>,
}

impl OpaquePredicate {
    /// Generate a random predicate that always evaluates to true
    pub fn random_true<R: Rng>(rng: &mut R) -> Self {
        let predicate_type = match rng.random_range(0..6) {
            0 => PredicateType::ConsecutiveProduct,
            1 => PredicateType::QuadraticIdentity,
            2 => PredicateType::XorSelf,
            3 => PredicateType::BitAndSelf,
            4 => PredicateType::SquareNonNegative,
            _ => PredicateType::SumSameParity,
        };

        let constants = Self::generate_constants(&predicate_type, rng);

        Self {
            predicate_type,
            constants,
        }
    }

    /// Generate constants appropriate for the predicate type
    fn generate_constants<R: Rng>(predicate_type: &PredicateType, rng: &mut R) -> Vec<u64> {
        match predicate_type {
            PredicateType::ConsecutiveProduct
            | PredicateType::QuadraticIdentity
            | PredicateType::XorSelf
            | PredicateType::BitAndSelf
            | PredicateType::SquareNonNegative => vec![rng.random::<u64>()],
            PredicateType::SumSameParity => {
                // Generate two values with same parity
                let a = rng.random::<u64>();
                let b = if a % 2 == 0 {
                    rng.random::<u64>() & !1 // Make even
                } else {
                    rng.random::<u64>() | 1 // Make odd
                };
                vec![a, b]
            }
        }
    }

    /// Generate the condition code with optional black_box wrapping
    ///
    /// IMPORTANT: Do NOT add type suffixes like `#n u64` in quote! - this generates
    /// invalid tokens like `12345 u64`. Instead, omit the suffix and let type inference
    /// work (methods like wrapping_mul provide sufficient type context).
    pub fn generate_condition(&self, use_black_box: bool) -> TokenStream2 {
        match &self.predicate_type {
            PredicateType::ConsecutiveProduct => {
                let n = self.constants[0];
                if use_black_box {
                    quote! {
                        ::core::hint::black_box(
                            ::core::hint::black_box(#n)
                                .wrapping_mul(::core::hint::black_box(#n).wrapping_add(1u64))
                        ) % 2 == 0
                    }
                } else {
                    quote! { (#n).wrapping_mul((#n).wrapping_add(1u64)) % 2 == 0 }
                }
            }
            PredicateType::QuadraticIdentity => {
                let n = self.constants[0];
                if use_black_box {
                    quote! {
                        ::core::hint::black_box(
                            ::core::hint::black_box(#n)
                                .wrapping_mul(::core::hint::black_box(#n).wrapping_sub(1u64))
                        ) % 2 == 0
                    }
                } else {
                    quote! { (#n).wrapping_mul((#n).wrapping_sub(1u64)) % 2 == 0 }
                }
            }
            PredicateType::XorSelf => {
                let x = self.constants[0];
                if use_black_box {
                    quote! { ::core::hint::black_box(#x) ^ ::core::hint::black_box(#x) == 0 }
                } else {
                    quote! { (#x) ^ (#x) == 0 }
                }
            }
            PredicateType::BitAndSelf => {
                let x = self.constants[0];
                if use_black_box {
                    quote! {
                        (::core::hint::black_box(#x) & ::core::hint::black_box(#x))
                            == ::core::hint::black_box(#x)
                    }
                } else {
                    quote! { ((#x) & (#x)) == (#x) }
                }
            }
            PredicateType::SquareNonNegative => {
                let x = self.constants[0];
                if use_black_box {
                    quote! {
                        ::core::hint::black_box(#x)
                            .wrapping_mul(::core::hint::black_box(#x))
                            .count_ones() <= 64
                    }
                } else {
                    quote! { (#x).wrapping_mul(#x).count_ones() <= 64 }
                }
            }
            PredicateType::SumSameParity => {
                let a = self.constants[0];
                let b = self.constants[1];
                if use_black_box {
                    quote! {
                        (::core::hint::black_box(#a)
                            .wrapping_add(::core::hint::black_box(#b))) % 2 == 0
                    }
                } else {
                    quote! { ((#a).wrapping_add(#b)) % 2 == 0 }
                }
            }
        }
    }

    /// Compile-time verification that predicate behaves as expected
    #[cfg(test)]
    #[allow(clippy::eq_op)] // Intentional: x ^ x and x & x are opaque predicates
    pub fn verify(&self) -> bool {
        match &self.predicate_type {
            PredicateType::ConsecutiveProduct => {
                let n = self.constants[0];
                n.wrapping_mul(n.wrapping_add(1)) % 2 == 0
            }
            PredicateType::QuadraticIdentity => {
                let n = self.constants[0];
                n.wrapping_mul(n.wrapping_sub(1)) % 2 == 0
            }
            PredicateType::XorSelf => {
                let x = self.constants[0];
                (x ^ x) == 0
            }
            PredicateType::BitAndSelf => {
                let x = self.constants[0];
                (x & x) == x
            }
            PredicateType::SquareNonNegative => {
                let x = self.constants[0];
                x.wrapping_mul(x).count_ones() <= 64
            }
            PredicateType::SumSameParity => {
                let a = self.constants[0];
                let b = self.constants[1];
                (a % 2) == (b % 2) && (a.wrapping_add(b) % 2 == 0)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn test_consecutive_product_always_even() {
        for n in 0..1000u64 {
            let pred = OpaquePredicate {
                predicate_type: PredicateType::ConsecutiveProduct,
                constants: vec![n],
            };
            assert!(pred.verify(), "Failed for n={}", n);
        }
    }

    #[test]
    fn test_quadratic_identity_always_even() {
        for n in 0..1000u64 {
            let pred = OpaquePredicate {
                predicate_type: PredicateType::QuadraticIdentity,
                constants: vec![n],
            };
            assert!(pred.verify(), "Failed for n={}", n);
        }
    }

    #[test]
    fn test_xor_self_always_zero() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        for _ in 0..1000 {
            let x: u64 = rng.random();
            let pred = OpaquePredicate {
                predicate_type: PredicateType::XorSelf,
                constants: vec![x],
            };
            assert!(pred.verify(), "Failed for x={}", x);
        }
    }

    #[test]
    fn test_all_predicate_types_verify() {
        let mut rng = ChaCha8Rng::seed_from_u64(12345);
        for i in 0..1000 {
            let pred = OpaquePredicate::random_true(&mut rng);
            assert!(
                pred.verify(),
                "Random true predicate failed verification for type {:?} on iteration {}",
                pred.predicate_type,
                i
            );
        }
    }

    #[test]
    fn test_generate_condition_produces_valid_tokens() {
        let mut rng = ChaCha8Rng::seed_from_u64(99);
        for _ in 0..100 {
            let pred = OpaquePredicate::random_true(&mut rng);

            let tokens_bb = pred.generate_condition(true);
            let _ = tokens_bb.to_string(); // Should not panic

            let tokens_no_bb = pred.generate_condition(false);
            let _ = tokens_no_bb.to_string(); // Should not panic
        }
    }
}
