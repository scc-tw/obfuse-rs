use super::block_scheduler::BlockScheduler;
use super::opaque_predicates::OpaquePredicate;
use super::CffConfig;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use rand::{prelude::IndexedRandom, Rng};
use std::collections::BTreeMap;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct StateId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockType {
    Init,
    Layer(usize),
    Finalize,
    Dead,
}

pub struct StateBlock {
    pub id: StateId,
    pub body: TokenStream2,
    pub real_next: Option<StateId>,
    pub fake_next: Option<StateId>,
    pub predicate: Option<OpaquePredicate>,
    pub block_type: BlockType,
}

const MAX_ROTATION_BITS: u32 = 8;

/// State machine builder - constructs the flattened control flow
///
/// # Borrow Checker Consideration
/// RNG is passed to methods rather than stored, allowing the caller to
/// retain access to other fields (e.g., for generating layer code).
pub struct StateMachineBuilder {
    config: CffConfig,
    pub(crate) blocks: Vec<StateBlock>,
    state_values: BTreeMap<StateId, u64>,
    entry_state: Option<StateId>,
    next_id: u32,
}

impl StateMachineBuilder {
    pub fn new(config: CffConfig) -> Self {
        Self {
            config,
            blocks: Vec::new(),
            state_values: BTreeMap::new(),
            entry_state: None,
            next_id: 0,
        }
    }

    /// Generate the next unique state ID
    fn next_state_id(&mut self) -> StateId {
        let id = StateId(self.next_id);
        self.next_id += 1;
        id
    }

    /// Add initialization block (transition point, no operation)
    pub fn add_init_block(&mut self) -> StateId {
        let id = self.next_state_id();
        let body = quote! {};
        let block = StateBlock {
            id,
            body,
            real_next: None, // Set later by connect_with_predicates
            fake_next: None,
            predicate: None,
            block_type: BlockType::Init,
        };
        self.blocks.push(block);
        self.entry_state = Some(id);
        id
    }

    /// Add decryption layer block with pre-generated code
    pub fn add_layer_block(&mut self, layer_index: usize, layer_code: TokenStream2) -> StateId {
        let id = self.next_state_id();
        let block = StateBlock {
            id,
            body: layer_code,
            real_next: None,
            fake_next: None,
            predicate: None,
            block_type: BlockType::Layer(layer_index),
        };
        self.blocks.push(block);
        id
    }

    /// Add finalization block (converts to String and returns)
    pub fn add_finalize_block(&mut self) -> StateId {
        let id = self.next_state_id();
        let body = quote! {
            return ::std::string::String::from_utf8(data)
                .map_err(|e| ::obfuse::ObfuseError::InvalidUtf8(e.utf8_error()));
        };
        let block = StateBlock {
            id,
            body,
            real_next: None,
            fake_next: None,
            predicate: None,
            block_type: BlockType::Finalize,
        };
        self.blocks.push(block);
        id
    }

    /// Add dead block (never executed, confuses static analysis)
    pub fn add_dead_block<R: Rng>(&mut self, rng: &mut R) -> StateId {
        let id = self.next_state_id();
        let ops = self.generate_confusing_ops(rng);
        let target = self.random_existing_state(rng);
        let block = StateBlock {
            id,
            body: ops,
            real_next: Some(target),
            fake_next: None,
            predicate: None,
            block_type: BlockType::Dead,
        };
        self.blocks.push(block);
        id
    }

    /// Select a random existing non-dead state
    fn random_existing_state<R: Rng>(&self, rng: &mut R) -> StateId {
        let real_blocks: Vec<StateId> = self
            .blocks
            .iter()
            .filter(|b| !matches!(b.block_type, BlockType::Dead))
            .map(|b| b.id)
            .collect();
        real_blocks.choose(rng).copied().unwrap_or(StateId(0))
    }

    /// Generate confusing operations for dead blocks
    fn generate_confusing_ops<R: Rng>(&self, rng: &mut R) -> TokenStream2 {
        match rng.random_range(0..4) {
            0 => quote! { data.reverse(); },
            1 => {
                let n: u8 = rng.random();
                quote! { data.iter_mut().for_each(|b| *b = b.wrapping_add(#n)); }
            }
            2 => quote! { data = data.iter().map(|&b| !b).collect(); },
            _ => {
                // Generate a random number from 1 to MAX_ROTATION_BITS (inclusive)
                let n: u32 = rng.random_range(1..=MAX_ROTATION_BITS);
                quote! { data = data.iter().map(|&b| b.rotate_left(#n)).collect(); }
            }
        }
    }

    /// Connect blocks with opaque predicates
    pub fn connect_with_predicates<R: Rng>(&mut self, rng: &mut R) {
        let real_block_ids: Vec<StateId> = self
            .blocks
            .iter()
            .filter(|b| !matches!(b.block_type, BlockType::Dead))
            .map(|b| b.id)
            .collect();

        let dead_block_ids: Vec<StateId> = self
            .blocks
            .iter()
            .filter(|b| matches!(b.block_type, BlockType::Dead))
            .map(|b| b.id)
            .collect();

        // Connect real blocks in sequence with opaque predicates
        for i in 0..real_block_ids.len().saturating_sub(1) {
            let current_id = real_block_ids[i];
            let next_id = real_block_ids[i + 1];

            if let Some(block) = self.blocks.iter_mut().find(|b| b.id == current_id) {
                block.real_next = Some(next_id);

                if rng.random::<f32>() < self.config.predicate_density && !dead_block_ids.is_empty() {
                    let fake_target = dead_block_ids.choose(rng).copied().unwrap_or(next_id);
                    block.fake_next = Some(fake_target);
                    block.predicate = Some(OpaquePredicate::random_true(rng));
                }
            }
        }
    }

    /// Assign random state values to all blocks
    fn assign_state_values<R: Rng>(&mut self, rng: &mut R) -> syn::Result<()> {
        const MAX_RETRIES: u32 = 1000;
        let mut existing_values = std::collections::HashSet::new();
        for block in &self.blocks {
            let mut retries = 0;
            let mut value =
                generate_state_value(rng, self.config.min_state_bits, self.config.max_state_bits);
            while existing_values.contains(&value) {
                value = generate_state_value(rng, self.config.min_state_bits, self.config.max_state_bits);
                retries += 1;
                if retries > MAX_RETRIES {
                    return Err(syn::Error::new(
                        proc_macro2::Span::call_site(),
                        format!(
                            "Failed to generate a unique state value after {} retries. Try adjusting bit constraints or reducing block count.",
                            MAX_RETRIES
                        ),
                    ));
                }
            }
            existing_values.insert(value);
            self.state_values.insert(block.id, value);
        }
        Ok(())
    }

    /// Generate state transition code for a block.
    ///
    /// Returns the TokenStream that updates the `state` variable to the next state.
    /// - For `Finalize` blocks: returns empty (the block returns directly)
    /// - For blocks with opaque predicates: generates `if predicate { real } else { fake }`
    /// - For blocks without predicates: generates direct assignment to next state
    fn generate_transition(&self, block: &StateBlock) -> TokenStream2 {
        match block.block_type {
            BlockType::Finalize => quote! {},
            _ => {
                if let (Some(real_next), Some(fake_next), Some(pred)) =
                    (block.real_next, block.fake_next, &block.predicate)
                {
                    let real_value = self.state_values[&real_next];
                    let fake_value = self.state_values[&fake_next];
                    let condition = pred.generate_condition(self.config.use_black_box);

                    quote! {
                        state = if #condition { #real_value } else { #fake_value };
                    }
                } else if let Some(real_next) = block.real_next {
                    let real_value = self.state_values[&real_next];
                    quote! { state = #real_value; }
                } else {
                    quote! {}
                }
            }
        }
    }

    /// Build final TokenStream
    ///
    /// # Panics
    ///
    /// Panics if `add_init_block()` was not called before `build()`.
    pub fn build<R: Rng>(mut self, ciphertext: &[u8], rng: &mut R) -> TokenStream2 {
        debug_assert!(
            self.entry_state.is_some(),
            "add_init_block() must be called before build()"
        );

        if let Err(e) = self.assign_state_values(rng) {
            return e.to_compile_error();
        }

        let ct_bytes = ciphertext.iter().map(|b| quote! { #b });
        let entry_value = self.state_values[&self.entry_state.unwrap()];

        BlockScheduler::shuffle(&mut self.blocks, rng);

        let match_arms = self.blocks.iter().map(|block| {
            let state_value = self.state_values[&block.id];
            let body = &block.body;
            let transition = self.generate_transition(block);
            quote! {
                #state_value => {
                    #body
                    #transition
                }
            }
        });

        quote! {
            ::obfuse::ObfuseStrInline::new(|| -> ::std::result::Result<::std::string::String, ::obfuse::ObfuseError> {
                let mut data: ::std::vec::Vec<u8> = vec![#(#ct_bytes),*];
                let mut state: u64 = #entry_value;
                loop {
                    match ::core::hint::black_box(state) {
                        #(#match_arms,)*
                        // SAFETY: All possible state values are generated uniquely by
                        // assign_state_values(). Any value not in the map is impossible
                        // at runtime because state is only ever set to values from
                        // self.state_values.
                        _ => unsafe { ::core::hint::unreachable_unchecked() },
                    }
                }
            })
        }
    }
}

/// Generate a random state value with good bit distribution
fn generate_state_value<R: Rng>(rng: &mut R, min_bits: u32, max_bits: u32) -> u64 {
    loop {
        let value = rng.random::<u64>();
        let ones = value.count_ones();
        if ones >= min_bits && ones <= max_bits {
            return value;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn test_state_value_bit_distribution() {
        let mut rng = ChaCha8Rng::seed_from_u64(33333);
        for _ in 0..1000 {
            let value = generate_state_value(&mut rng, 20, 44);
            let ones = value.count_ones();
            assert!(ones >= 20, "State value {} has only {} ones", value, ones);
            assert!(ones <= 44, "State value {} has {} ones", value, ones);
        }
    }

    #[test]
    fn test_build_produces_valid_tokenstream() {
        let mut rng = ChaCha8Rng::seed_from_u64(12345);
        let config = CffConfig::default();
        let mut builder = StateMachineBuilder::new(config);

        builder.add_init_block();
        builder.add_layer_block(0, quote! { data.reverse(); });
        builder.add_finalize_block();
        builder.connect_with_predicates(&mut rng);

        let code = builder.build(&[0x41, 0x42, 0x43], &mut rng);
        let code_str = code.to_string();
        assert!(code_str.contains("loop"));
        assert!(code_str.contains("match"));
        assert!(code_str.contains("unreachable_unchecked"));
    }

    #[test]
    fn test_state_machine_with_multiple_layers() {
        let mut rng = ChaCha8Rng::seed_from_u64(54321);
        let mut config = CffConfig::default();
        config.predicate_density = 1.0;
        let mut builder = StateMachineBuilder::new(config);

        builder.add_init_block();
        builder.add_layer_block(0, quote! { /* layer 0 */ });
        builder.add_finalize_block();
        builder.add_dead_block(&mut rng);

        builder.connect_with_predicates(&mut rng);
        
        assert_eq!(builder.blocks.len(), 4, "Should be exactly 4 blocks created");

        let code = builder.build(&[0x00], &mut rng);
        let code_str = code.to_string();
        assert_eq!(
            code_str.matches("u64 =>").count(),
            4,
            "Unexpected match arm count. Generated code: {}",
            code_str
        );
    }

    #[test]
    fn test_cff_edge_cases() {
        let mut rng = ChaCha8Rng::seed_from_u64(999);
        
        // Case 1: No fake blocks
        let mut config = CffConfig::default();
        config.fake_block_count = 0;
        let mut builder = StateMachineBuilder::new(config);
        builder.add_init_block();
        builder.add_finalize_block();
        // Should not panic
        builder.connect_with_predicates(&mut rng);
        let code = builder.build(&[], &mut rng);
        assert!(code.to_string().contains("match"));

        // Case 2: Zero predicate density
        config.predicate_density = 0.0;
        let mut builder = StateMachineBuilder::new(config);
        builder.add_init_block();
        builder.add_finalize_block();
        builder.add_dead_block(&mut rng);
        builder.connect_with_predicates(&mut rng);
        // Should have no opaque predicates (fake_next should be None or simple)
        // Checking internal state would be better, but we can check it doesn't crash

        // Case 3: Max predicate density
        config.predicate_density = 1.0;
        let mut builder = StateMachineBuilder::new(config);
        builder.add_init_block();
        builder.add_finalize_block();
        builder.add_dead_block(&mut rng); // Need dead block for predicates to form
        builder.connect_with_predicates(&mut rng);
    }
}
