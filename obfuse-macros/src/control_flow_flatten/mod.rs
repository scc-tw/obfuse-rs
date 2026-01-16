mod opaque_predicates;
mod block_scheduler;
mod state_machine;

pub use state_machine::StateMachineBuilder;


/// Configuration for control flow flattening
#[derive(Debug, Clone, Copy)]
pub struct CffConfig {
    pub fake_block_count: usize,
    pub predicate_density: f32,
    pub use_black_box: bool,
    pub min_state_bits: u32,
    pub max_state_bits: u32,
}

impl Default for CffConfig {
    fn default() -> Self {
        Self {
            fake_block_count: 3,
            // The golden ratio, a common choice for creating a balanced but irregular distribution.
            predicate_density: 0.618,
            use_black_box: true,
            min_state_bits: 20,
            max_state_bits: 44,
        }
    }
}
