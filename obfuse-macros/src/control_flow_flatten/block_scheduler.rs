use super::state_machine::StateBlock;
use rand::Rng;

pub struct BlockScheduler;

impl BlockScheduler {
    /// Fisher-Yates shuffle of blocks.
    pub fn shuffle<R: Rng>(blocks: &mut [StateBlock], rng: &mut R) {
        let len = blocks.len();
        for i in (1..len).rev() {
            let j = rng.random_range(0..=i);
            blocks.swap(i, j);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::control_flow_flatten::state_machine::{BlockType, StateId};
    use super::*;
    use quote::quote;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use std::collections::{BTreeSet, VecDeque};

    // Helper to create a dummy block.
    fn new_dummy_block(id: u32, block_type: BlockType) -> StateBlock {
        StateBlock {
            id: StateId(id),
            body: quote! {},
            real_next: None,
            fake_next: None,
            predicate: None,
            block_type,
        }
    }

    /// Interleave real and fake blocks for better confusion.
    ///
    /// Uses VecDeque for O(1) pop_front instead of Vec::remove(0) which is O(n).
    /// This makes the overall function O(n) instead of O(n²).
    ///
    /// Note: This is a test utility; if needed in production, move to impl BlockScheduler.
    fn interleave<R: Rng>(
        real: Vec<StateBlock>,
        fake: Vec<StateBlock>,
        rng: &mut R,
    ) -> Vec<StateBlock> {
        let total_len = real.len() + fake.len();
        let mut result = Vec::with_capacity(total_len);

        let mut real_queue: VecDeque<StateBlock> = real.into();
        let mut fake_queue: VecDeque<StateBlock> = fake.into();

        while !real_queue.is_empty() || !fake_queue.is_empty() {
            // Weighted selection: slightly favor real blocks to ensure progress
            let take_real = if fake_queue.is_empty() {
                true
            } else if real_queue.is_empty() {
                false
            } else {
                rng.random::<f32>() < 0.6
            };

            if take_real {
                result.push(real_queue.pop_front().unwrap());
            } else {
                result.push(fake_queue.pop_front().unwrap());
            }
        }
        result
    }

    #[test]
    fn test_shuffle_preserves_elements() {
        let mut rng = ChaCha8Rng::seed_from_u64(11111);
        let mut blocks: Vec<StateBlock> = (0..20)
            .map(|i| new_dummy_block(i, BlockType::Dead))
            .collect();

        let original_ids: BTreeSet<u32> = blocks.iter().map(|b| b.id.0).collect();
        let original_len = blocks.len();

        BlockScheduler::shuffle(&mut blocks, &mut rng);

        let new_ids: BTreeSet<u32> = blocks.iter().map(|b| b.id.0).collect();

        assert_eq!(
            blocks.len(),
            original_len,
            "Shuffle should not change the number of blocks"
        );
        assert_eq!(
            original_ids, new_ids,
            "Shuffle should preserve all original block IDs"
        );
    }

    #[test]
    fn test_interleave_produces_correct_count() {
        let mut rng = ChaCha8Rng::seed_from_u64(54321);
        let real_blocks: Vec<StateBlock> = (0..5)
            .map(|i| new_dummy_block(i, BlockType::Layer(i as usize)))
            .collect();
        let fake_blocks: Vec<StateBlock> = (100..103)
            .map(|i| new_dummy_block(i, BlockType::Dead))
            .collect();

        let real_count = real_blocks.len();
        let fake_count = fake_blocks.len();

        let interleaved = interleave(real_blocks, fake_blocks, &mut rng);

        assert_eq!(
            interleaved.len(),
            real_count + fake_count,
            "Interleaved list should have the sum of block counts"
        );
    }
}
