//! Deterministic mode example for reproducible builds.

use obfuse::obfuse;

fn main() {
    // Deterministic mode - same seed = same encryption each compile
    // Useful for:
    // - Unit tests
    // - CI/CD pipelines
    // - Debugging encryption issues

    let secret1 = obfuse!("database password", seed = "test_seed_123");
    let secret2 = obfuse!("database password", seed = "test_seed_123");

    // Both will decrypt to the same value
    println!("Secret 1: {}", secret1.as_str());
    println!("Secret 2: {}", secret2.as_str());

    // Different seeds produce different encryption
    let secret3 = obfuse!("database password", seed = "different_seed");
    println!("Secret 3: {}", secret3.as_str());

    // All three decrypt to the same plaintext, but have different ciphertext
    assert_eq!(secret1.as_str(), secret2.as_str());
    assert_eq!(secret2.as_str(), secret3.as_str());

    println!("\nAll secrets match: {}", secret1.as_str());
}
