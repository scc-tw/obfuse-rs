//! Integration tests for the obfuse library.

use obfuse::{ObfuseStr, obfuse};

#[test]
fn test_basic_decryption() {
    let secret = obfuse!("hello world");
    assert_eq!(secret.as_str(), "hello world");
}

#[test]
fn test_empty_string() {
    let secret = obfuse!("");
    assert_eq!(secret.as_str(), "");
}

#[test]
fn test_unicode() {
    let secret = obfuse!("Hello, 世界! 🌍");
    assert_eq!(secret.as_str(), "Hello, 世界! 🌍");
}

#[test]
fn test_long_string() {
    let _long_text = "a".repeat(10000);
    // Can't use repeat() in macro, so use a literal long string
    let secret = obfuse!(
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. \
        Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. \
        Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris \
        nisi ut aliquip ex ea commodo consequat."
    );

    assert!(secret.as_str().starts_with("Lorem ipsum"));
    assert!(secret.as_str().contains("consectetur"));
}

#[test]
fn test_special_characters() {
    let secret = obfuse!("!@#$%^&*()_+-=[]{}|;':\",./<>?`~\\");
    assert_eq!(secret.as_str(), "!@#$%^&*()_+-=[]{}|;':\",./<>?`~\\");
}

#[test]
fn test_newlines_and_tabs() {
    let secret = obfuse!("line1\nline2\tindented");
    assert_eq!(secret.as_str(), "line1\nline2\tindented");
}

#[test]
fn test_is_decrypted() {
    let secret = obfuse!("test");
    assert!(!secret.is_decrypted());

    let _ = secret.as_str();
    assert!(secret.is_decrypted());
}

#[test]
fn test_try_decrypt() {
    let secret = obfuse!("test");
    assert!(!secret.is_decrypted());

    secret.try_decrypt().unwrap();
    assert!(secret.is_decrypted());
}

#[test]
fn test_as_bytes() {
    let secret = obfuse!("hello");
    assert_eq!(secret.as_bytes(), b"hello");
}

#[test]
fn test_try_as_str() {
    let secret = obfuse!("test");
    let result = secret.try_as_str();
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "test");
}

#[test]
fn test_try_as_bytes() {
    let secret = obfuse!("test");
    let result = secret.try_as_bytes();
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), b"test");
}

#[test]
fn test_deref() {
    let secret = obfuse!("hello");
    // Deref to str
    let len: usize = secret.len();
    assert_eq!(len, 5);

    let upper = secret.to_uppercase();
    assert_eq!(upper, "HELLO");
}

#[test]
fn test_as_ref_str() {
    let secret = obfuse!("test");
    let s: &str = secret.as_ref();
    assert_eq!(s, "test");
}

#[test]
fn test_as_ref_bytes() {
    let secret = obfuse!("test");
    let b: &[u8] = secret.as_ref();
    assert_eq!(b, b"test");
}

#[test]
fn test_display() {
    let secret = obfuse!("displayable");
    let s = format!("{secret}");
    assert_eq!(s, "displayable");
}

#[test]
fn test_debug_redacts() {
    let secret = obfuse!("sensitive");
    let debug = format!("{secret:?}");

    // Should NOT contain the actual value
    assert!(!debug.contains("sensitive"));
    // Should contain [REDACTED]
    assert!(debug.contains("REDACTED"));
}

#[test]
fn test_deterministic_same_seed() {
    let secret1 = obfuse!("test data", seed = "same_seed");
    let secret2 = obfuse!("test data", seed = "same_seed");

    // Both should decrypt to the same value
    assert_eq!(secret1.as_str(), secret2.as_str());
    assert_eq!(secret1.as_str(), "test data");
}

#[test]
fn test_deterministic_different_seeds() {
    let secret1 = obfuse!("test", seed = "seed_a");
    let secret2 = obfuse!("test", seed = "seed_b");

    // Both decrypt to same plaintext despite different seeds
    assert_eq!(secret1.as_str(), secret2.as_str());
}

#[test]
fn test_type_annotation() {
    let secret: ObfuseStr = obfuse!("typed");
    assert_eq!(secret.as_str(), "typed");
}

#[test]
fn test_multiple_accesses() {
    let secret = obfuse!("multi");

    // Multiple accesses should work
    assert_eq!(secret.as_str(), "multi");
    assert_eq!(secret.as_str(), "multi");
    assert_eq!(secret.as_str(), "multi");

    // Should still be decrypted
    assert!(secret.is_decrypted());
}

#[test]
fn test_concurrent_access() {
    use std::sync::Arc;
    use std::thread;

    // Create a static obfuscated string
    let secret = Arc::new(obfuse!("concurrent test"));

    let handles: Vec<_> = (0..4)
        .map(|_| {
            let secret = Arc::clone(&secret);
            thread::spawn(move || {
                for _ in 0..100 {
                    assert_eq!(secret.as_str(), "concurrent test");
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }
}
