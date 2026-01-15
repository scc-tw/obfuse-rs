//! Integration tests for polymorphic decryption mode.

#[cfg(feature = "polymorphic")]
use obfuse::obfuse;

#[cfg(feature = "polymorphic")]
#[test]
fn test_polymorphic_basic_decryption() {
    let secret = obfuse!("hello world");
    assert_eq!(secret.as_str(), "hello world");
}

#[cfg(feature = "polymorphic")]
#[test]
fn test_polymorphic_empty_string() {
    let secret = obfuse!("");
    let _: &str = secret.as_str(); // Force type inference
    assert_eq!(secret.as_str(), "");
}

#[cfg(feature = "polymorphic")]
#[test]
fn test_polymorphic_unicode() {
    let secret = obfuse!("Hello, 世界! 🌍");
    assert_eq!(secret.as_str(), "Hello, 世界! 🌍");
}

#[cfg(feature = "polymorphic")]
#[test]
fn test_polymorphic_long_string() {
    let secret = obfuse!(
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. \
        Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. \
        Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris \
        nisi ut aliquip ex ea commodo consequat."
    );

    assert!(secret.as_str().starts_with("Lorem ipsum"));
    assert!(secret.as_str().contains("consectetur"));
}

#[cfg(feature = "polymorphic")]
#[test]
fn test_polymorphic_special_characters() {
    let secret = obfuse!("!@#$%^&*()_+-=[]{}|;':\",./<>?`~\\");
    assert_eq!(secret.as_str(), "!@#$%^&*()_+-=[]{}|;':\",./<>?`~\\");
}

#[cfg(feature = "polymorphic")]
#[test]
fn test_polymorphic_newlines_and_tabs() {
    let secret = obfuse!("line1\nline2\tindented");
    assert_eq!(secret.as_str(), "line1\nline2\tindented");
}

#[cfg(feature = "polymorphic")]
#[test]
fn test_polymorphic_is_decrypted() {
    let secret = obfuse!("test");
    assert!(!secret.is_decrypted());

    let _ = secret.as_str();
    assert!(secret.is_decrypted());
}

#[cfg(feature = "polymorphic")]
#[test]
fn test_polymorphic_try_decrypt() {
    let secret = obfuse!("test");
    assert!(!secret.is_decrypted());

    secret.try_decrypt().unwrap();
    assert!(secret.is_decrypted());
}

#[cfg(feature = "polymorphic")]
#[test]
fn test_polymorphic_as_bytes() {
    let secret = obfuse!("hello");
    assert_eq!(secret.as_bytes(), b"hello");
}

#[cfg(feature = "polymorphic")]
#[test]
fn test_polymorphic_try_as_str() {
    let secret = obfuse!("test");
    let result = secret.try_as_str();
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "test");
}

#[cfg(feature = "polymorphic")]
#[test]
fn test_polymorphic_try_as_bytes() {
    let secret = obfuse!("test");
    let result = secret.try_as_bytes();
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), b"test");
}

#[cfg(feature = "polymorphic")]
#[test]
fn test_polymorphic_deref() {
    let secret = obfuse!("hello");
    // Deref to str
    let len: usize = secret.len();
    assert_eq!(len, 5);

    let upper = secret.to_uppercase();
    assert_eq!(upper, "HELLO");
}

#[cfg(feature = "polymorphic")]
#[test]
fn test_polymorphic_as_ref_str() {
    let secret = obfuse!("test");
    let s: &str = secret.as_ref();
    assert_eq!(s, "test");
}

#[cfg(feature = "polymorphic")]
#[test]
fn test_polymorphic_as_ref_bytes() {
    let secret = obfuse!("test");
    let bytes: &[u8] = secret.as_ref();
    assert_eq!(bytes, b"test");
}

#[cfg(feature = "polymorphic")]
#[test]
fn test_polymorphic_display() {
    let secret = obfuse!("display test");
    let displayed = format!("{}", secret);
    assert_eq!(displayed, "display test");
}

#[cfg(feature = "polymorphic")]
#[test]
fn test_polymorphic_debug_redacts() {
    let secret = obfuse!("secret");
    let debug_output = format!("{:?}", secret);
    assert!(debug_output.contains("REDACTED"));
    assert!(!debug_output.contains("secret"));
}

#[cfg(feature = "polymorphic")]
#[test]
fn test_polymorphic_multiple_accesses() {
    let secret = obfuse!("test");

    // First access
    assert_eq!(secret.as_str(), "test");
    // Second access (from cache)
    assert_eq!(secret.as_str(), "test");
    // Third access
    assert_eq!(secret.as_str(), "test");
}

#[cfg(feature = "polymorphic")]
#[test]
fn test_polymorphic_concurrent_access() {
    use std::sync::Arc;
    use std::thread;

    let secret = Arc::new(obfuse!("concurrent test"));

    let handles: Vec<_> = (0..10)
        .map(|_| {
            let secret_clone = Arc::clone(&secret);
            thread::spawn(move || {
                assert_eq!(secret_clone.as_str(), "concurrent test");
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }
}

#[cfg(feature = "polymorphic")]
#[test]
fn test_polymorphic_deterministic_same_seed() {
    let secret1 = obfuse!("test string", seed = "same_seed");
    let secret2 = obfuse!("test string", seed = "same_seed");

    // With the same seed, the same plaintext should decrypt correctly
    assert_eq!(secret1.as_str(), "test string");
    assert_eq!(secret2.as_str(), "test string");
}

#[cfg(feature = "polymorphic")]
#[test]
fn test_polymorphic_deterministic_different_seeds() {
    let secret1 = obfuse!("test string", seed = "seed1");
    let secret2 = obfuse!("test string", seed = "seed2");

    // Both should decrypt to the same plaintext
    assert_eq!(secret1.as_str(), "test string");
    assert_eq!(secret2.as_str(), "test string");
}

#[cfg(feature = "polymorphic")]
#[test]
fn test_polymorphic_unique_encryption_per_string() {
    // Even though the content is the same, different invocations
    // should produce different encryption (in non-deterministic mode)
    let secret1 = obfuse!("same content");
    let secret2 = obfuse!("same content");

    // Both should decrypt correctly
    assert_eq!(secret1.as_str(), "same content");
    assert_eq!(secret2.as_str(), "same content");

    // The actual decryption happens independently for each
}

#[cfg(feature = "polymorphic")]
#[test]
fn test_polymorphic_type_annotation() {
    // Test that type annotations work
    let _secret: _ = obfuse!("typed test");
}
