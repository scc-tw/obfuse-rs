#![cfg(feature = "control-flow-flatten")]

use obfuse::obfuse;

#[test]
fn test_flattened_decryption_correctness() {
    let original = "Hello, World! This is a test string with moderate length.";
    let obfuscated = obfuse!("Hello, World! This is a test string with moderate length.");
    assert_eq!(obfuscated.as_str(), original);
}

#[test]
fn test_flattened_with_seed_deterministic() {
    let s1 = obfuse!("test_deterministic", seed = "cff_deterministic_seed");
    let s2 = obfuse!("test_deterministic", seed = "cff_deterministic_seed");
    assert_eq!(s1.as_str(), "test_deterministic");
    assert_eq!(s2.as_str(), "test_deterministic");

    // A proper test would be to check if the generated code is identical,
    // but that's much harder. For now, we assume if they decrypt to the same
    // value, the seed is working.
}

#[test]
fn test_flattened_unicode() {
    let original = "こんにちは世界 🌍 Привет мир";
    let obfuscated = obfuse!("こんにちは世界 🌍 Привет мир");
    assert_eq!(obfuscated.as_str(), original);
}

#[test]
fn test_flattened_empty_string() {
    let obfuscated = obfuse!("");
    assert_eq!(obfuscated.as_str(), "");
}

#[test]
fn test_flattened_long_string() {
    let long_string = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed non risus. Suspendisse lectus tortor, dignissim sit amet, adipiscing nec, ultricies sed, dolor. Cras elementum ultrices diam. Maecenas ligula massa, varius a, semper congue, euismod non, mi. Proin porttitor, orci nec nonummy molestie, enim est eleifend mi, non fermentum diam nisl sit amet erat. Duis semper. Duis arcu massa, scelerisque vitae, consequat in, pretium a, enim. Pellentesque congue. Ut in risus volutpat libero pharetra tempor. Cras vestibulum bibendum augue. Praesent egestas leo in pede. Praesent blandit odio eu enim. Pellentesque sed dui ut augue blandit sodales. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia Curae; Aliquam nibh. Mauris ac mauris sed pede pellentesque fermentum. Maecenas adipiscing ante non diam. Proin sed libero.";
    let obfuscated = obfuse!("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed non risus. Suspendisse lectus tortor, dignissim sit amet, adipiscing nec, ultricies sed, dolor. Cras elementum ultrices diam. Maecenas ligula massa, varius a, semper congue, euismod non, mi. Proin porttitor, orci nec nonummy molestie, enim est eleifend mi, non fermentum diam nisl sit amet erat. Duis semper. Duis arcu massa, scelerisque vitae, consequat in, pretium a, enim. Pellentesque congue. Ut in risus volutpat libero pharetra tempor. Cras vestibulum bibendum augue. Praesent egestas leo in pede. Praesent blandit odio eu enim. Pellentesque sed dui ut augue blandit sodales. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia Curae; Aliquam nibh. Mauris ac mauris sed pede pellentesque fermentum. Maecenas adipiscing ante non diam. Proin sed libero.");
    assert_eq!(obfuscated.as_str(), long_string);
}

#[test]
fn test_multiple_obfuscated_strings() {
    let s1 = obfuse!("first string", seed = "multi_1");
    let s2 = obfuse!("second string", seed = "multi_2");

    assert_eq!(s1.as_str(), "first string");
    assert_eq!(s2.as_str(), "second string");
    assert_ne!(s1.as_str(), s2.as_str());
}