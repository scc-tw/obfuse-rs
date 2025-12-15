//! Basic usage example for obfuse.

use obfuse::obfuse;

fn main() {
    // Random key mode (production) - different each compile
    let secret = obfuse!("my secret API key");

    println!("Is decrypted before access: {}", secret.is_decrypted());

    // Decryption happens on first access
    println!("Secret: {}", secret.as_str());

    println!("Is decrypted after access: {}", secret.is_decrypted());

    // Using Deref trait - also triggers decryption
    let len = secret.len();
    println!("Secret length: {len}");

    // Memory is securely wiped when `secret` goes out of scope
}
