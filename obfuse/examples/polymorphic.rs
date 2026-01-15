//! Example demonstrating polymorphic decryption with multiple strings.
//!
//! This example shows how each obfuscated string gets unique, inline decryption code.

use obfuse::obfuse;

fn main() {
    // Each of these strings will have completely different decryption code
    let api_key = obfuse!("sk_live_abc123");
    let db_password = obfuse!("P@ssw0rd!2024");
    let secret_token = obfuse!("jwt_secret_xyz789");
    
    println!("API Key: {}", api_key.as_str());
    println!("DB Password: {}", db_password.as_str());
    println!("Secret Token: {}", secret_token.as_str());
    
    // Note: In polymorphic mode, there is NO central decrypt() function
    // Each string has its own unique transformation layers
    // Keys are computed at runtime, not stored as static data
}
