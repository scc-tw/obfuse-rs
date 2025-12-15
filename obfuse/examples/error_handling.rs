//! Error handling example showing fallible API.

use obfuse::{ObfuseError, obfuse};

fn main() {
    let secret = obfuse!("sensitive data");

    // Fallible API - recommended for critical code paths
    match secret.try_as_str() {
        Ok(s) => println!("Secret: {s}"),
        Err(ObfuseError::AllocationFailed) => {
            eprintln!("Out of memory during decryption");
        }
        Err(ObfuseError::AuthenticationFailed) => {
            eprintln!("Decryption failed - binary may be corrupted");
        }
        Err(ObfuseError::InvalidUtf8(e)) => {
            eprintln!("Invalid UTF-8: {e}");
        }
    }

    // Using Result with ? operator
    if let Err(e) = process_secret() {
        eprintln!("Failed to process secret: {e}");
    }
}

fn process_secret() -> Result<(), ObfuseError> {
    let secret = obfuse!("API token");
    let value = secret.try_as_str()?;
    println!("Processing: {value}");
    Ok(())
}
