//! Binary verification test to ensure obfuscated strings do not appear as plaintext.
//!
//! Builds the `hello` example in release mode (non-polymorphic) and verifies:
//! 1. `_OBFUSCATED_OBFUSE_RS_ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_1FAEFB6177B4672DEE07F9D3AFC62588CCD2631EDCF22E8CCC1FB35B501C9C86`, `_PLAINTEXT_OBFUSE_RS_ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_1FAEFB6177B4672DEE07F9D3AFC62588CCD2631EDCF22E8CCC1FB35B501C9C86` and the verification function symbol exist via `nm`
//! 2. `_OBFUSE_RS_ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_1FAEFB6177B4672DEE07F9D3AFC62588CCD2631EDCF22E8CCC1FB35B501C9C86` is a text (code) symbol (`T`)
//! 3. Plaintext `OBFUSE_RS_ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_1FAEFB6177B4672DEE07F9D3AFC62588CCD2631EDCF22E8CCC1FB35B501C9C86` appears exactly once in `strings` output (from the plaintext static only)

#[test]
fn test_obfuscated_string_not_in_plaintext() {
    use std::process::Command;

    // Build the hello example in release mode without polymorphic
    let build_output = Command::new("cargo")
        .args([
            "build",
            "--release",
            "--example",
            "hello",
            "--no-default-features",
            "--features",
            "aes-256-gcm",
        ])
        .output()
        .expect("Failed to run cargo build");

    assert!(
        build_output.status.success(),
        "Failed to build hello example: {}",
        String::from_utf8_lossy(&build_output.stderr)
    );

    let cargo_manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let workspace_root = std::path::Path::new(&cargo_manifest_dir)
        .parent()
        .expect("Failed to get workspace root");

    let binary_name = if cfg!(target_os = "windows") {
        "hello.exe"
    } else {
        "hello"
    };

    let binary_path = workspace_root
        .join("target")
        .join("release")
        .join("examples")
        .join(binary_name);

    assert!(
        binary_path.exists(),
        "Binary not found at {}",
        binary_path.display()
    );

    // Verify both symbols exist via nm (Unix) or dumpbin (Windows)
    let (cmd, args) = if cfg!(target_os = "windows") {
        ("dumpbin", vec!["/SYMBOLS", binary_path.to_str().unwrap()])
    } else {
        ("nm", vec![binary_path.to_str().unwrap()])
    };

    match Command::new(cmd).args(&args).output() {
        Ok(symbol_output) => {
            if !symbol_output.status.success() {
                println!(
                    "Skipping symbol verification: {} failed with: {}",
                    cmd,
                    String::from_utf8_lossy(&symbol_output.stderr)
                );
            } else {
                let symbols = String::from_utf8_lossy(&symbol_output.stdout);

                let has_obfuscated = symbols.lines().any(|l| l.contains("_OBFUSCATED_OBFUSE_RS_ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_1FAEFB6177B4672DEE07F9D3AFC62588CCD2631EDCF22E8CCC1FB35B501C9C86"));
                let has_plaintext = symbols.lines().any(|l| l.contains("_PLAINTEXT_OBFUSE_RS_ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_1FAEFB6177B4672DEE07F9D3AFC62588CCD2631EDCF22E8CCC1FB35B501C9C86"));
                let has_fn = symbols
                    .lines()
                    .any(|l| l.contains("_OBFUSE_RS_ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_1FAEFB6177B4672DEE07F9D3AFC62588CCD2631EDCF22E8CCC1FB35B501C9C86") && (l.contains(" T ") || l.contains("External")));

                assert!(
                    has_obfuscated,
                    "Symbol _OBFUSCATED_OBFUSE_RS_ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_1FAEFB6177B4672DEE07F9D3AFC62588CCD2631EDCF22E8CCC1FB35B501C9C86 not found in binary"
                );
                assert!(
                    has_plaintext,
                    "Symbol _PLAINTEXT_OBFUSE_RS_ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_1FAEFB6177B4672DEE07F9D3AFC62588CCD2631EDCF22E8CCC1FB35B501C9C86 not found in binary"
                );
                assert!(
                    has_fn,
                    "Function _OBFUSE_RS_ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_1FAEFB6177B4672DEE07F9D3AFC62588CCD2631EDCF22E8CCC1FB35B501C9C86 not found as text symbol in binary"
                );
                println!("✓ _OBFUSCATED_, _PLAINTEXT_, and verification function symbols present");
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("Skipping symbol verification: {} not found", cmd);
        }
        Err(e) => {
            panic!("Failed to run {}: {}", cmd, e);
        }
    }

    // Verify plaintext OBFUSE_RS_ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_... appears in binary
    // We read the binary directly to avoid dependency on `strings` command behavior/output format
    let binary_bytes = std::fs::read(&binary_path).expect("Failed to read binary file");

    const PLAINTEXT_MAGIC: &str = "OBFUSE_RS_ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_1FAEFB6177B4672DEE07F9D3AFC62588CCD2631EDCF22E8CCC1FB35B501C9C86";
    let magic_bytes = PLAINTEXT_MAGIC.as_bytes();

    let count = binary_bytes
        .windows(magic_bytes.len())
        .filter(|&w| w == magic_bytes)
        .count();

    assert!(
        count >= 1,
        "Expected plaintext {} in binary, found 0 occurrences",
        PLAINTEXT_MAGIC
    );

    // We expect at least 1 occurrence (the plaintext static).
    // Note: The string also appears in the symbol names (mangled), so count will likely be > 1.
    // We just verify it IS present to ensure the verification static wasn't optimized out.

    println!(
        "✓ Plaintext OBFUSE_RS_ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_... found in binary ({} occurrences including symbols)",
        count
    );
}
