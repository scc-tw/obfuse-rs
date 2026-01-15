//! Binary verification test to ensure polymorphic decryption is not optimized away.
//!
//! This test builds the polymorphic example in release mode and verifies that:
//! 1. Transformation instructions (XOR, ADD, SUB, ROL, ROR) are present
//! 2. No central decrypt function exists
//! 3. The binary executes correctly
//!
//! Supports both x86_64 and ARM64 (aarch64) architectures with appropriate
//! instruction pattern matching for each.

#[cfg(feature = "polymorphic")]
#[test]
fn test_polymorphic_not_optimized_away() {
    use std::process::Command;

    println!("Building polymorphic example in release mode...");

    // Build the polymorphic example
    let build_output = Command::new("cargo")
        .args(&[
            "build",
            "--release",
            "--example",
            "polymorphic",
            "--features",
            "polymorphic",
        ])
        .output()
        .expect("Failed to build polymorphic example");

    assert!(
        build_output.status.success(),
        "Failed to build polymorphic example: {}",
        String::from_utf8_lossy(&build_output.stderr)
    );

    println!("Build successful, analyzing binary...");

    // Path to the binary (relative to workspace root)
    let cargo_manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let workspace_root = std::path::Path::new(&cargo_manifest_dir)
        .parent()
        .expect("Failed to get workspace root");

    let binary_name = if cfg!(target_os = "windows") {
        "polymorphic.exe"
    } else {
        "polymorphic"
    };

    let binary_path = workspace_root
        .join("target")
        .join("release")
        .join("examples")
        .join(binary_name);

    // Check that binary exists
    assert!(
        binary_path.exists(),
        "Binary not found at {}",
        binary_path.display()
    );

    // Disassemble the binary
    let objdump_output = Command::new("objdump")
        .args(&["-d", binary_path.to_str().unwrap()])
        .output();

    if let Ok(output) = objdump_output {
        if output.status.success() {
            let disasm = String::from_utf8_lossy(&output.stdout);

            // Architecture-specific instruction patterns:
            // - x86_64: xor, add, sub, rol, ror
            // - ARM64:  eor (exclusive or), add, sub, ror (handles both rotations)
            let is_arm = cfg!(target_arch = "aarch64");

            // Count XOR instructions (x86: xor, ARM64: eor)
            let xor_count = if is_arm {
                // ARM64 uses 'eor' for exclusive OR
                disasm.matches("eor").count()
            } else {
                disasm.matches("xor").count()
            };

            // ADD and SUB are the same on both architectures
            let add_count = disasm.matches("add").count();
            let sub_count = disasm.matches("sub").count();

            // Rotation instructions
            // x86_64: rol (rotate left), ror (rotate right)
            // ARM64: ror only (rotate left is implemented as ror with inverted shift)
            let (rol_count, ror_count) = if is_arm {
                // ARM64 only has ror, but it's used for both directions
                (0usize, disasm.matches("ror").count())
            } else {
                (disasm.matches("rol").count(), disasm.matches("ror").count())
            };

            let arch_name = if is_arm { "ARM64" } else { "x86_64" };
            println!("Architecture: {}", arch_name);
            println!("Instruction counts:");
            if is_arm {
                println!("  EOR (XOR): {}", xor_count);
            } else {
                println!("  XOR: {}", xor_count);
            }
            println!("  ADD: {}", add_count);
            println!("  SUB: {}", sub_count);
            if is_arm {
                println!("  ROR: {}", ror_count);
            } else {
                println!("  ROL: {}", rol_count);
                println!("  ROR: {}", ror_count);
            }

            // Verify we have transformation instructions
            // Thresholds may vary by architecture due to different code generation
            let min_xor = if is_arm { 3 } else { 5 };
            let min_add = if is_arm { 5 } else { 10 };
            let min_sub = if is_arm { 3 } else { 5 };

            assert!(
                xor_count >= min_xor,
                "Expected at least {} XOR/{} instructions, found {}",
                min_xor,
                if is_arm { "EOR" } else { "XOR" },
                xor_count
            );
            assert!(
                add_count >= min_add,
                "Expected at least {} ADD instructions, found {}",
                min_add,
                add_count
            );
            assert!(
                sub_count >= min_sub,
                "Expected at least {} SUB instructions, found {}",
                min_sub,
                sub_count
            );
            assert!(
                rol_count + ror_count >= 1,
                "Expected at least 1 rotation instruction, found {} ROL + {} ROR",
                rol_count,
                ror_count
            );
        } else {
            println!("Warning: objdump failed, skipping disassembly verification");
            println!("stderr: {}", String::from_utf8_lossy(&output.stderr));
        }
    } else {
        println!("Warning: objdump not available, skipping disassembly verification");
    }

    // Check for decrypt symbols (should be none)
    let nm_output = Command::new("nm")
        .arg(binary_path.to_str().unwrap())
        .output();

    if let Ok(output) = nm_output {
        if output.status.success() {
            let symbols = String::from_utf8_lossy(&output.stdout);
            let decrypt_symbols: Vec<_> = symbols
                .lines()
                .filter(|line| line.to_lowercase().contains("decrypt"))
                .collect();

            assert!(
                decrypt_symbols.is_empty(),
                "Found decrypt symbols in polymorphic binary (should be none): {:?}",
                decrypt_symbols
            );
            println!("✓ No decrypt symbols found (as expected)");
        }
    }

    // Run the binary and verify output
    println!("Running binary to verify execution...");
    let run_output = Command::new(binary_path.to_str().unwrap())
        .output()
        .expect("Failed to run polymorphic example");

    assert!(
        run_output.status.success(),
        "Binary execution failed: {}",
        String::from_utf8_lossy(&run_output.stderr)
    );

    let output_str = String::from_utf8_lossy(&run_output.stdout);

    // Verify expected strings are in output
    assert!(
        output_str.contains("sk_live_abc123"),
        "Output missing expected string: sk_live_abc123"
    );
    assert!(
        output_str.contains("P@ssw0rd!2024"),
        "Output missing expected string: P@ssw0rd!2024"
    );
    assert!(
        output_str.contains("jwt_secret_xyz789"),
        "Output missing expected string: jwt_secret_xyz789"
    );

    println!("✓ Binary executes correctly and produces expected output");
    println!("\n✅ Polymorphic decryption verification PASSED");
}
