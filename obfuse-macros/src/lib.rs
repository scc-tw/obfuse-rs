//! Procedural macros for compile-time string obfuscation.
//!
//! This crate provides the `obfuse!` macro that encrypts string literals
//! at compile time. It is used internally by the `obfuse` crate.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{LitStr, Token, parse::Parse, parse::ParseStream, parse_macro_input};

mod encrypt;

use encrypt::{KEY_SIZE, NONCE_SIZE, encrypt};

/// Input to the `obfuse!` macro.
///
/// Supports two forms:
/// - `obfuse!("string")` - random key each compile
/// - `obfuse!("string", seed = "seed_value")` - deterministic key from seed
struct ObfuseInput {
    literal: LitStr,
    seed: Option<LitStr>,
}

impl Parse for ObfuseInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let literal: LitStr = input.parse()?;

        let seed = if input.peek(Token![,]) {
            input.parse::<Token![,]>()?;

            // Parse `seed = "value"`
            let ident: syn::Ident = input.parse()?;
            if ident != "seed" {
                return Err(syn::Error::new(
                    ident.span(),
                    format!("expected `seed`, found `{ident}`"),
                ));
            }

            input.parse::<Token![=]>()?;
            Some(input.parse::<LitStr>()?)
        } else {
            None
        };

        Ok(Self { literal, seed })
    }
}

/// Encrypts a string literal at compile time.
///
/// # Usage
///
/// ## Random Key (Production)
///
/// ```ignore
/// use obfuse::obfuse;
///
/// let secret = obfuse!("my secret string");
/// println!("{}", secret.as_str());
/// ```
///
/// Each compilation generates a unique random key, making binaries non-reproducible
/// but maximizing obfuscation.
///
/// ## Deterministic Key (Testing/CI)
///
/// ```ignore
/// use obfuse::obfuse;
///
/// let secret = obfuse!("my secret string", seed = "test_seed");
/// println!("{}", secret.as_str());
/// ```
///
/// The same seed produces the same key across compilations, enabling reproducible
/// builds for testing and CI pipelines.
///
/// # Security Warning
///
/// This is **obfuscation**, not encryption. The key is embedded in the binary
/// alongside the ciphertext. A determined attacker can extract both.
#[proc_macro]
pub fn obfuse(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as ObfuseInput);
    obfuse_impl(input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

fn obfuse_impl(input: ObfuseInput) -> syn::Result<TokenStream2> {
    let plaintext = input.literal.value();
    let plaintext_bytes = plaintext.as_bytes();

    // Encrypt at compile time
    let (ciphertext, key, nonce) = encrypt(plaintext_bytes, input.seed.as_ref().map(|s| s.value()));

    // Convert to token streams
    let ciphertext_tokens = byte_array_tokens(&ciphertext);
    let key_tokens = fixed_byte_array_tokens::<KEY_SIZE>(&key);
    let nonce_tokens = fixed_byte_array_tokens::<NONCE_SIZE>(&nonce);

    Ok(quote! {
        ::obfuse::ObfuseStr::new(
            &#ciphertext_tokens,
            #key_tokens,
            #nonce_tokens,
        )
    })
}

/// Generates a token stream for a byte slice: `[0x01, 0x02, ...]`
fn byte_array_tokens(bytes: &[u8]) -> TokenStream2 {
    let byte_literals = bytes.iter().map(|b| quote! { #b });
    quote! { [#(#byte_literals),*] }
}

/// Generates a token stream for a fixed-size byte array: `[0x01, 0x02, ...; N]`
fn fixed_byte_array_tokens<const N: usize>(bytes: &[u8; N]) -> TokenStream2 {
    let byte_literals = bytes.iter().map(|b| quote! { #b });
    quote! { [#(#byte_literals),*] }
}
