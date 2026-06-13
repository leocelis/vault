//! Fuzz the HmacBlockStream reader (coverage-gap A4, constraint C10).
//!
//! Stresses block-size handling, the end-of-stream marker, and truncation/duplication resistance.
//! Invariant: arbitrary bytes yield `Ok` or a `vault_core::Error` — never a panic, hang, or
//! over-allocation (a hostile block size must be rejected before allocating).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fixed keys: we are fuzzing the reader's bounds and framing, not the HMAC's secrecy.
    let _ = vault_core::format::block_stream::read(&[0u8; 32], &[0u8; 32], data);
});
