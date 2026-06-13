//! Fuzz stanza-record parsing (constraints C30, C5).
//!
//! Stresses bounded-length handling: `stanza_count <= 8`, `stanza_data_len <= 4096`, no overflow.
//! Invariant: arbitrary bytes yield `Ok` or a `vault_core::Error` — never a panic or over-alloc.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // `[count: u8][stanza × count]` — exercises the count bound and per-record length bounds.
    let _ = vault_core::format::stanza::parse_sequence(data);
});
