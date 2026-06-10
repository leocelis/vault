//! On-disk file format and integrity — constraints **C7–C10, C18, C19**.
//!
//! This module parses **untrusted bytes** (a synced or restored vault file). It must never panic,
//! hang, or over-allocate on hostile input: every length field is bounded against the remaining
//! buffer *before* allocation, and KDF params are range-checked *before* Argon2id runs.
//! The parsers here are the primary targets in `fuzz/` (constraint C30).
//!
//! See `docs/FILE_FORMAT.md` for the byte layout.

use crate::Result;

/// Maximum number of stanzas in a v1 vault (constraint C5).
pub const MAX_STANZAS: u8 = 8;
/// Maximum size of a single stanza's data blob (constraint C5).
pub const MAX_STANZA_DATA_LEN: u32 = 4096;
/// HmacBlockStream block size: 1 MiB (constraint C10).
pub const BLOCK_SIZE: usize = 1024 * 1024;

/// The plaintext header of a vault file (constraints C7–C9).
///
/// Holds only non-secret material: magic, version, KDF params, salts, stanza records, and the two
/// integrity tags. No field of this struct may hold entry content (constraint C18).
#[derive(Debug)]
pub struct Header {
    _private: (),
}

impl Header {
    /// Parse and validate a header from untrusted bytes.
    ///
    /// Order (constraints C9 and C2 ceiling): check magic/version → verify `header_hash`
    /// (keyless corruption check) → **range-check KDF params** → caller derives the master key →
    /// verify `header_hmac`. No body byte is decrypted if any check fails.
    pub fn parse(_bytes: &[u8]) -> Result<Self> {
        unimplemented!("M2: header parse with bounded reads (constraints C7–C9, C30)")
    }
}

/// Encrypt-then-MAC block stream over the AEAD body — HmacBlockStream with per-block
/// HMAC-SHA-256 and an end-of-stream marker (constraint C10).
pub mod block_stream {}

/// One key-wrapping stanza record — parsing with bounded lengths (constraint C5).
pub mod stanza {}
