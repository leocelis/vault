//! The inner ChaCha20 random stream over Protected fields (constraint C19).
//!
//! After the outer XChaCha20-Poly1305 AEAD (C1), every field marked Protected (password,
//! `otp_secret`, protected custom values) receives an **additional** ChaCha20 stream-cipher pass
//! keyed by the payload's 64-byte `inner_stream_key`. Protected fields are processed in **document
//! order through a single stream** whose state advances sequentially (not independently keyed per
//! field), exactly matching between save (encrypt) and open (decrypt) — KDBX 4 precedent.
//!
//! On disk this is **defense-in-depth only**: the outer AEAD is the primary confidentiality
//! boundary. The inner stream's primary purpose is in-memory protection, which is layered on top of
//! this serialization pass in a later segment (C19 "IN-MEMORY USE").
//!
//! ## Key derivation (implementation-defined, within C19's latitude)
//! The 64-byte key is mapped to an IETF ChaCha20 instance:
//! - bytes `0..32`  → 256-bit ChaCha20 key
//! - bytes `32..44` → 96-bit nonce
//! - bytes `44..64` → reserved (unused by the 12-byte-nonce instantiation in v1)
//!
//! The counter starts at zero and advances as the keystream is consumed across all Protected
//! fields, so each field is encrypted under a distinct keystream segment.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;

use crate::format::payload::INNER_STREAM_KEY_LEN;

/// A single sequential ChaCha20 keystream over a vault's Protected fields (constraint C19).
pub(crate) struct InnerStream {
    cipher: ChaCha20,
}

impl InnerStream {
    /// Build the stream from the 64-byte inner-stream key.
    ///
    /// Callers guarantee `key.len() == INNER_STREAM_KEY_LEN` (the payload parser validates the
    /// length before constructing, and a save always uses a freshly generated 64-byte key).
    pub(crate) fn new(key: &[u8]) -> Self {
        debug_assert_eq!(key.len(), INNER_STREAM_KEY_LEN);
        let cipher_key = chacha20::Key::from_slice(&key[0..32]);
        let nonce = chacha20::Nonce::from_slice(&key[32..44]);
        InnerStream {
            cipher: ChaCha20::new(cipher_key, nonce),
        }
    }

    /// Apply the next keystream segment to `data` in place, advancing the stream by `data.len()`
    /// bytes. A stream cipher is its own inverse, so this both encrypts (on save) and decrypts
    /// (on open) — the two passes stay in lockstep because Protected fields are visited in the
    /// same document order.
    pub(crate) fn apply(&mut self, data: &mut [u8]) {
        self.cipher.apply_keystream(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; INNER_STREAM_KEY_LEN] = [0x5A; INNER_STREAM_KEY_LEN];

    #[test]
    fn apply_is_its_own_inverse() {
        let plain = b"ghp_FAKE0mZ9xQ2vL7nR4tW8pY1aB3cD5eF6gH7iJ";
        let mut buf = plain.to_vec();
        InnerStream::new(&KEY).apply(&mut buf);
        assert_ne!(buf, plain); // encrypted: not the plaintext
        InnerStream::new(&KEY).apply(&mut buf);
        assert_eq!(buf, plain); // decrypted back with a fresh stream at the same key
    }

    #[test]
    fn stream_advances_sequentially_across_fields() {
        // Two fields encrypted through one advancing stream must differ from the same two fields
        // each encrypted from a fresh stream position 0 (the second field's keystream is offset).
        let (a, b) = (
            b"first-secret-value".to_vec(),
            b"first-secret-value".to_vec(),
        );
        let mut s = InnerStream::new(&KEY);
        let mut a_seq = a.clone();
        s.apply(&mut a_seq);
        let mut b_seq = b.clone();
        s.apply(&mut b_seq); // continues the stream — different keystream than a
        assert_ne!(
            a_seq, b_seq,
            "identical plaintexts must encrypt differently down one stream"
        );

        // Decrypting in the same order recovers both.
        let mut d = InnerStream::new(&KEY);
        let mut a_back = a_seq.clone();
        d.apply(&mut a_back);
        let mut b_back = b_seq.clone();
        d.apply(&mut b_back);
        assert_eq!(a_back, a);
        assert_eq!(b_back, b);
    }

    #[test]
    fn wrong_key_does_not_recover() {
        let plain = b"supersecret123".to_vec();
        let mut ct = plain.clone();
        InnerStream::new(&KEY).apply(&mut ct);
        let mut wrong = ct.clone();
        InnerStream::new(&[0x11; INNER_STREAM_KEY_LEN]).apply(&mut wrong);
        assert_ne!(wrong, plain);
    }
}
