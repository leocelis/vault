//! Clipboard auto-clear helper logic (constraint C13).

/// True when `cur` is still the secret the vault placed on the clipboard (clear-iff-unchanged).
pub fn clipboard_still_ours(cur: &[u8], secret: &[u8]) -> bool {
    cur == secret
        || cur.strip_suffix(b"\n") == Some(secret)
        || cur.strip_suffix(b"\r\n") == Some(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c13_exact_match() {
        assert!(clipboard_still_ours(b"secret", b"secret"));
    }

    #[test]
    fn c13_trailing_lf() {
        assert!(clipboard_still_ours(b"secret\n", b"secret"));
    }

    #[test]
    fn c13_trailing_crlf() {
        assert!(clipboard_still_ours(b"secret\r\n", b"secret"));
    }

    #[test]
    fn c13_user_overwrote_clipboard() {
        assert!(!clipboard_still_ours(b"other", b"secret"));
        assert!(!clipboard_still_ours(b"secret-extra", b"secret"));
    }
}
