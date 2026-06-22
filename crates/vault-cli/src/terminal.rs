//! Terminal output sanitization (C28).

/// Render control / ANSI bytes as visible escapes before writing to a TTY (constraint C28).
pub fn sanitize_for_terminal(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c == '\t' || !c.is_control() {
                c.to_string()
            } else {
                format!("\\x{:02x}", c as u32)
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c28_escapes_ansi_csi() {
        assert_eq!(sanitize_for_terminal("ok\x1b[31m"), "ok\\x1b[31m");
    }

    #[test]
    fn c28_preserves_tab_and_printable() {
        assert_eq!(sanitize_for_terminal("a\tb"), "a\tb");
    }
}
