//! Constraint coverage map (IVD Rule 3: every constraint has a test).
//!
//! This file is the index that ties each constraint in `vault_intent.yaml` to the integration test
//! that proves it. As constraints are implemented (see `ROADMAP.md`), replace the `#[ignore]`
//! placeholders with real assertions. CI runs the active tests; the ignored ones document what is
//! still owed so a constraint can never be silently left unverified.

/// Helper to make intent explicit in test names.
macro_rules! constraint_test {
    ($name:ident, $constraint:literal, $desc:literal) => {
        #[test]
        #[ignore = "pending implementation — see ROADMAP.md"]
        fn $name() {
            // Constraint $constraint: $desc
            // TODO: implement per vault_intent.yaml `test:` block for $constraint.
        }
    };
}

constraint_test!(c1_stream_aead, "C1", "XChaCha20-Poly1305 STREAM: reorder/truncate detection");
constraint_test!(c2_argon2id_floor, "C2", "Argon2id floor enforced; warn below recommended");
constraint_test!(c2_argon2id_ceiling, "C2", "Reject KDF params above ceiling before allocation");
constraint_test!(c2_nfc_normalization, "C2", "NFC vs NFD master password derives identical key");
constraint_test!(c5_yubikey_staleness, "C5", "YubiKey absent: graceful stale save + warning; strict mode aborts");
constraint_test!(c7_magic_version, "C7", "Reject bad magic and newer format_version");
constraint_test!(c9_header_hmac, "C9", "Data-key-keyed HMAC verifiable on hardware-only unlock; stanza-step error ambiguous");
constraint_test!(c10_block_stream, "C10", "HmacBlockStream: swap/duplicate/truncate detection");
constraint_test!(c11_zeroize, "C11", "Secret buffers are zeroed on drop; no plain Vec<u8> secrets");
constraint_test!(c12_mlock_warn_once, "C12", "mlock failure warns exactly once; KDF buffer exempt");
constraint_test!(c13_helper_clear, "C13", "Detached helper clears after CLI exit; clear-iff-unchanged");
constraint_test!(c16_rollback, "C16", "Regressed version warns/aborts; non-TTY exits code 2");
constraint_test!(c16_tofu_first_open, "C16", "First open with no anchor is TOFU: accepted, anchor created");
constraint_test!(c18_zero_plaintext, "C18", "strings(vault.vlt) reveals no entry content");
constraint_test!(c19_inner_stream_per_save, "C19", "Inner stream key differs between saves; in-RAM protection");
constraint_test!(c21_exit_code_map, "C21", "Frozen exit codes 0-9 per failure class; clap usage exits 8");
constraint_test!(c26_gen_unbiased, "C26", "CSPRNG generator: uniform charset, no modulo bias");
constraint_test!(c27_model_blind, "C27", "get → clipboard by default; --stdout warns on stderr");
constraint_test!(c27_headless_refusal, "C27", "No clipboard: refuse with exit 7, never silent stdout fallback");
constraint_test!(c28_terminal_sanitization, "C28", "Control/ANSI/OSC bytes never reach the terminal raw");
constraint_test!(c29_export_injection, "C29", "CSV formula metacharacters escaped; strict JSON escaping");
constraint_test!(c30_parser_robustness, "C30", "forbid(unsafe_code); hostile lengths rejected pre-allocation");
constraint_test!(c31_no_argv_secrets, "C31", "No secret-accepting flags exist; stdin/prompt/fd only");
constraint_test!(c32_atomic_save, "C32", "Kill -9 during save never loses the vault; flock excludes writers");
constraint_test!(c33_clipboard_concealment, "C33", "Clipboard writes carry concealed/history-exclusion marks");
constraint_test!(c34_release_verification, "C34", "Reproducible build digests match; unsigned release fails closed");
constraint_test!(c40_gui_reactive_repaint, "C40", "vault-gui reactive repaint; no continuous request_repaint");
constraint_test!(c41_gui_glow_renderer, "C41", "eframe glow pinned; persistence feature disabled");
constraint_test!(c42_gui_search_cache, "C42", "vault-gui caches find results until query or entries change");
constraint_test!(c43_gui_list_virtualize, "C43", "entry list virtualized above 500 rows");
constraint_test!(c44_gui_password_mask, "C44", "password TextEdit fields use password(true)");
constraint_test!(c45_gui_thin_shell, "C45", "vault-gui no direct crypto; Action dispatch after panels");
constraint_test!(c46_gui_reveal_timeout, "C46", "vault-gui reveal auto re-masks within 15s");
constraint_test!(c47_gui_lock_on_blur, "C47", "vault-gui optional lock when window loses focus");
constraint_test!(c48_gui_keyfile_unlock, "C48", "vault-gui unlocks keyfile-2FA vaults");
constraint_test!(c49_gui_keyfile_enroll, "C49", "vault-gui enrolls keyfile 2FA with recovery modal");
constraint_test!(c50_gui_pre10_notice, "C50", "vault-gui pre-1.0 banner until dismissed");
constraint_test!(c51_gui_clipboard_timeout, "C51", "vault-gui configurable clipboard clear timeout");
constraint_test!(c52_gui_virtualize_100, "C52", "vault-gui virtualizes entry list above 100 rows");
constraint_test!(c53_gui_search_scope_hint, "C53", "vault-gui search hint states metadata-only scope");
constraint_test!(c54_gui_password_labels, "C54", "vault-gui password fields have explicit labels");
constraint_test!(c55_audit_readiness_script, "C55", "audit-readiness.sh passes on release toolchain");
constraint_test!(c56_audit_intake_doc, "C56", "AUDIT_READINESS.md lists CP-7 scope");
constraint_test!(c57_enterprise_env_vars, "C57", "vault-gui honors VAULT_VAULT_PATH, VAULT_CONFIG_DIR, VAULT_LOCK_ON_BLUR");
constraint_test!(c58_c38_release_only, "C58", "C38 search benchmark skips in debug builds");
constraint_test!(c59_search_5k_200ms, "C59", "search at N=5000 under 200 ms in release");
constraint_test!(c60_enterprise_posture_docs, "C60", "ENTERPRISE_POSTURE + enterprise-deployment docs exist");
