//! Cryptographic primitives — constraints **C1–C3**.
//!
//! **No custom cryptography.** Every operation here is a thin wrapper over an audited library
//! (`chacha20poly1305`, `argon2`, `hkdf`, `hmac`, `sha2`). If a primitive is not in an audited
//! library, it does not belong in Vault (constraint C3).

use crate::Result;

/// STREAM chunk size: 64 KiB (constraint C1).
pub const STREAM_CHUNK_SIZE: usize = 64 * 1024;

/// Default Argon2id parameters: m = 64 MiB, t = 3, p = 4 (constraint C2).
pub const ARGON2_DEFAULT_M_COST_KIB: u32 = 65_536;
/// Default Argon2id time cost.
pub const ARGON2_DEFAULT_T_COST: u32 = 3;
/// Default Argon2id parallelism.
pub const ARGON2_DEFAULT_P_COST: u32 = 4;

/// Minimum acceptable Argon2id parameters — enforced on every open (constraint C2).
pub const ARGON2_FLOOR_M_COST_KIB: u32 = 19_456; // 19 MiB
/// Minimum time cost (we require ≥ 2 even when memory is higher — stricter than OWASP).
pub const ARGON2_FLOOR_T_COST: u32 = 2;
/// Minimum parallelism.
pub const ARGON2_FLOOR_P_COST: u32 = 1;

/// Maximum acceptable Argon2id memory cost — rejects hostile/overflowing files before allocation.
/// (Constraint C28: a missing ceiling is a memory-exhaustion / integer-overflow DoS.
/// Also requires m_cost >= 8 * p_cost per RFC 9106.)
pub const ARGON2_CEILING_M_COST_KIB: u32 = 4 * 1024 * 1024; // 4 GiB
/// Maximum time cost ceiling.
pub const ARGON2_CEILING_T_COST: u32 = 24;
/// Maximum parallelism ceiling.
pub const ARGON2_CEILING_P_COST: u32 = 16;

/// Validate stored Argon2id parameters against the floor **and** ceiling (constraints C2 + C28).
///
/// Returns `Ok(within_recommended)` where `false` means "valid but below current recommended,
/// warn and offer upgrade". Returns `Err(KdfParamsOutOfRange)` for values that are unsafe to even
/// attempt (below floor or above ceiling), so we never allocate gigabytes for a hostile file.
pub fn validate_kdf_params(m_cost: u32, t_cost: u32, p_cost: u32) -> Result<bool> {
    use crate::Error;

    // C28 ceiling FIRST — reject hostile/overflowing params before any allocation or Argon2id.
    if m_cost > ARGON2_CEILING_M_COST_KIB
        || t_cost > ARGON2_CEILING_T_COST
        || p_cost > ARGON2_CEILING_P_COST
    {
        return Err(Error::KdfParamsOutOfRange);
    }

    // RFC 9106: memory must be at least 8 * parallelism (one slice per lane). Checked math; p_cost
    // is already <= ceiling (16) here, so 8 * p_cost cannot overflow, but stay explicit.
    let min_m_for_lanes = p_cost.checked_mul(8).ok_or(Error::KdfParamsOutOfRange)?;
    if m_cost < min_m_for_lanes {
        return Err(Error::KdfParamsOutOfRange);
    }

    // C2 floor — below this is unsafe to even attempt.
    if m_cost < ARGON2_FLOOR_M_COST_KIB
        || t_cost < ARGON2_FLOOR_T_COST
        || p_cost < ARGON2_FLOOR_P_COST
    {
        return Err(Error::KdfParamsOutOfRange);
    }

    // Valid. `true` = at or above the current recommended defaults; `false` = valid but below
    // recommended (caller MUST warn and offer an upgrade — C2).
    let within_recommended = m_cost >= ARGON2_DEFAULT_M_COST_KIB
        && t_cost >= ARGON2_DEFAULT_T_COST
        && p_cost >= ARGON2_DEFAULT_P_COST;
    Ok(within_recommended)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    // `Error` cannot derive `PartialEq` (it wraps `io::Error`), so assert via unwrap / matches!.

    #[test]
    fn defaults_are_within_recommended() {
        assert!(validate_kdf_params(
            ARGON2_DEFAULT_M_COST_KIB,
            ARGON2_DEFAULT_T_COST,
            ARGON2_DEFAULT_P_COST
        )
        .unwrap());
    }

    #[test]
    fn exact_floor_is_valid_but_warns() {
        // C2 test: floor params are accepted (Ok) but below recommended (false).
        assert!(!validate_kdf_params(
            ARGON2_FLOOR_M_COST_KIB,
            ARGON2_FLOOR_T_COST,
            ARGON2_FLOOR_P_COST
        )
        .unwrap());
    }

    #[test]
    fn below_floor_is_rejected() {
        // m below 19 MiB, t below 2 — C2 floor failures.
        assert!(matches!(
            validate_kdf_params(4096, 1, 1),
            Err(Error::KdfParamsOutOfRange)
        ));
        assert!(matches!(
            validate_kdf_params(ARGON2_FLOOR_M_COST_KIB, 1, 1),
            Err(Error::KdfParamsOutOfRange)
        ));
    }

    #[test]
    fn above_ceiling_is_rejected_without_overflow() {
        // C28: extreme params rejected cleanly, no panic/overflow.
        assert!(matches!(
            validate_kdf_params(u32::MAX, u32::MAX, u32::MAX),
            Err(Error::KdfParamsOutOfRange)
        ));
        assert!(matches!(
            validate_kdf_params(ARGON2_CEILING_M_COST_KIB + 1, 3, 4),
            Err(Error::KdfParamsOutOfRange)
        ));
    }

    #[test]
    fn ceiling_exact_is_accepted() {
        // Exactly at the ceiling, m >= 8p satisfied → accepted (above recommended → true).
        assert!(validate_kdf_params(
            ARGON2_CEILING_M_COST_KIB,
            ARGON2_CEILING_T_COST,
            ARGON2_CEILING_P_COST
        )
        .unwrap());
    }

    #[test]
    fn memory_below_eight_times_parallelism_is_rejected() {
        // RFC 9106 m >= 8p: 64 KiB memory with p=16 needs >= 128 KiB.
        assert!(matches!(
            validate_kdf_params(64, 3, 16),
            Err(Error::KdfParamsOutOfRange)
        ));
    }
}

/// Encrypt a payload with XChaCha20-Poly1305 in STREAM mode (constraint C1).
///
/// Each 64 KiB chunk is independently sealed; no plaintext is released before its tag verifies.
pub mod stream {}

/// Argon2id key derivation (constraint C2).
pub mod kdf {}
