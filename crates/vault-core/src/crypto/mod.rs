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
/// (Constraint C2 ceiling: a missing ceiling is a memory-exhaustion / integer-overflow DoS.)
pub const ARGON2_CEILING_M_COST_KIB: u32 = 4 * 1024 * 1024; // 4 GiB
/// Maximum time cost ceiling.
pub const ARGON2_CEILING_T_COST: u32 = 24;
/// Maximum parallelism ceiling.
pub const ARGON2_CEILING_P_COST: u32 = 16;

/// Validate stored Argon2id parameters against the floor **and** ceiling (constraint C2).
///
/// Returns `Ok(true)` when params are at or above the floor, `Ok(false)` when below the floor
/// (the caller must print the "below minimum recommended" warning and prompt before unlocking —
/// C2 mandates warn-and-prompt, not rejection, for the low end). Returns
/// `Err(KdfParamsOutOfRange)` only for above-ceiling or overflowing values, which are never
/// legitimate and are rejected before any allocation (so a hostile file can't OOM us).
pub fn validate_kdf_params(_m_cost: u32, _t_cost: u32, _p_cost: u32) -> Result<bool> {
    unimplemented!("M3: KDF param floor+ceiling validation (constraint C2)")
}

/// Encrypt a payload with XChaCha20-Poly1305 in STREAM mode (constraint C1).
///
/// Each 64 KiB chunk is independently sealed; no plaintext is released before its tag verifies.
pub mod stream {}

/// Argon2id key derivation with enforced floor/ceiling and NFC password normalization
/// (constraint C2).
pub mod kdf {}
