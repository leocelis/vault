# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepablechangelog.com/en/1.1.0/), and the project aims to adhere to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Open-source project scaffolding: governance, security policy, CI/security automation,
  documentation skeleton, and the `vault-core` / `vault-cli` / `vault-hardware` workspace.
- Intent specification with 34 constraints across 11 groups ([vault_intent.yaml](vault_intent.yaml)),
  including AI-era hardening (CSPRNG generation `C26`, model-blind delivery `C27`).
- Research foundation: security spec, AI-era offensive-LLM threat landscape, a security
  coverage-gap analysis, and a UI-architecture study ([research/](research/)).
- Product & design layer: a PRD with 18 major use cases ([docs/PRD.md](docs/PRD.md)), a tech spec
  per use case ([docs/specs/](docs/specs/README.md)), a dependency-ordered roadmap (critical path +
  sidequests), and a two-maintainer co-work protocol ([cowork.yaml](cowork.yaml)).
- UI direction (post-v1): shared Rust `vault-core` + thin per-platform shells over a stable FFI
  (Signal/UniFFI pattern); `ratatui` → `egui` → SwiftUI; copy-not-display delivery — `UC-18`.
- Quick-capture import of an unstructured secrets file with masked interactive review — `UC-17`.

### Changed
- Intent **v1.2.0**: extended `C27`'s forward constraint to UI surfaces (copy-not-display, no
  plaintext marshalled into an unzeroable managed-runtime heap) and clarified the GUI non-goal.
- Intent **v1.1.0**: fixed `C1`/`C8` XChaCha20 keystream reuse across saves via a per-body-write
  `nonce_prefix` HKDF salt (with conflict resolution `SC6`); fixed the SLSA provenance job in
  `release.yml`.

### Security (2026-06-10 spec-hardening pass — pre-implementation)
- Promoted the high-severity coverage gaps to enforced constraints: terminal output sanitization
  (`C28`), export/CSV-injection hardening (`C29`), parser robustness with `forbid(unsafe_code)` +
  CI fuzzing (`C30`), no secrets on argv (`C31`), atomic durable saves with locking (`C32`),
  clipboard concealment (`C33`), and reproducible/signed releases with provenance (`C34`).
- Folded a KDF parameter **ceiling** (anti-DoS, checked arithmetic) and **Unicode NFC**
  normalization of the master password into `C2`.
- Resolved spec self-contradictions: `C19` inner-stream key is regenerated per **save** (not per
  open) with an honest in-memory-protection rationale; `C5` documents the YubiKey
  device-at-save coupling with a graceful abort; `C12` scopes mlock to long-lived secrets with a
  once-per-process warning; `C16` documents the fresh-device trust-on-first-use limitation;
  `C20`'s acceptance test no longer passes a password on argv; `C27` states explicitly what
  model-blind delivery does and does not defend against.
- Constraint count 27 → 34; groups 10 → 11 (new `G11` — untrusted input/output robustness);
  satisfiability conflicts grew to 8 (`SC7` argv-vs-scriptability, `SC8` ceiling-vs-file-authoritative;
  `SC6` is the C1/C4 nonce_prefix binding from the keystream fix below). Intent version 1.2.0.

### Security (2026-06-10 — C1 keystream-reuse fix, intent v1.1.0)
- `C1`/`C8`: the empty-HKDF-salt deviation from age allowed XChaCha20 **keystream reuse across
  saves** (constant data key + counter nonces restarting at 0 ⇒ a history-keeping sync backend
  could XOR successive versions to recover plaintext diffs). Fixed with a per-body-write 16-byte
  `nonce_prefix` as the HKDF salt for the payload key, restoring age's construction; `SC6` binds
  salt rotation to body writes so `C4`'s O(1) password rotation is preserved.
- `release.yml`: SLSA provenance subjects were empty (matrix job outputs overwrote each other);
  a dedicated `hashes` job now computes the combined subjects.

### Added (product & design layer)
- `docs/PRD.md` (16 use cases, personas, success metrics) and `docs/specs/` — one tech spec per
  use case with alternatives, constraint compliance maps, and test plans.
- `ROADMAP.md` rewritten as dependency order: Gate 0 intent decisions, critical path CP-1..CP-7,
  parallel-safe sidequests, two-lane split.
- `cowork.yaml` + `CLAUDE.md`: two-maintainer/two-agent collaboration protocol (AG1–AG10).

### Notes
- This project is **pre-alpha**. No functional release exists yet; do not store real secrets.

[Unreleased]: https://github.com/leocelis/vault/commits/main
