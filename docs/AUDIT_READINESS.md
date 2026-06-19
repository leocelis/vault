# Audit Readiness (CP-7)

Vault is **pre-1.0**. Independent third-party review is a **hard gate** before the `1.0.0` tag
([ROADMAP](../ROADMAP.md) CP-7). This document is the **auditor intake package** — not a substitute
for an audit.

## Scope for external review

| Area | Artifacts | Constraints |
|------|-----------|-------------|
| File format & parsers | `docs/FILE_FORMAT.md`, `crates/vault-core/src/format/`, fuzz targets | C7–C10, C30 |
| KDF & crypto | `docs/CRYPTO.md`, `crates/vault-core/src/crypto/` | C1–C6 |
| Memory & runtime | `docs/specs/UC-14-runtime-hardening.md`, `vault-sys` | C11–C13, C25 |
| Envelope & 2FA | `docs/specs/UC-09-hardware-factors.md` | C5, C14–C15 |
| AI-era delivery | `docs/specs/UC-04-model-blind-retrieval.md` | C26–C27 |
| Desktop shell boundary | `docs/specs/UC-18-native-ui.md`, `crates/vault-gui/` | C40–C54, C45 |
| Supply chain | `docs/VERIFYING_RELEASES.md`, SBOM, `cargo auditable` | C3, C34 |

Out of scope for v1 audit: team vaults, cloud sync service, browser extension (intent `non_goals`).

## Automated readiness check

From repo root (project toolchain active):

```sh
./scripts/audit-readiness.sh
```

Runs release search benchmarks (C38/C59), clippy, and supply-chain checks.

## IVD constraint index

Canonical constraints: [`vault_intent.yaml`](../vault_intent.yaml) (60 constraints as of v1.7.0).

Integration index: [`tests/constraint_coverage.rs`](../tests/constraint_coverage.rs).

## Threat model

[`docs/THREAT_MODEL.md`](THREAT_MODEL.md) — residual risks auditors should not expect mitigated.

## Disclosure

[`SECURITY.md`](../SECURITY.md) · [`docs/specs/UC-15-vulnerability-reporting.md`](specs/UC-15-vulnerability-reporting.md)
