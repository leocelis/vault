# Governance

Vault is an open-source project run by its [maintainers](MAINTAINERS.md). This document describes
how decisions are made. It is intentionally lightweight; we will formalize it further as the
community grows.

## Principles

1. **Security over convenience.** When they conflict, the more secure option wins, and the tradeoff
   is documented (this is encoded in `constraint_satisfiability` in [vault_intent.yaml](vault_intent.yaml)).
2. **Decide before you build.** Significant design decisions are agreed (as a constraint or an ADR)
   *before* implementation.
3. **Everything verifiable.** Claims are backed by tests; decisions are backed by written rationale.
4. **Eyes beyond the maintainers.** Two-maintainer sign-off is the same two people; we treat that
   honestly as a floor, not as independent review. Crypto and format changes actively solicit
   external (non-maintainer) review as the community grows, and an **independent security audit is
   a hard release gate for v1.0** (see [ROADMAP.md](ROADMAP.md) M10) — no audit, no 1.0.

## Decision tiers

| Change type | Process |
|-------------|---------|
| Docs, tests, refactors, non-security bugfixes | **Lazy consensus** — one maintainer approval, 24h for objections |
| New features / new constraints | Discussion → constraint added to `vault_intent.yaml` (with test) → one maintainer approval |
| **Cryptography, file format, KDF, release integrity** | **Two-maintainer sign-off required** (see CODEOWNERS) + an [ADR](docs/adr/) |
| Breaking format changes | Two-maintainer sign-off + ADR + `format_version` bump + migration plan |
| Adding/removing a maintainer | Unanimous maintainer agreement |

## Architecture Decision Records

Hard-to-reverse decisions are captured as [ADRs](docs/adr/). An ADR is immutable once accepted;
to change a decision, write a new ADR that supersedes it.

## Changes to this document

Governance changes require two-maintainer sign-off and a CHANGELOG entry.
