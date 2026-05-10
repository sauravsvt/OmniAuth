# Audits

Index of external cryptographic and security audits. Required by `.cursor/rules/audit-trigger.mdc`.

## Triggers

- Protocol design review by an external applied cryptographer before any flow that crosses Rust → Go interop ships to a non-developer user.
- Implementation audit of `oss/crypto-core` before publishing to crates.io or tagging `v0.1.0`.
- ZK circuit and trusted-setup ceremony review before publishing fixed verifying keys for relying parties.
- Mobile audit before any production release.
- Backend audit before any production deployment.
- Re-audit after any change that alters a wire format, KDF, AAD, ZK circuit, threshold scheme, or recovery semantics.

## Catalog

| Audit | Scope | Auditor | Date | Report Location | Critical | High | Medium | Low | Re-Test Date |
|-------|-------|---------|------|-----------------|----------|------|--------|-----|--------------|
| _placeholder_ | _fill in_ | _fill in_ | _fill in_ | _fill in_ | _0_ | _0_ | _0_ | _0_ | _fill in_ |

## Severity Rules

- Critical and high findings block the release.
- Medium findings require a documented remediation plan.
- Low findings require a tracked issue.

## Pre-Audit Hardening

- Rust: `cargo clippy --all-targets -D warnings`, no `unsafe` without justification, RustSec scan clean.
- Go: `go vet ./...` clean, `govulncheck` clean, no plaintext logging.
- Mobile: `npm audit` reviewed, no debug `console.log`s in release, UniFFI bindings synchronized.
- Threat model up to date in `oss/crypto-core/src/lib.rs` and `docs/research/paper.md`.
- Fuzz harnesses for serialization and AAD parsing.
