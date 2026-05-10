# OmniAuth Research Paper Draft

Working title: **Post-Quantum Identity With Encrypted Vaults, Selective-Disclosure Proofs, And Threshold Recovery**

Citation style: use citation keys from `docs/research/references.bib`, for example `[@fips204]`.

## Target Venue

To be selected from: USENIX Security, NDSS, ACM CCS, IEEE S&P, PoPETs, ACM ASIACCS. Record the chosen venue and submission deadline here, and roll up "weeks remaining" in `docs/progress.md`.

Current target: _to be decided_.

## Abstract Draft

Post-quantum cryptography is moving from research to procurement: NIST finalized ML-KEM (FIPS 203) and ML-DSA (FIPS 204) in 2024; HQC was selected as a backup KEM in 2025; CISA's procurement advisory landed in January 2026 and CNSA 2.0 mandates new acquisitions starting January 2027. Identity, Credential, and Access Management systems remain in transition, because changing digital signatures requires updating PKI roots of trust, smart card stacks, and HSMs. OmniAuth explores an end-user identity architecture for this transition: an encrypted local vault holding NIST-finalized PQC keypairs, transient secret access via password-per-operation, selective-disclosure ZK proofs over identity claims, replay-protected challenge-response with a verifying backend, and a path to threshold recovery and behavioral liveness. The paper presents the architecture, threat model, formal analysis, and a measured prototype across Rust, Go, and a mobile reference client.

## Thesis

Practical post-quantum identity for end users is best built around encrypted local vaults with transient secret access, selective-disclosure ZK claims, replay-protected wire flows, and threshold recovery, with cross-language interop and formal verification as first-class engineering concerns.

## Research Contributions To Target

- A protocol specification for a PQC encrypted identity vault with versioned AAD and transient secret access (`oss/crypto-core/src/lib.rs`).
- A ZK identity claim suite (Groth16 on BN254) with sound bit-decomposed inequality constraints and a documented trusted-setup migration path.
- A challenge-response flow with single-use challenges, server-issued nonces, TTL bounds, and replay rejection, formally analyzed.
- A threshold-PQC recovery design with a formal model of secrecy and recoverability properties.
- A measured cross-language interop layer (Rust producer, Go consumer) with checked-in vectors and producer-and-consumer tests.

## Literature And Standards Map

- NIST PQC standards: `[@fips203]`, `[@fips204]`, `[@fips205]`.
- Argon2 memory-hard password hashing: `[@rfc9106]`.
- HPKE for key encapsulation envelopes: `[@rfc9180]`.
- OPAQUE augmented PAKE: `[@rfc9807]`.
- Groth16 zk-SNARK: `[@groth16]`.
- arkworks-rs ZK ecosystem: `[@arkworks]`.
- Cloudflare CIRCL PQC verification: `[@circl]`.
- CISA PQC procurement advisory 2026: `[@cisaPqcAdvisory2026]`.
- FIDO2 / WebAuthn post-quantum status (cite when sources are in `references.bib`).
- Decentralized identity (DID, VC, W3C specs).
- ZK identity work (zk-creds and similar).
- Sibling MyPassword paper for shared crypto patterns and recovery framing.

## Current Design Checkpoints

- Vault uses Argon2id-derived KEK + XChaCha20-Poly1305 with versioned AAD `OmniAuth-VaultBlob-v1`.
- Identity keypair is ML-DSA-65 (FIPS 204); KEM keypair is ML-KEM-768 (FIPS 203).
- ZK age and range circuits with 64-bit bit decomposition for soundness; per-instance trusted setup is development-only and must move to a Powers-of-Tau ceremony before publishing fixed VKs.
- Go backend verifier uses CIRCL Dilithium mode3 today; Rust↔Go signature interop encoding alignment is a known blocker tracked in `project_backlog.md`.
- Replay protection uses single-use challenges; the in-memory challenge store demo lives in the test suite and must be promoted to a persistent store with TTL before production.

## Core Research Questions

1. What is the minimum-friction PQC identity architecture that an end user can adopt today without trust regressions vs. classical FIDO2 / passkeys?
2. How should ZK identity claims be composed without introducing linkability across relying parties?
3. What is the right threshold-PQC scheme for social recovery in 2026, given the maturity of the candidate libraries?
4. How should hybrid PQC + classical constructions be staged through the multi-year transition the procurement advisories anticipate?
5. What protocol properties of a PQC challenge-response identity flow can be formally verified in Tamarin/ProVerif, and which require manual proof sketches?

## Evaluation Plan

- Security analysis against the threat model in `oss/crypto-core/src/lib.rs`.
- NIST KAT-aligned tests for ML-KEM and ML-DSA.
- ZK soundness tests including bit-decomposition boundary cases.
- Cross-language interop vectors with Rust producer and Go consumer tests.
- Formal models in `docs/research/formal/` for the challenge-response flow and any threshold scheme adopted.
- Benchmarks per `docs/benchmarks.md` with figure scripts in `docs/research/figures/`.
- Mobile reference UX walkthrough.
- Limitations and ethics sections addressing biometric, MPC, and recovery social dynamics.

## Non-Claims

- The system is not proven secure merely because it uses NIST-finalized primitives.
- PQC reduces "harvest now, decrypt later" risk but depends on the full protocol (challenge freshness, replay resistance, device binding, recovery) being correct.
- A weak master password remains weak despite Argon2id.
- Current ZK trusted setup is per-instance and unsuitable for production until a ceremony is run.
- Mobile keystores reduce but do not eliminate the risk of malware exfiltration.
- The Go backend's replay protection demo is not yet a production store.
- Cross-language interop is incomplete until Rust↔Go signature encodings agree.

## Paper Readiness Checklist

- [ ] Every technical claim has a citation, experiment, or implementation reference.
- [ ] Related work compares against current PQC identity efforts and post-quantum WebAuthn discussions.
- [ ] The protocol section matches implemented wire / storage formats (`docs/specs/`).
- [ ] Evaluation includes tests, attack scenarios, formal model results, and reproducibility notes.
- [ ] Limitations are explicit and not hidden in marketing language.
- [ ] References are maintained in `docs/research/references.bib`.
- [ ] Sibling MyPassword work cited where claims overlap.
- [ ] At least three entries from `docs/research/decisions-rejected.md` referenced in alternatives or limitations.
