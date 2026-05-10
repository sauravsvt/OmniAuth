# Progress

This file tracks project completion for automated `let's start` sessions.

## Overall

Estimated weighted completion: 18%

Status: A working prototype exists. Rust crypto core implements an Argon2id-derived KEK, XChaCha20-Poly1305 vault, ML-KEM-768 + ML-DSA-65 keypairs with transient-secret APIs, and Groth16 ZK age/range circuits with bit-decomposed slack variables. Go backend exposes `/health` and `/api/v1/verify` (CIRCL Dilithium mode3 only) with replay-protection demo tests. Mobile reference client wires UniFFI Kotlin/Swift bindings and a registration screen. Phase 0 hardening (specs, threat model in code, benchmark catalog, paper skeleton, decisions-rejected log) is the immediate priority before deeper phases.

## Phase 0 - Foundation Hardening

Estimated completion: 35%

- [x] PQC vault implementation (Rust core).
- [x] ZK age and range circuits with sound bit decomposition.
- [x] Mobile UniFFI bridge stubs (Kotlin, Swift).
- [x] Go verifier with replay-protection demo test.
- [ ] Document vault format, AAD, KDF parameters, ZK circuits in `docs/specs/`.
- [ ] Lock the threat model comment block in `oss/crypto-core/src/lib.rs` and mirror in the paper.
- [ ] Establish `docs/benchmarks.md` entries and run baseline numbers.
- [ ] Establish `docs/research/decisions-rejected.md` with at least three retrospective entries (e.g., per-instance ZK setup vs ceremony, classical-only vs hybrid, password-per-op vs unlocked session).
- [ ] Close Rust↔Go signature interop encoding gap or record the limitation explicitly.
- [ ] Wire CI to run Rust + Go + mobile tests per `.github/workflows/ci.yml`.

## Phase 1 - Threshold PQC (Fragmentation)

Estimated completion: 0%

- [ ] Choose a threshold scheme (t-of-n ML-DSA via verifiable shares, or alternative) — record decision research entry.
- [ ] Add `docs/specs/threshold-sign-v1.md`.
- [ ] Implement share generation, partial sign, combine.
- [ ] Negative tests: t-1 coalition fails, malformed share rejected.
- [ ] Formal model under `docs/research/formal/threshold-sign-v1/`.
- [ ] Benchmarks added to `docs/benchmarks.md`.
- [ ] Paper section drafted.

## Phase 2 - Liveness / Behavioral Biometrics

Estimated completion: 0%

- [ ] Behavioral signal taxonomy + privacy story (no template storage; fuzzy extractors when feasible).
- [ ] Mobile SDK shape (iOS/Android) with explicit permission model.
- [ ] False-accept / false-reject baseline on a fixed dataset.
- [ ] Continuous-auth tick latency budget and benchmarks.

## Phase 3 - Decentralization (Social Recovery + MPC Escrow)

Estimated completion: 0%

- [ ] Social recovery guardian model + UX.
- [ ] MPC fragment storage protocol (IPFS / Arweave / Filecoin candidate evaluation).
- [ ] Adversarial guardian model analysis.
- [ ] Formal model.

## Phase 4 - Universal Client

Estimated completion: 0%

- [ ] Browser extension (MV3) with strict CSP and minimal permissions.
- [ ] OS-level daemon for SSH, VPN, NFC, Bluetooth integration scoping.
- [ ] Intercept-and-prove flow for stub login.

## Phase 5 - Proof / Paper

Estimated completion: 0%

- [ ] All benchmarks re-run with final parameters.
- [ ] Full Tamarin/ProVerif models passing.
- [ ] Paper draft frozen for venue submission (target recorded in `docs/research/paper.md`).
- [ ] Audit references included in evaluation / limitations.

## Cross-Cutting Tracks

- Interop closure (Rust↔Go signatures, ZK proof verification on Go side).
- Memory hygiene reviews.
- Audit triggers.
- Compliance posture (FIPS 203 / 204, CISA PQC procurement, CNSA 2.0).
- Cross-project coordination with MyPassword.

## Next Default Milestone

Phase 0: write `docs/specs/vault-blob-v1.md` mirroring the current `oss/crypto-core/src/lib.rs` vault format and AAD, then add the first three benchmark entries with measured numbers.
