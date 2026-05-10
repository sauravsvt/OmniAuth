# OmniAuth Rules

These rules are the durable operating contract for every new coding session.

## Start Command

- When the user says `let's start`, `start`, `continue the build`, or gives no narrower task, read the project docs first and continue the next incomplete milestone from `docs/progress.md`.
- When the user says `let's do`, enter full safe automation mode: continue milestone-by-milestone, use git automation, update research/paper/progress, and stop only for safety stops, blockers, or major decision points.
- The startup docs are `RULES.md`, `plan.md`, `.cursor/rules/*.mdc`, `docs/start-workflow.md`, `docs/engineering-principles.md`, `docs/quality-gates.md`, `docs/git-workflow.md`, `docs/progress.md`, `docs/research/decision-research.md`, `docs/research/research-log.md`, `docs/research/paper.md`, `docs/research/references.bib`, `project_backlog.md`.
- Skim `2.0.md` only when strategic vision is relevant; treat it as inspiration, not commitment.
- End each work run by updating `docs/progress.md` and reporting phase, completed milestone, percent progress, checks, research updates, paper updates, risks, and next step.
- Stop after one milestone by default unless the trigger is `let's do`.

## Product Direction

- Build a post-quantum identity and authentication platform.
- The Rust crypto core is the audit-ready trust layer. The Go backend orchestrates and verifies. The mobile client is a vault-based reference; password is required for every cryptographic operation.
- Use NIST-finalized PQC: ML-KEM-768 (FIPS 203) and ML-DSA-65 (FIPS 204). Track FIPS 205 (SLH-DSA) and HQC as candidate alternates.
- Prefer hybrid PQC + classical modes where practical until PQC stacks have wider audit coverage.
- ZK identity claims (Groth16 on BN254) are the privacy-preserving disclosure layer; trusted setup must move from per-instance to a Powers-of-Tau ceremony before publishing fixed verifying keys for production.
- The dual-license boundary is real: `oss/` is AGPL, `proprietary/` is proprietary. Do not move code across the boundary without explicit user confirmation.

## Cryptographic Rules

- Production crypto in `oss/crypto-core` must use audited or NIST-aligned crates.
- Never write production cryptographic primitives by hand.
- No plaintext, master passwords, master keys, KEKs, ML-DSA secret keys, ML-KEM secret keys, ZK witnesses, or recovery shares may be logged, persisted unencrypted, or sent over the network.
- Each crypto operation re-decrypts under the password; there is no long-lived `Identity` object exposed via FFI.
- Constant-time discipline at every secret comparison; use `subtle::ConstantTimeEq` in Rust and `crypto/subtle.ConstantTimeCompare` in Go.
- Replay protection on every challenge-bearing endpoint; single-use challenges with TTL.
- Recovery is a client-side ceremony (threshold PQC, social recovery guardians, or MPC); no server-side reset.

## Cross-Project Coordination

- OmniAuth and MyPassword (`../MyPassword`) share one PhD spine. OmniAuth is the higher-novelty PhD anchor.
- Read MyPassword's `RULES.md`, `plan.md`, and `docs/progress.md` before claiming novelty or changing a shared crypto pattern.
- The user's working agreement: MyPassword is finished through Phase 3 (desktop) before deep OmniAuth Phase 1+ work. After MyPassword Phase 3 ships, OmniAuth becomes the primary track.
- At every phase boundary, surface the sibling-coordination check and wait for the user.

## Research Freshness

- Before adding dependencies or choosing protocol details, check current official docs, crate / library status, security advisories, and primary standards (FIPS, RFC, CFRG drafts, IETF PQC drafts, arkworks-rs upstream, CIRCL upstream).
- Track NIST PQC milestones: HQC selected March 2025; CISA PQC procurement advisory January 2026; CNSA 2.0 deadline January 2027.
- Record non-trivial research decisions in `docs/research/` with source links and dates.
- Pin exact dependencies in lockfiles after selection; do not pretend pinned means permanently correct.
- Before important decisions, compare viable options using `docs/research/decision-research.md` and choose best current practice for this phase.
- If current evidence contradicts the old plan, stop and explain the trade-off before coding.

## Coding Workflow

- Before each phase, state the guarantee, non-guarantees, crate/version choices (Rust + Go + mobile), test plan, and places where mistakes silently weaken security.
- Write test stubs before implementation for ZK circuits, PQC vault behavior, and interop vectors.
- Keep changes phase-aligned and small enough to review.
- Run formatting and tests after substantive edits across all touched languages.
- Do not market or document the system as "proven secure"; document assumptions, limits, and audit requirements.

## Engineering Discipline

- Prefer simple, reviewable, phase-aligned code over architecture for future phases.
- Add abstractions only for real duplication, protocol boundaries, or security invariants.
- Make invalid states hard to represent with explicit types and narrow APIs.
- Stop and ask before changing architecture, adding major dependencies, weakening a guarantee, or introducing a new cross-language boundary.

## Quality Gates

- User-facing work needs happy, empty, loading, error, and recovery states before it is done.
- Security-sensitive work needs negative tests for tampering, wrong keys, wrong AAD, stale versions, replay, revoked identity when applicable, and ZK soundness rejections.
- Builds must be reproducible from documented commands and lockfiles for Rust, Go, and mobile.
- Deployment requires config validation, non-secret logs, health checks, rollback notes, and no plaintext leakage in telemetry or crash reports.

## Git Automation

- Git commits, branches, merges, pushes, rebases, resets, and branch deletion require explicit user opt-in for the current run. `let's do` is explicit opt-in for branch, commit, merge, and local cleanup automation.
- When opted in, keep one milestone per branch, run checks before commit/merge, exclude secrets / `.env` / mobile keystores / signing keys / unrelated user changes, merge only when safe, delete local merged branches, then report remaining git state.
- Pushing, deployment, force-push, and shared-history rewrites require separate explicit authorization or clear project-doc authorization.
- Respect the dual-license boundary; do not move proprietary code into `oss/`.

## Documentation And Paper

- Do not create docs just to create docs. Each doc change must support the product, preserve a decision, enable automation, or improve the publishable paper.
- Prefer updating existing docs over creating new docs.
- Research paper claims need citations in `docs/research/references.bib` and source context in `docs/research/research-log.md`.
- The end goal is a working PQC identity prototype and a publishable paper with evidence, citations, evaluation, formal analysis, and limitations.
