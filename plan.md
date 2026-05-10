# OmniAuth Active Plan

This file is the durable project plan for new sessions. Read `RULES.md` and `.cursor/rules/` first, then follow this plan.

## Automation Trigger

When the user says `let's start`, `start`, `continue`, or asks to proceed without a narrower task, follow `docs/start-workflow.md` and continue the next incomplete milestone from `docs/progress.md`.

The run must include coding, research updates, paper notes, checks, and a progress report when they are relevant to the milestone.

## Current Strategic Direction

Build OmniAuth as a post-quantum identity and authentication platform with an audit-ready Rust crypto core (`oss/crypto-core`), a Go verifying backend (`proprietary/backend`), and a vault-based mobile reference client (`oss/client-mobile`).

The strongest direction:

- Use NIST-finalized PQC primitives (FIPS 203 ML-KEM-768, FIPS 204 ML-DSA-65) and track FIPS 205 (SLH-DSA) and HQC as candidate alternates.
- Prefer hybrid PQC + classical constructions where practical until PQC stacks mature.
- ZK identity claims (Groth16 on BN254) for privacy-preserving attribute verification; move trusted setup to a Powers-of-Tau ceremony before publishing fixed verifying keys.
- Close the Rust↔Go signature interop gap before shipping any cross-language production flow.
- Replay protection, challenge freshness, and device binding are first-class wire properties.
- Recovery is a client-side ceremony (threshold PQC, social recovery, or MPC).
- Maintain research notes and a paper draft while building. The OmniAuth paper is the higher-novelty PhD anchor of the spine shared with MyPassword.

## New-Session Operating Prompt

Use this at the start of future sessions:

```text
You are helping build OmniAuth, a post-quantum identity and authentication platform.

Before coding:
1. Read RULES.md and the Cursor rules in .cursor/rules/.
2. Read plan.md for the current project phase.
3. Check the sibling project at ../MyPassword for shared crypto patterns and the cross-project coordination rule.
4. If making dependency, PQC parameter, ZK scheme, mobile permission, backend wire, or recovery decisions, check current official docs (NIST FIPS, IETF, CFRG, arkworks-rs, CIRCL, pqcrypto-*), crate status, and security advisories before coding.
5. State the phase guarantee, non-guarantees, exact crate/version choices (Rust + Go + mobile), tests to write first, and silent security failure risks.
6. Production crypto in oss/crypto-core uses audited or NIST-aligned crates only.
```

## Research System

- Keep source-backed notes in `docs/research/research-log.md`.
- Keep the evolving paper draft in `docs/research/paper.md`.
- For each major decision, record:
  - Date checked.
  - Primary sources.
  - Decision.
  - Alternatives rejected.
  - Security/product risk if wrong.
- Prefer FIPS, RFCs, CFRG drafts, upstream library docs, audit reports, and peer-reviewed papers over blog summaries.
- Use web research before adding new packages or relying on rapidly changing APIs.

## Immediate Build Roadmap

1. Phase 0 hardening (cleanup the existing prototype):
   - Document the current vault format, AAD, KDF parameters, and ZK circuits in `docs/specs/` (create the folder when first spec is added).
   - Lock the threat model in `oss/crypto-core/src/lib.rs` and mirror it in the paper.
   - Add benchmark stubs per `docs/benchmarks.md`.
2. Phase 1 fragmentation: threshold PQC (t-of-n ML-DSA signing) for social recovery; formal model.
3. Phase 2 liveness: behavioral biometrics SDK with documented privacy story; never store templates.
4. Phase 3 decentralization: social recovery + MPC key escrow; recoverability under adversarial guardian models.
5. Phase 4 universal client: browser extension + OS daemon; intercept-and-prove flow.
6. Phase 5 proof / paper: full evaluation, formal model, paper submission.

Cross-cutting in every phase: close interop gaps, run formal models when protocols change, update paper section per `paper-milestones.mdc`, refresh `decisions-rejected.md` for any rejected option.

## Coordination With MyPassword

- MyPassword Phase 3 (desktop) ships before deep OmniAuth Phase 1+ work.
- Reuse vault format, AAD schema, and recovery framing across projects unless a divergence is recorded in `docs/research/decisions-rejected.md`.
- OmniAuth's paper covers PQC + ZK + threshold + formal model; MyPassword's paper covers hybrid relay + recovery + offboarding for SMB.
- Cite the sibling work explicitly in related work; avoid claim overlap.
