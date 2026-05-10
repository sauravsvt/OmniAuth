# Engineering Principles

These principles keep `let's start` productive instead of endless.

## Stop Point Rule

One run should normally complete one milestone from `docs/progress.md`.

After that milestone:

- Run the relevant checks (Rust, Go, mobile, as touched).
- Update `docs/progress.md`.
- Update research or paper notes if affected.
- Report status and stop.

Continue automatically only for tiny cleanup required to make the same milestone correct, such as formatting, clippy fixes, or updating a doc that explains the just-made change.

## Clean Code Rules

- Make illegal states hard to represent.
- Use explicit types for keys, IDs, versions, epochs, algorithm-suite tags, share indices, and serialized protocol fields.
- Keep crypto APIs narrow: callers should not choose nonces, algorithms, or unsafe serialization details casually.
- Prefer clear data flow over clever control flow.
- Keep functions small enough to review, but do not split code into fake abstractions.
- Document invariants and security assumptions, not obvious assignments.
- Tests should cover invariants, failure cases, serialization compatibility, and cross-language interop, not just happy paths.

## Scalability Rules

- Design protocol objects with versioning from the start.
- Keep storage, crypto, sync, and UI boundaries separate.
- Do not add distributed systems machinery until single-device flows are correct.
- Prefer append-only logs for membership/audit semantics.
- Treat metadata as a privacy budget: every visible field on the backend must have a reason.

## Product Experience Rules

- Reliability beats architectural purity for users who depend on identity flows.
- Recovery must feel deliberate, not like a casual password reset.
- Key rotation UX must honestly explain what changes for the user and what does not.
- Mobile UX must be conservative: minimal permissions, explicit ZK claim disclosure per request, safe clipboard handling.
- Error messages must not leak secrets, signature bytes, witness data, or recovery material.

## Anti-Overengineering Rules

- Do not build Phase 4 while in Phase 0.
- Do not introduce a framework for one caller.
- Do not add a dependency unless it improves security, correctness, portability, or clear maintainability.
- Do not make generic abstractions around cryptography unless the protocol spec requires crypto agility.
- Do not optimize performance before correctness, NIST KAT vectors, ZK soundness, and security boundaries are clear.
