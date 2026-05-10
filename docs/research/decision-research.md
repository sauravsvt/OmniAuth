# Decision Research Protocol

Use this before important technical, product, crypto, dependency, deployment, or paper-claim decisions.

## When Required

Run decision research before:

- Adding or replacing dependencies (Rust crate, Go module, npm package, native bridge).
- Choosing PQC parameters, KEM / signature constructions, or hybrid combinators.
- Choosing or changing a ZK proving scheme, curve, or trusted-setup approach.
- Designing storage formats, sync behavior, recovery, sharing, or revocation.
- Making mobile permission, biometric, or platform-storage decisions.
- Making backend deployment, CI, telemetry, logging, or secret-handling choices.
- Claiming novelty, market position, or research contribution in the paper.

## Source Priority

Prefer sources in this order:

1. Standards: NIST FIPS, RFCs, IETF drafts, CFRG drafts, W3C, platform security docs.
2. Upstream docs: arkworks-rs, CIRCL, pqcrypto-* crate docs, official framework docs, changelogs, migration guides.
3. Security sources: RustSec, govulncheck, npm audit, CVEs, GitHub advisories, audit reports, maintainer issue trackers.
4. Peer-reviewed or reputable research papers.
5. Mature production examples from respected open-source projects.
6. Blog posts only as supporting context, not the main authority.

## Search Pattern

For each decision:

1. Search the current official source.
2. Search for security advisories and deprecation/maintenance status.
3. Search for best-practice comparisons or production usage.
4. Compare at least two viable options when alternatives exist.
5. Record the decision in `docs/research/research-log.md` if it affects architecture, security, dependencies, or paper claims.
6. Produce a `docs/research/decisions-rejected.md` entry when an option was seriously evaluated but not chosen.

## Decision Template

```markdown
## YYYY-MM-DD Decision Name

### Question

What decision are we making?

### Sources Checked

- Source name, version/date: URL

### Options Compared

- Option A: strengths, weaknesses, security/product risks.
- Option B: strengths, weaknesses, security/product risks.

### Decision

Chosen option and why it is best for the current phase.

### Alternatives Rejected

Why each rejected option is not selected now. Mirror in `decisions-rejected.md`.

### Risk If Wrong

What breaks if this decision is wrong, and how we can migrate later.

### Sibling Impact

Does this affect MyPassword's design? If yes, link to the sibling decision or note the divergence.
```

## Stop Conditions

Stop and ask the user before coding if:

- Research contradicts the existing plan.
- The safest choice changes architecture or phase order.
- All options are immature, unmaintained, or risky.
- A decision has product / legal / security implications beyond the current milestone.
- A NIST update (e.g., new FIPS, HQC guidance) materially changes the right primitive choice.
