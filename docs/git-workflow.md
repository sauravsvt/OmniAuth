# Git Workflow

This is the human-readable companion to `.cursor/rules/git-workflow.mdc`.

## Default Behavior

Git automation is off by default. The agent must not commit, merge, push, rebase, reset, or delete branches unless the user has opted in for the current run.

Opt-in phrases include: `let's do`, `commit this`, `auto-git this milestone`, `create a branch`, `merge if checks pass`.

## Branching

- One milestone per branch when the work is non-trivial.
- Naming: `phase-N-short-task` or `chore/short-task` (e.g., `phase-0-vault-spec`, `chore/interop-vectors`).

## Commits

- Inspect `git status`, staged and unstaged diff, and recent log before committing.
- Exclude secrets, `.env`, mobile keystores, signing keys, generated proving / verifying keys without provenance, local databases, and unrelated user changes.
- Run all relevant checks (Rust, Go, mobile) before commit unless the user explicitly asks for a WIP commit.
- Commit message format: imperative mood, subject summarizes the change, body explains the why and any sibling-coordination implication.

## Merging

- Merge only after checks pass and the user has opted into merge automation.
- `let's do` opts in for local milestone branch merges.
- Never force-push or rewrite shared history unless explicitly requested.

## Pushing And Deployment

- Push only when a remote is configured and the user has explicitly included push/deploy intent, or when project docs clearly authorize it.
- Deployment requires the deployment gate from `docs/quality-gates.md`.

## Cleanup

- Remove generated scratch files after a milestone.
- Delete local branches only after they are merged.
- Leave ignored build artifacts alone.
- Update `docs/progress.md`.
- Report any branches or files left behind.

## Dual License Boundary

- `oss/` is AGPL.
- `proprietary/` is proprietary.
- Documentation and public research are CC BY 4.0 unless a file says otherwise.
- Project names, logos, domains, and product branding are reserved.
- Do not move files across this boundary. Do not relicense files. Stop and ask if a refactor would cross.
