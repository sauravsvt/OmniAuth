# Quality Gates

Use these gates before marking a milestone complete.

## Product Experience Gate

- The user-facing flow has a clear happy path, empty state, loading state, error state, and recovery path.
- Security-sensitive actions require deliberate confirmation: vault wipe, key rotation, new guardian, ZK claim disclosure, recovery initiation.
- Copy explains guarantees honestly and does not imply impossible protection. PQC reduces risk; it does not eliminate it.
- Failure states tell the user what happened and what to do next without leaking secrets.
- Default behavior is safe: locked, private, least-permission, no surprise network or analytics behavior.

## Testing Gate

- Unit tests cover core logic and important failure cases.
- Security-sensitive code has negative tests: wrong key, wrong AAD, tampered ciphertext, stale version, replay, revoked identity when applicable, ZK soundness rejection.
- ZK circuits use known-answer vectors where available and bit-decomposition rejection tests at the boundaries.
- PQC code uses NIST KAT vectors for ML-KEM and ML-DSA when available.
- Production crypto uses audited or NIST-aligned crates / libraries and tests object formats, AAD binding, and serialization compatibility.
- Cross-language interop has both producer and consumer tests passing against a checked-in vector.

## Build Gate

For Rust work in `oss/crypto-core`:

```bash
cargo fmt --all
cargo test
cargo clippy --all-targets -D warnings
```

For Go work in `proprietary/backend`:

```bash
gofmt -l . | tee /tmp/gofmt.out && [ ! -s /tmp/gofmt.out ]
go vet ./...
go test ./...
```

For mobile work in `oss/client-mobile`:

```bash
npm install
npm test
```

Use the package manager and scripts actually present in the project. Do not invent commands if scripts are missing.

## Deployment Gate

Do not deploy or package a component until:

- Configuration is validated at startup.
- Logs and telemetry are reviewed for plaintext/key leakage on every component (Rust core, Go backend, mobile client).
- Secrets are passed through environment or OS secret stores, not committed files.
- Health checks exist for services.
- Release artifacts are reproducible and, eventually, signed.
- Rollback instructions exist.
- The deployment target and threat model are documented.

## Stop Rule

If a gate fails, fix it if the fix belongs to the same milestone. If the fix expands scope, stop and report the blocker.
