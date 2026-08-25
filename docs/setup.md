# Setup

Local development environment for OmniAuth across Rust, Go, and mobile.

## Prerequisites

- Rust stable (`rustup update`). Latest stable unless a crate requires otherwise.
- Go 1.22 or newer.
- Node.js 18 LTS or newer with npm.
- For mobile runtime: Expo CLI, Android Studio with at least one emulator, and/or Xcode on macOS for iOS.
- For ZK / formal work later: Tamarin Prover, ProVerif, arkworks-rs already pulled via Cargo.

## Repository Layout

- `oss/crypto-core/` — Rust crate: PQC vault, ZK circuits, UniFFI bindings.
- `oss/client-mobile/` — React Native (Expo) reference client with native bridges.
- `proprietary/backend/` — Go services: API gateway (`cmd/server`), worker (`cmd/worker`), Postgres schema (`db/schema.sql`).
- `docs/` — Operating docs, specs, research, benchmarks, audits, compliance.
- `.cursor/rules/` — Cursor agent rules.

## First-Time Build

```bash
# Rust core
cd oss/crypto-core
cargo build --release
cargo test

# Go backend
cd ../../proprietary/backend
go mod tidy
go test ./...

# Mobile client
cd ../../oss/client-mobile
npm install
npm test
```

## Backend Connectivity

The mobile registration screen targets `http://10.0.2.2:8080` on Android emulators and `http://localhost:8080` on iOS. Move these to environment variables or a typed config before any release build (see `.cursor/rules/mobile-workflow.mdc`).

## Secrets

- Never commit `.env`, mobile keystores, signing keys, Postgres passwords, S3 credentials, or generated proving keys without provenance.
- Use OS secret stores or environment variables for backend credentials.
- See `docs/audits.md` and `docs/compliance.md` for handling rules.

## Common Commands

```bash
# Rust gates
cd oss/crypto-core
cargo fmt --all
cargo clippy --all-targets -D warnings
cargo test

# Go gates
cd proprietary/backend
go vet ./...
go test ./...

# Mobile gates
cd oss/client-mobile
npm test -- --runInBand
npm run typecheck -- --noEmit
npm audit
env EXPO_NO_TELEMETRY=1 npx --yes expo-doctor
```
