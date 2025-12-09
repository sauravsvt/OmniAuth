# OmniAuth Monorepo

## Overview
OmniAuth is a security-first authentication platform designed with a "Quantum-Proof" architecture. It separates open-source core components from proprietary business logic.

## Structure
- **oss/**: Audit-ready open source core ("Trust" Layer).
  - `client-mobile/`: React Native (Expo) app.
  - `crypto-core/`: Rust crate with PQC algorithms (Kyber/Dilithium).
- **proprietary/**: Business logic ("SaaS" Layer).
  - `api-gateway/`: Go API.
  - `rotation-engine/`: Go background worker.
  - `admin-dashboard/`: React Admin.
- **shared/**: Shared schemas and config.
- **infra/**: Infrastructure as Code.

## Tech Stack
- **Languages**: Rust, TypeScript, Go.
- **Crypto**: CRYSTALS-Kyber, CRYSTALS-Dilithium, XChaCha20-Poly1305.
- **Mobile**: Expo SDK 50+, UniFFI for Rust bindings.
- **Backend**: Connect-Go (gRPC), PostgreSQL (pgx).
