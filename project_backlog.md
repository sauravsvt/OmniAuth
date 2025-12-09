# OmniAuth Core Backlog
Logged by Lead Architect on Final Handover.

## P0: Critical Security & Infrastructure
- [ ] **Integrate `zeroize` crate**:
    - **Goal**: Ensure `Identity` and private keys are wiped from memory on drop.
    - **Target**: `oss/crypto-core/src/lib.rs`
- [ ] **Implement Argon2id**:
    - **Goal**: Derive Key Encryption Key (KEK) from Master Password instead of using it directly.
    - **Target**: `oss/crypto-core/src/lib.rs` (Vault::new)

## P1: Testing & Assurance
- [ ] **End-to-End (E2E) Handshake Tests**:
    - **Goal**: Verify full flow: Mobile -> PQC Sign -> Backend Verify -> Auth Success.
    - **Target**: New Integration Test Suite (e.g., in `tests/` or `Proprietary/backend/test`)

## P2: Future Features
- [ ] **Key Rotation**:
    - **Goal**: Implement logic for replacing old Dilithium keys.
- [ ] **Biometric Unlock**:
    - **Goal**: Store Master Password in iOS Keychain / Android KeyStore, unlock with FaceID.
