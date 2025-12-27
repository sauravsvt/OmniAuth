//! Zero-Knowledge Proof module for OmniAuth 2.0
//! 
//! This module provides ZK-SNARK capabilities using arkworks-rs with Groth16 proofs
//! on the BN254 curve. Key features:
//! - Age proofs (prove age >= threshold without revealing birth date)
//! - Ownership proofs (prove knowledge of preimage)
//! - Range proofs (prove value in [min, max])
//! - Membership proofs (prove inclusion in Merkle tree)

pub mod circuits;
pub mod prover;
pub mod verifier;

#[cfg(test)]
mod interop;

// Re-export commonly used types
pub use circuits::AgeProofCircuit;
pub use prover::{ZKProver, ZKProof};
pub use verifier::ZKVerifier;
