//! ZK Verifier Module
//!
//! Verifies Groth16 proofs for identity claims.
//! This module provides standalone verification that can be used without a prover.

use ark_bn254::{Bn254, Fr};
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;

use crate::AuthError;
use super::prover::ZKProof;

/// ZK Verifier for validating Groth16 proofs
pub struct ZKVerifier {
    /// Prepared verifying key for age proofs
    age_pvk: Option<PreparedVerifyingKey<Bn254>>,
    /// Prepared verifying key for range proofs
    range_pvk: Option<PreparedVerifyingKey<Bn254>>,
}

/// Proof types supported by OmniAuth
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofType {
    Age,
    Range,
    Ownership,
    Membership,
}

impl ZKVerifier {
    /// Creates a new ZKVerifier from serialized verifying keys.
    /// 
    /// # Arguments
    /// * `age_vk_bytes` - Optional compressed verifying key bytes for age proofs
    /// * `range_vk_bytes` - Optional compressed verifying key bytes for range proofs
    pub fn new(
        age_vk_bytes: Option<&[u8]>,
        range_vk_bytes: Option<&[u8]>,
    ) -> Result<Self, AuthError> {
        let age_pvk = if let Some(bytes) = age_vk_bytes {
            let vk = VerifyingKey::<Bn254>::deserialize_compressed(bytes)
                .map_err(|_| AuthError::CryptoFailure)?;
            Some(prepare_verifying_key(&vk))
        } else {
            None
        };

        let range_pvk = if let Some(bytes) = range_vk_bytes {
            let vk = VerifyingKey::<Bn254>::deserialize_compressed(bytes)
                .map_err(|_| AuthError::CryptoFailure)?;
            Some(prepare_verifying_key(&vk))
        } else {
            None
        };

        Ok(Self { age_pvk, range_pvk })
    }

    /// Verify a proof given its type.
    /// 
    /// # Arguments
    /// * `proof_type` - The type of claim being proven
    /// * `proof_bytes` - Compressed Groth16 proof
    /// * `public_inputs_bytes` - Serialized public inputs
    pub fn verify(
        &self,
        proof_type: ProofType,
        proof_bytes: &[u8],
        public_inputs_bytes: &[u8],
    ) -> Result<bool, AuthError> {
        let pvk = match proof_type {
            ProofType::Age => self.age_pvk.as_ref().ok_or(AuthError::CryptoFailure)?,
            ProofType::Range => self.range_pvk.as_ref().ok_or(AuthError::CryptoFailure)?,
            _ => return Err(AuthError::CryptoFailure), // Not implemented yet
        };

        let proof = Proof::<Bn254>::deserialize_compressed(proof_bytes)
            .map_err(|_| AuthError::CorruptedVault)?;

        let public_inputs: Vec<Fr> = Vec::deserialize_compressed(public_inputs_bytes)
            .map_err(|_| AuthError::CorruptedVault)?;

        Groth16::<Bn254>::verify_with_processed_vk(pvk, &public_inputs, &proof)
            .map_err(|_| AuthError::CryptoFailure)
    }

    /// Verify an age proof.
    /// 
    /// # Arguments
    /// * `zk_proof` - The proof and public inputs
    /// 
    /// # Returns
    /// `true` if the proof is valid (the prover is >= threshold age)
    pub fn verify_age(&self, zk_proof: &ZKProof) -> Result<bool, AuthError> {
        self.verify(ProofType::Age, &zk_proof.proof_bytes, &zk_proof.public_inputs)
    }

    /// Verify a range proof.
    pub fn verify_range(&self, zk_proof: &ZKProof) -> Result<bool, AuthError> {
        self.verify(ProofType::Range, &zk_proof.proof_bytes, &zk_proof.public_inputs)
    }
}

/// Standalone function for easy FFI export: verify any proof type
/// 
/// # Arguments
/// * `proof_type_str` - "age", "range", "ownership", or "membership"
/// * `proof_b64` - Base64-encoded proof bytes
/// * `public_inputs_b64` - Base64-encoded public inputs
/// * `vk_b64` - Base64-encoded verifying key
pub fn verify_zk_proof(
    proof_type_str: &str,
    proof_b64: &str,
    public_inputs_b64: &str,
    vk_b64: &str,
) -> Result<bool, AuthError> {
    use base64::{Engine as _, engine::general_purpose};

    let proof_type = match proof_type_str.to_lowercase().as_str() {
        "age" => ProofType::Age,
        "range" => ProofType::Range,
        "ownership" => ProofType::Ownership,
        "membership" => ProofType::Membership,
        _ => return Err(AuthError::CryptoFailure),
    };

    let proof_bytes = general_purpose::STANDARD.decode(proof_b64)
        .map_err(|_| AuthError::CorruptedVault)?;
    let public_inputs_bytes = general_purpose::STANDARD.decode(public_inputs_b64)
        .map_err(|_| AuthError::CorruptedVault)?;
    let vk_bytes = general_purpose::STANDARD.decode(vk_b64)
        .map_err(|_| AuthError::CorruptedVault)?;

    // Build verifier with the appropriate key
    let verifier = match proof_type {
        ProofType::Age => ZKVerifier::new(Some(&vk_bytes), None)?,
        ProofType::Range => ZKVerifier::new(None, Some(&vk_bytes))?,
        _ => return Err(AuthError::CryptoFailure),
    };

    verifier.verify(proof_type, &proof_bytes, &public_inputs_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::prover::ZKProver;

    #[test]
    fn test_verifier_with_exported_key() {
        // Create prover and generate proof
        let prover = ZKProver::new().unwrap();
        let proof = prover.prove_age(20251227, 180000, 20000101).unwrap();
        
        // Export verifying key
        let vk_bytes = prover.export_age_vk().unwrap();
        
        // Create standalone verifier
        let verifier = ZKVerifier::new(Some(&vk_bytes), None).unwrap();
        
        // Verify
        let valid = verifier.verify_age(&proof).unwrap();
        assert!(valid, "Age proof should verify with exported key");
    }
}
