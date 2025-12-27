//! ZK Prover Module
//!
//! Generates Groth16 proofs for identity claims using arkworks-rs.
//! Proofs are serialized in compressed format for cross-language compatibility.

use ark_bn254::{Bn254, Fr};
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, ProvingKey};
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::thread_rng;

use crate::AuthError;
use super::circuits::{AgeProofCircuit, RangeProofCircuit};

/// Wrapper for a serialized Groth16 proof
#[derive(Clone)]
pub struct ZKProof {
    /// Compressed proof bytes
    pub proof_bytes: Vec<u8>,
    /// Public inputs as field elements serialized
    pub public_inputs: Vec<u8>,
}

impl ZKProof {
    /// Serialize proof to base64 for transport
    pub fn to_base64(&self) -> String {
        use base64::{Engine as _, engine::general_purpose};
        general_purpose::STANDARD.encode(&self.proof_bytes)
    }

    /// Serialize public inputs to base64
    pub fn public_inputs_base64(&self) -> String {
        use base64::{Engine as _, engine::general_purpose};
        general_purpose::STANDARD.encode(&self.public_inputs)
    }
}

/// ZK Prover for generating Groth16 proofs
pub struct ZKProver {
    /// Proving key for age proofs
    age_pk: Option<ProvingKey<Bn254>>,
    /// Prepared verifying key for age proofs (for local verification)
    age_pvk: Option<PreparedVerifyingKey<Bn254>>,
    /// Proving key for range proofs
    range_pk: Option<ProvingKey<Bn254>>,
    /// Prepared verifying key for range proofs
    range_pvk: Option<PreparedVerifyingKey<Bn254>>,
}

impl ZKProver {
    /// Creates a new ZKProver by generating proving/verifying keys.
    /// 
    /// # Note
    /// In production, keys should be loaded from pre-computed files
    /// generated using Perpetual Powers of Tau ceremony artifacts.
    /// This method performs circuit-specific setup (Phase 2).
    pub fn new() -> Result<Self, AuthError> {
        let mut rng = thread_rng();

        // Generate keys for AgeProofCircuit
        let age_circuit = AgeProofCircuit::<Fr>::default();
        let (age_pk, age_vk) = Groth16::<Bn254>::circuit_specific_setup(age_circuit, &mut rng)
            .map_err(|_| AuthError::CryptoFailure)?;
        let age_pvk = prepare_verifying_key(&age_vk);

        // Generate keys for RangeProofCircuit
        let range_circuit = RangeProofCircuit::<Fr>::default();
        let (range_pk, range_vk) = Groth16::<Bn254>::circuit_specific_setup(range_circuit, &mut rng)
            .map_err(|_| AuthError::CryptoFailure)?;
        let range_pvk = prepare_verifying_key(&range_vk);

        Ok(Self {
            age_pk: Some(age_pk),
            age_pvk: Some(age_pvk),
            range_pk: Some(range_pk),
            range_pvk: Some(range_pvk),
        })
    }

    /// Generates an age proof.
    ///
    /// # Arguments
    /// * `current_date` - Current date as YYYYMMDD u64
    /// * `age_threshold` - Minimum age threshold in same format
    /// * `birth_date` - User's private birth date
    ///
    /// # Returns
    /// A ZKProof that can be verified without knowing birth_date
    pub fn prove_age(
        &self,
        current_date: u64,
        age_threshold: u64,
        birth_date: u64,
    ) -> Result<ZKProof, AuthError> {
        let pk = self.age_pk.as_ref().ok_or(AuthError::CryptoFailure)?;
        let mut rng = thread_rng();

        let circuit = AgeProofCircuit::new(current_date, age_threshold, birth_date);

        let proof = Groth16::<Bn254>::prove(pk, circuit, &mut rng)
            .map_err(|_| AuthError::CryptoFailure)?;

        // Serialize proof (compressed format for smaller size)
        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes)
            .map_err(|_| AuthError::CryptoFailure)?;

        // Serialize public inputs: [current_date, age_threshold]
        let public_inputs: Vec<Fr> = vec![
            Fr::from(current_date),
            Fr::from(age_threshold),
        ];
        let mut public_inputs_bytes = Vec::new();
        public_inputs.serialize_compressed(&mut public_inputs_bytes)
            .map_err(|_| AuthError::CryptoFailure)?;

        Ok(ZKProof {
            proof_bytes,
            public_inputs: public_inputs_bytes,
        })
    }

    /// Generates a range proof.
    ///
    /// # Arguments
    /// * `min` - Minimum allowed value (public)
    /// * `max` - Maximum allowed value (public)
    /// * `value` - Private value to prove is in range
    pub fn prove_range(
        &self,
        min: u64,
        max: u64,
        value: u64,
    ) -> Result<ZKProof, AuthError> {
        let pk = self.range_pk.as_ref().ok_or(AuthError::CryptoFailure)?;
        let mut rng = thread_rng();

        let circuit = RangeProofCircuit::new(min, max, value);

        let proof = Groth16::<Bn254>::prove(pk, circuit, &mut rng)
            .map_err(|_| AuthError::CryptoFailure)?;

        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes)
            .map_err(|_| AuthError::CryptoFailure)?;

        // Public inputs: [min, max]
        let public_inputs: Vec<Fr> = vec![Fr::from(min), Fr::from(max)];
        let mut public_inputs_bytes = Vec::new();
        public_inputs.serialize_compressed(&mut public_inputs_bytes)
            .map_err(|_| AuthError::CryptoFailure)?;

        Ok(ZKProof {
            proof_bytes,
            public_inputs: public_inputs_bytes,
        })
    }

    /// Verifies an age proof locally (for testing).
    pub fn verify_age_proof(&self, zk_proof: &ZKProof) -> Result<bool, AuthError> {
        let pvk = self.age_pvk.as_ref().ok_or(AuthError::CryptoFailure)?;

        let proof = Proof::<Bn254>::deserialize_compressed(&zk_proof.proof_bytes[..])
            .map_err(|_| AuthError::CryptoFailure)?;

        let public_inputs: Vec<Fr> = Vec::deserialize_compressed(&zk_proof.public_inputs[..])
            .map_err(|_| AuthError::CryptoFailure)?;

        Groth16::<Bn254>::verify_with_processed_vk(pvk, &public_inputs, &proof)
            .map_err(|_| AuthError::CryptoFailure)
    }

    /// Verifies a range proof locally (for testing).
    pub fn verify_range_proof(&self, zk_proof: &ZKProof) -> Result<bool, AuthError> {
        let pvk = self.range_pvk.as_ref().ok_or(AuthError::CryptoFailure)?;

        let proof = Proof::<Bn254>::deserialize_compressed(&zk_proof.proof_bytes[..])
            .map_err(|_| AuthError::CryptoFailure)?;

        let public_inputs: Vec<Fr> = Vec::deserialize_compressed(&zk_proof.public_inputs[..])
            .map_err(|_| AuthError::CryptoFailure)?;

        Groth16::<Bn254>::verify_with_processed_vk(pvk, &public_inputs, &proof)
            .map_err(|_| AuthError::CryptoFailure)
    }

    /// Export verifying key bytes for Go backend
    pub fn export_age_vk(&self) -> Result<Vec<u8>, AuthError> {
        let pvk = self.age_pvk.as_ref().ok_or(AuthError::CryptoFailure)?;
        let mut bytes = Vec::new();
        pvk.vk.serialize_compressed(&mut bytes)
            .map_err(|_| AuthError::CryptoFailure)?;
        Ok(bytes)
    }
}

impl Default for ZKProver {
    fn default() -> Self {
        Self::new().expect("Failed to initialize ZK prover")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_age_proof_generation_and_verification() {
        let prover = ZKProver::new().expect("Prover init failed");

        // Valid case: born 2000, checking in 2025, threshold 18
        // Using simple year values that match circuit tests
        let proof = prover.prove_age(2025, 18, 2000)
            .expect("Proof generation failed");

        assert!(!proof.proof_bytes.is_empty());
        
        let valid = prover.verify_age_proof(&proof)
            .expect("Verification failed");
        assert!(valid, "Valid age proof should verify");
    }

    #[test]
    fn test_age_proof_exactly_at_threshold() {
        let prover = ZKProver::new().expect("Prover init failed");

        // Edge case: born 2007, current 2025, threshold 18
        // 2007 + 18 = 2025, exactly at threshold (should pass)
        let proof = prover.prove_age(2025, 18, 2007)
            .expect("Proof generation failed");

        let valid = prover.verify_age_proof(&proof)
            .expect("Verification failed");
        assert!(valid, "Age exactly at threshold should verify");
    }

    #[test]
    fn test_range_proof_valid() {
        let prover = ZKProver::new().expect("Prover init failed");

        let proof = prover.prove_range(100, 200, 150)
            .expect("Range proof generation failed");

        let valid = prover.verify_range_proof(&proof)
            .expect("Verification failed");
        assert!(valid, "Value 150 in [100, 200] should verify");
    }

    #[test]
    fn test_range_proof_at_bounds() {
        let prover = ZKProver::new().expect("Prover init failed");

        // At lower bound
        let proof_min = prover.prove_range(100, 200, 100)
            .expect("Range proof at min failed");
        let valid_min = prover.verify_range_proof(&proof_min)
            .expect("Verification failed");
        assert!(valid_min, "Value at lower bound should verify");

        // At upper bound
        let proof_max = prover.prove_range(100, 200, 200)
            .expect("Range proof at max failed");
        let valid_max = prover.verify_range_proof(&proof_max)
            .expect("Verification failed");
        assert!(valid_max, "Value at upper bound should verify");
    }

    #[test]
    fn test_proof_serialization_roundtrip() {
        let prover = ZKProver::new().expect("Prover init failed");
        let proof = prover.prove_age(2025, 18, 2000).unwrap();

        // Check base64 roundtrip
        let b64 = proof.to_base64();
        assert!(!b64.is_empty());
        
        use base64::{Engine as _, engine::general_purpose};
        let decoded = general_purpose::STANDARD.decode(&b64).unwrap();
        assert_eq!(decoded, proof.proof_bytes);
    }

    #[test]
    fn test_vk_export() {
        let prover = ZKProver::new().expect("Prover init failed");
        let vk_bytes = prover.export_age_vk().expect("VK export failed");
        
        // VK should be non-empty
        assert!(!vk_bytes.is_empty());
        
        // Should be a reasonable size for compressed Groth16 VK
        assert!(vk_bytes.len() > 100, "VK seems too small");
    }
}

