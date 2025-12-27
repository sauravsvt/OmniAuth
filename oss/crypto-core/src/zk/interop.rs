//! ZK Interop Tests
//!
//! Generates test vectors for cross-language verification (Rust → Go)
//! 
//! Run with: `cargo test generate_zk_interop_vectors -- --ignored --nocapture`

use std::io::Write;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::prover::ZKProver;
    use serde::{Serialize, Deserialize};
    use base64::{Engine as _, engine::general_purpose};

    #[derive(Serialize, Deserialize)]
    struct AgeProofVector {
        test_case: String,
        current_date: u64,
        age_threshold: u64,
        birth_date: u64,
        expected_valid: bool,
        proof_base64: String,
        public_inputs_base64: String,
        verifying_key_base64: String,
    }

    #[derive(Serialize, Deserialize)]
    struct ZKInteropVectors {
        version: u32,
        generated_at: String,
        age_proofs: Vec<AgeProofVector>,
    }

    /// Generates ZK interop test vectors for Go backend verification.
    /// 
    /// The output file contains:
    /// - Base64-encoded Groth16 proofs
    /// - Base64-encoded public inputs (serialized field elements)
    /// - Base64-encoded verifying key
    ///
    /// Go backend should be able to:
    /// 1. Deserialize the verifying key
    /// 2. Deserialize the proof and public inputs
    /// 3. Verify the proof returns the expected result
    #[test]
    #[ignore] // Run manually to generate vectors
    fn generate_zk_interop_vectors() {
        let prover = ZKProver::new().expect("Prover init failed");
        
        // Export verifying key
        let vk_bytes = prover.export_age_vk().expect("VK export failed");
        let vk_b64 = general_purpose::STANDARD.encode(&vk_bytes);

        let mut age_proofs = Vec::new();

        // Test case 1: Valid adult (born 2000, current 2025, threshold 18)
        {
            let proof = prover.prove_age(2025, 18, 2000).expect("Proof gen failed");
            age_proofs.push(AgeProofVector {
                test_case: "valid_adult".to_string(),
                current_date: 2025,
                age_threshold: 18,
                birth_date: 2000, // Private - not revealed to verifier
                expected_valid: true,
                proof_base64: proof.to_base64(),
                public_inputs_base64: proof.public_inputs_base64(),
                verifying_key_base64: vk_b64.clone(),
            });
        }

        // Test case 2: Exactly at threshold (born 2007, current 2025, threshold 18)
        {
            let proof = prover.prove_age(2025, 18, 2007).expect("Proof gen failed");
            age_proofs.push(AgeProofVector {
                test_case: "exactly_at_threshold".to_string(),
                current_date: 2025,
                age_threshold: 18,
                birth_date: 2007,
                expected_valid: true,
                proof_base64: proof.to_base64(),
                public_inputs_base64: proof.public_inputs_base64(),
                verifying_key_base64: vk_b64.clone(),
            });
        }

        // Test case 3: Well over threshold (born 1990, current 2025, threshold 21)
        {
            let proof = prover.prove_age(2025, 21, 1990).expect("Proof gen failed");
            age_proofs.push(AgeProofVector {
                test_case: "well_over_threshold".to_string(),
                current_date: 2025,
                age_threshold: 21,
                birth_date: 1990,
                expected_valid: true,
                proof_base64: proof.to_base64(),
                public_inputs_base64: proof.public_inputs_base64(),
                verifying_key_base64: vk_b64.clone(),
            });
        }

        let vectors = ZKInteropVectors {
            version: 1,
            generated_at: "2025-12-27T00:00:00Z".to_string(),
            age_proofs,
        };

        let json = serde_json::to_string_pretty(&vectors).expect("JSON serialization failed");
        
        let path = "../../proprietary/backend/zk_interop_vectors.json";
        let mut file = std::fs::File::create(path).expect("Failed to create file");
        file.write_all(json.as_bytes()).expect("Failed to write file");
        
        println!("✅ ZK interop vectors written to: {}", path);
        println!("   Age proof test cases: {}", vectors.age_proofs.len());
    }
}
