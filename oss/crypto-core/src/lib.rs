use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce, Key as ChaChaKey
};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::sign::{SecretKey as _, PublicKey as _};
use pqcrypto_traits::kem::{SecretKey as _, PublicKey as _};
use base64::{Engine as _, engine::general_purpose};
use std::sync::{Arc, Mutex};
use zeroize::{Zeroize, ZeroizeOnDrop};
use argon2::{
    password_hash::{
        rand_core::RngCore,
        PasswordHasher, SaltString
    },
    Argon2
};
use serde::{Serialize, Deserialize};

uniffi::include_scaffolding!("omni_auth");

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Invalid password provided")]
    InvalidPassword,
    #[error("Vault data is corrupted")]
    CorruptedVault,
    #[error("Cryptographic operation failed")]
    CryptoFailure,
}

// -----------------------------------------------------------------------------
// Data Structures
// -----------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct VaultBlob {
    salt: String,   // Base64 encoded salt for Argon2
    nonce: String,  // Base64 encoded nonce for XChaCha20
    ciphertext: String, // Base64 encoded ciphertext
}

// Helper struct to serialize raw key bytes since pqcrypto types don't impl Serde
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct SerializableIdentity {
    #[zeroize(skip)]
    sign_pk: Vec<u8>,
    sign_sk: Vec<u8>,
    #[zeroize(skip)]
    kem_pk: Vec<u8>,
    kem_sk: Vec<u8>,
}

// Core Identity (In-Memory)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Identity {
    #[zeroize(skip)]
    sign_pk: dilithium3::PublicKey,
    sign_sk: dilithium3::SecretKey,
    #[zeroize(skip)]
    _kem_pk: kyber768::PublicKey,
    _kem_sk: kyber768::SecretKey,
}

impl Identity {
    fn new() -> Self {
        let (pk, sk) = dilithium3::keypair();
        let (k_pk, k_sk) = kyber768::keypair();
        Identity {
            sign_sk: sk,
            sign_pk: pk,
            _kem_sk: k_sk,
            _kem_pk: k_pk,
        }
    }

    pub fn get_public_signing_key(&self) -> String {
        general_purpose::STANDARD.encode(self.sign_pk.as_bytes())
    }

    pub fn sign_payload(&self, message: String) -> String {
        let sig = dilithium3::detached_sign(message.as_bytes(), &self.sign_sk);
        general_purpose::STANDARD.encode(sig.as_bytes())
    }
    
    // Internal helpers for serialization
    fn to_serializable(&self) -> SerializableIdentity {
        SerializableIdentity {
            sign_pk: self.sign_pk.as_bytes().to_vec(),
            sign_sk: self.sign_sk.as_bytes().to_vec(),
            kem_pk: self._kem_pk.as_bytes().to_vec(),
            kem_sk: self._kem_sk.as_bytes().to_vec(),
        }
    }

    fn from_serializable(s: SerializableIdentity) -> Result<Self, AuthError> {
        let sign_pk = dilithium3::PublicKey::from_bytes(&s.sign_pk).map_err(|_| AuthError::CorruptedVault)?;
        let sign_sk = dilithium3::SecretKey::from_bytes(&s.sign_sk).map_err(|_| AuthError::CorruptedVault)?;
        let kem_pk = kyber768::PublicKey::from_bytes(&s.kem_pk).map_err(|_| AuthError::CorruptedVault)?;
        let kem_sk = kyber768::SecretKey::from_bytes(&s.kem_sk).map_err(|_| AuthError::CorruptedVault)?;

        Ok(Identity {
            sign_pk, sign_sk, _kem_pk: kem_pk, _kem_sk: kem_sk
        })
    }
    
    fn clone_arc(&self) -> Arc<Identity> {
        // Warning: This physically clones keys in RAM. 
        // UniFFI needs Arc<Identity>, but we want to minimize copies.
        // We accept this for the UI thread safety.
        let s = self.to_serializable();
        let i = Identity::from_serializable(s).unwrap(); // Should never fail from valid self
        Arc::new(i)
    }
}

pub struct Vault {
    inner_identity: Arc<Mutex<Identity>>,
    encrypted_blob: String, // Keep the blob so we can export it if needed
}

impl Vault {
    pub fn new(master_password: String) -> Result<Self, AuthError> {
        let identity = Identity::new();
        
        // 1. Generate Salt
        let salt = SaltString::generate(&mut OsRng);
        
        // 2. Derive KEK (Argon2id)
        let argon2 = Argon2::default();
        let mut kek = [0u8; 32];
        argon2.hash_password(master_password.as_bytes(), &salt)
            .map_err(|_| AuthError::CryptoFailure)?
            .hash
            .ok_or(AuthError::CryptoFailure)?
            .fill_bytes(&mut kek); // Fill 32 bytes
            
        // 3. Encrypt Identity
        let serializable = identity.to_serializable();
        let json_bytes = serde_json::to_vec(&serializable).map_err(|_| AuthError::CryptoFailure)?;
        
        let cipher = XChaCha20Poly1305::new(&ChaChaKey::from_slice(&kek));
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng); // 24 bytes
        
        let ciphertext = cipher.encrypt(&nonce, json_bytes.as_ref())
            .map_err(|_| AuthError::CryptoFailure)?;
            
        // 4. Create Blob
        let blob = VaultBlob {
            salt: salt.as_str().to_string(),
            nonce: general_purpose::STANDARD.encode(nonce),
            ciphertext: general_purpose::STANDARD.encode(ciphertext),
        };
        
        let blob_string = serde_json::to_string(&blob).map_err(|_| AuthError::CryptoFailure)?;

        Ok(Vault {
            inner_identity: Arc::new(Mutex::new(identity)),
            encrypted_blob: blob_string,
        })
    }

    pub fn new_with_blob(master_password: String, encrypted_blob_str: String) -> Result<Self, AuthError> {
        if encrypted_blob_str.is_empty() {
             return Err(AuthError::CorruptedVault);
        }

        // 1. Parse Blob
        let blob: VaultBlob = serde_json::from_str(&encrypted_blob_str)
            .map_err(|_| AuthError::CorruptedVault)?;
            
        // 2. Re-derive KEK
        // Argon2 output depends on the stored salt
        let salt = SaltString::from_b64(&blob.salt).map_err(|_| AuthError::CorruptedVault)?;
        let argon2 = Argon2::default();
        
        // Note: verify_password helps check password vs hash, but here we need the Output Key.
        // We use hash_password with the *SAME* salt to regenerate the hash.
        let mut kek = [0u8; 32];
        // We manually construct the hash with the salt
        argon2.hash_password(master_password.as_bytes(), &salt)
             .map_err(|_| AuthError::InvalidPassword)? // Argon2 fail usually means params
             .hash
             .ok_or(AuthError::InvalidPassword)?
             .fill_bytes(&mut kek);

        // 3. Decrypt
        let cipher = XChaCha20Poly1305::new(&ChaChaKey::from_slice(&kek));
        let nonce_bytes = general_purpose::STANDARD.decode(&blob.nonce)
            .map_err(|_| AuthError::CorruptedVault)?;
        let nonce = XNonce::from_slice(&nonce_bytes);
        
        let ciphertext = general_purpose::STANDARD.decode(&blob.ciphertext)
            .map_err(|_| AuthError::CorruptedVault)?;
            
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| AuthError::InvalidPassword)?; // Poly1305 failure = wrong password

        // 4. Deserialize Identity
        let serializable: SerializableIdentity = serde_json::from_slice(&plaintext)
            .map_err(|_| AuthError::CorruptedVault)?;
            
        let identity = Identity::from_serializable(serializable)?;
        
        Ok(Vault {
            inner_identity: Arc::new(Mutex::new(identity)),
            encrypted_blob: encrypted_blob_str,
        })
    }

    pub fn unlock(&self) -> Result<Arc<Identity>, AuthError> {
        let guard = self.inner_identity.lock().map_err(|_| AuthError::CryptoFailure)?;
        Ok(guard.clone_arc())
    }
    
    pub fn export_encrypted_blob(&self) -> Result<String, AuthError> {
        Ok(self.encrypted_blob.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_lifecycle_hardened() {
        let password = "correct_horse_battery_staple".to_string();
        
        // 1. Create (Argon2 derivation + Encryption happens here)
        let vault = Vault::new(password.clone()).expect("Vault creation failed");
        let blob = vault.export_encrypted_blob().unwrap();
        
        assert!(!blob.is_empty());
        assert!(blob.contains("\"salt\":"));
        assert!(blob.contains("\"nonce\":"));
        assert!(blob.contains("\"ciphertext\":"));

        // 2. Unlock with CORRECT password
        let unlocked = vault.unlock();
        assert!(unlocked.is_ok());

        // 3. Restore from Blob (Cold Start)
        let recovered_vault = Vault::new_with_blob(password.clone(), blob.clone())
            .expect("Failed to recover vault");
            
        let recovered_id = recovered_vault.unlock().expect("Failed to unlock recovered");
        let sig = recovered_id.sign_payload("test".to_string());
        assert!(!sig.is_empty());
    }

    #[test]
    fn test_wrong_password() {
        let password = "password123".to_string();
        let vault = Vault::new(password.clone()).unwrap();
        let blob = vault.export_encrypted_blob().unwrap();
        
        // Try to open with WRONG password
        let result = Vault::new_with_blob("wrong_password".to_string(), blob);
        
        match result {
            Err(AuthError::InvalidPassword) => assert!(true), // Pass
            _ => panic!("Should have failed with InvalidPassword"),
        }
    }
}
