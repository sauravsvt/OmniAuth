use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng}, 
    XChaCha20Poly1305, XNonce, Key as ChaChaKey
};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::sign::{SecretKey as _, PublicKey as _, DetachedSignature}; 
use pqcrypto_traits::kem::{SecretKey as _, PublicKey as _, Ciphertext as _, SharedSecret as _};
use base64::{Engine as _, engine::general_purpose};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use argon2::{
    password_hash::SaltString,
    Argon2
};
use serde::{Serialize, Deserialize};
use hkdf::Hkdf;
use sha2::Sha256;

// ZK Module - Zero-Knowledge Proofs for Identity Claims
pub mod zk;

uniffi::setup_scaffolding!("omniauth_core");

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum AuthError {
    #[error("Invalid password provided")]
    InvalidPassword,
    #[error("Vault data is corrupted")]
    CorruptedVault,
    #[error("Cryptographic operation failed")]
    CryptoFailure,
}

// -----------------------------------------------------------------------------
// Internal Helpers
// -----------------------------------------------------------------------------

fn derive_session_key(raw_secret: &[u8]) -> Result<[u8; 32], AuthError> {
    let hkdf = Hkdf::<Sha256>::new(None, raw_secret);
    let mut okm = [0u8; 32]; 
    hkdf.expand(b"OmniAuth-Session-v1", &mut okm)
        .map_err(|_| AuthError::CryptoFailure)?;
    Ok(okm)
}

#[derive(Serialize, Deserialize)]
struct VaultBlob {
    version: u32,
    salt: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct SerializableIdentity {
    sign_pk: Vec<u8>,
    sign_sk: Vec<u8>,
    kem_pk: Vec<u8>, 
    kem_sk: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct KEMResult {
    pub shared_secret: String, 
    pub ciphertext: String,    
}

// Internal Identity struct (not exposed via UniFFI)
struct Identity {
    sign_pk: dilithium3::PublicKey,
    sign_sk: Zeroizing<Vec<u8>>, 
    kem_pk: kyber768::PublicKey,
    kem_sk: Zeroizing<Vec<u8>>, 
}

impl Identity {
    fn new() -> Self {
        let (pk, sk) = dilithium3::keypair();
        let (k_pk, k_sk) = kyber768::keypair();
        Identity {
            sign_pk: pk,
            sign_sk: Zeroizing::new(sk.as_bytes().to_vec()),
            kem_pk: k_pk, 
            kem_sk: Zeroizing::new(k_sk.as_bytes().to_vec()),
        }
    }
    
    fn to_serializable(&self) -> SerializableIdentity {
        SerializableIdentity {
            sign_pk: self.sign_pk.as_bytes().to_vec(),
            sign_sk: self.sign_sk.to_vec(), 
            kem_pk: self.kem_pk.as_bytes().to_vec(),
            kem_sk: self.kem_sk.to_vec(),
        }
    }

    fn from_serializable(mut s: SerializableIdentity) -> Result<Self, AuthError> {
        // Use mem::take to move bytes out while satisfying ZeroizeOnDrop
        let sign_pk_bytes = std::mem::take(&mut s.sign_pk);
        let sign_sk_bytes = std::mem::take(&mut s.sign_sk);
        let kem_pk_bytes = std::mem::take(&mut s.kem_pk);
        let kem_sk_bytes = std::mem::take(&mut s.kem_sk);
        // s is now full of empty Vecs, and will be dropped (zeroize noop)

        let sign_pk_obj = dilithium3::PublicKey::from_bytes(&sign_pk_bytes)
            .map_err(|_| AuthError::CorruptedVault)?;
        let kem_pk_obj = kyber768::PublicKey::from_bytes(&kem_pk_bytes)
            .map_err(|_| AuthError::CorruptedVault)?;

        // Sanity-check secret key formats
        dilithium3::SecretKey::from_bytes(&sign_sk_bytes).map_err(|_| AuthError::CorruptedVault)?;
        kyber768::SecretKey::from_bytes(&kem_sk_bytes).map_err(|_| AuthError::CorruptedVault)?;

        Ok(Identity {
            sign_pk: sign_pk_obj, 
            sign_sk: Zeroizing::new(sign_sk_bytes), // Moved, not cloned
            kem_pk: kem_pk_obj, 
            kem_sk: Zeroizing::new(kem_sk_bytes),   // Moved, not cloned
        })
    }
    
    fn get_public_signing_key(&self) -> String {
        general_purpose::STANDARD.encode(self.sign_pk.as_bytes())
    }

    fn get_public_kem_key(&self) -> String {
        general_purpose::STANDARD.encode(self.kem_pk.as_bytes())
    }

    fn sign_payload(&self, message: &str) -> Result<String, AuthError> {
        let sk = dilithium3::SecretKey::from_bytes(&self.sign_sk)
            .map_err(|_| AuthError::CryptoFailure)?;
        let sig = dilithium3::detached_sign(message.as_bytes(), &sk);
        Ok(general_purpose::STANDARD.encode(sig.as_bytes()))
    }

    fn recover_shared_secret(&self, ciphertext_b64: &str) -> Result<String, AuthError> {
        let ct_bytes = general_purpose::STANDARD.decode(ciphertext_b64)
            .map_err(|_| AuthError::CryptoFailure)?;
        let ct = kyber768::Ciphertext::from_bytes(&ct_bytes)
            .map_err(|_| AuthError::CryptoFailure)?;
        let sk = kyber768::SecretKey::from_bytes(&self.kem_sk)
            .map_err(|_| AuthError::CryptoFailure)?;
        let raw_shared_secret = kyber768::decapsulate(&ct, &sk);
        let session_key = derive_session_key(raw_shared_secret.as_bytes())?;
        Ok(general_purpose::STANDARD.encode(session_key))
    }
}

// -----------------------------------------------------------------------------
// Public API: Vault
// -----------------------------------------------------------------------------

#[derive(uniffi::Object)]
pub struct Vault {
    encrypted_blob: String, 
}

// Internal impl block (not exported via UniFFI)
impl Vault {
    fn decrypt_identity(&self, password: &str) -> Result<Identity, AuthError> {
        let blob: VaultBlob = serde_json::from_str(&self.encrypted_blob)
            .map_err(|_| AuthError::CorruptedVault)?;

        // Version check: only v1 is currently supported
        if blob.version != 1 {
            return Err(AuthError::CorruptedVault);
        }

        let salt = SaltString::from_b64(&blob.salt).map_err(|_| AuthError::CorruptedVault)?;
        let argon2 = Argon2::default();

        // Use Zeroizing wrapper so KEK is wiped even on early ? returns
        let mut kek = Zeroizing::new([0u8; 32]);
        argon2.hash_password_into(password.as_bytes(), salt.as_str().as_bytes(), &mut kek[..])
            .map_err(|_| AuthError::CryptoFailure)?;

        let cipher = XChaCha20Poly1305::new(&ChaChaKey::from_slice(&kek[..]));

        let nonce_bytes = general_purpose::STANDARD.decode(&blob.nonce)
            .map_err(|_| AuthError::CorruptedVault)?;
        if nonce_bytes.len() != 24 {
            return Err(AuthError::CorruptedVault);
        }
        let nonce = XNonce::from_slice(&nonce_bytes);

        let ciphertext = general_purpose::STANDARD.decode(&blob.ciphertext)
            .map_err(|_| AuthError::CorruptedVault)?;

        // Static AAD — matches encrypt path exactly, avoids format! allocation
        let aad = b"OmniAuth-VaultBlob-v1";
        let payload = chacha20poly1305::aead::Payload { msg: &ciphertext, aad };

        // Wrap plaintext in Zeroizing so it's wiped even if JSON parse fails
        let plaintext = Zeroizing::new(
            cipher.decrypt(nonce, payload)
                .map_err(|_| AuthError::InvalidPassword)?
        );

        let serializable: SerializableIdentity =
            serde_json::from_slice(&plaintext).map_err(|_| AuthError::CorruptedVault)?;

        Identity::from_serializable(serializable)
    }
}

// UniFFI-exported impl block
#[uniffi::export]
impl Vault {
    #[uniffi::constructor]
    pub fn new(master_password: String) -> Result<Self, AuthError> {
        let identity = Identity::new();
        
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let mut kek = [0u8; 32];
        argon2.hash_password_into(master_password.as_bytes(), salt.as_str().as_bytes(), &mut kek)
            .map_err(|_| AuthError::CryptoFailure)?;
            
        let serializable = identity.to_serializable();
        let mut json_bytes = serde_json::to_vec(&serializable).map_err(|_| AuthError::CryptoFailure)?;
        
        let cipher = XChaCha20Poly1305::new(&ChaChaKey::from_slice(&kek));
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng); 
        
        // AAD binds version 1
        let aad = b"OmniAuth-VaultBlob-v1";
        let payload = chacha20poly1305::aead::Payload {
            msg: &json_bytes,
            aad,
        };

        let ciphertext = cipher.encrypt(&nonce, payload)
            .map_err(|_| AuthError::CryptoFailure)?;
        
        kek.zeroize();
        json_bytes.zeroize();
            
        let blob = VaultBlob {
            version: 1,
            salt: salt.as_str().to_string(),
            nonce: general_purpose::STANDARD.encode(nonce),
            ciphertext: general_purpose::STANDARD.encode(ciphertext),
        };
        
        let blob_string = serde_json::to_string(&blob).map_err(|_| AuthError::CryptoFailure)?;

        Ok(Vault {
            encrypted_blob: blob_string,
        })
    }

    #[uniffi::constructor]
    pub fn new_with_blob(encrypted_blob_str: String) -> Result<Self, AuthError> {
        if encrypted_blob_str.is_empty() {
             return Err(AuthError::CorruptedVault);
        }
        let _blob: VaultBlob = serde_json::from_str(&encrypted_blob_str)
            .map_err(|_| AuthError::CorruptedVault)?;
        
        Ok(Vault {
            encrypted_blob: encrypted_blob_str,
        })
    }

    /// Signs a message. Decrypts identity transiently, signs, zeroizes, returns signature.
    pub fn sign(&self, password: String, message: String) -> Result<String, AuthError> {
        let identity = self.decrypt_identity(&password)?;
        identity.sign_payload(&message)
    }
    
    /// Decapsulates a shared secret. Decrypts identity transiently.
    pub fn recover_shared_secret(&self, password: String, ciphertext: String) -> Result<String, AuthError> {
        let identity = self.decrypt_identity(&password)?;
        identity.recover_shared_secret(&ciphertext)
    }
    
    /// Gets the public signing key. Requires password to verify vault integrity.
    pub fn get_public_signing_key(&self, password: String) -> Result<String, AuthError> {
        let identity = self.decrypt_identity(&password)?;
        Ok(identity.get_public_signing_key())
    }
    
    /// Gets the public KEM key. Requires password to verify vault integrity.
    pub fn get_public_kem_key(&self, password: String) -> Result<String, AuthError> {
        let identity = self.decrypt_identity(&password)?;
        Ok(identity.get_public_kem_key())
    }
    
    pub fn export_encrypted_blob(&self) -> Result<String, AuthError> {
        Ok(self.encrypted_blob.clone())
    }
}

/// Encapsulates a shared secret for a target public KEM key.
#[uniffi::export]
pub fn generate_shared_secret(target_public_key: String) -> Result<KEMResult, AuthError> {
    let pk_bytes = general_purpose::STANDARD.decode(target_public_key)
        .map_err(|_| AuthError::CryptoFailure)?;
    let pk = kyber768::PublicKey::from_bytes(&pk_bytes)
        .map_err(|_| AuthError::CryptoFailure)?;
    let (raw_shared_secret, ciphertext) = kyber768::encapsulate(&pk);
    let session_key = derive_session_key(raw_shared_secret.as_bytes())?;
    Ok(KEMResult {
        shared_secret: general_purpose::STANDARD.encode(session_key),
        ciphertext: general_purpose::STANDARD.encode(ciphertext.as_bytes()),
    })
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_lifecycle_transient() {
        let password = "correct_horse_battery_staple".to_string();
        
        let vault = Vault::new(password.clone()).expect("Vault creation failed");
        let blob = vault.export_encrypted_blob().unwrap();
        assert!(!blob.is_empty());

        let sig = vault.sign(password.clone(), "test message".to_string()).unwrap();
        assert!(!sig.is_empty());

        let pk = vault.get_public_signing_key(password.clone()).unwrap();
        assert!(!pk.is_empty());

        let recovered_vault = Vault::new_with_blob(blob).expect("Failed to recover vault");
        let sig2 = recovered_vault.sign(password.clone(), "another message".to_string()).unwrap();
        assert!(!sig2.is_empty());
    }

    #[test]
    fn test_wrong_password() {
        let password = "password123".to_string();
        let vault = Vault::new(password.clone()).unwrap();
        let blob = vault.export_encrypted_blob().unwrap();
        
        let vault = Vault::new_with_blob(blob).unwrap();
        let result = vault.sign("wrong_password".to_string(), "msg".to_string());
        
        match result {
            Err(AuthError::InvalidPassword) => assert!(true), 
            _ => panic!("Should have failed with InvalidPassword"),
        }
    }
    
    #[test]
    fn test_corrupted_nonce_length() {
        let password = "pass".to_string();
        let vault = Vault::new(password.clone()).unwrap();
        let blob_str = vault.export_encrypted_blob().unwrap();
        
        let mut blob: VaultBlob = serde_json::from_str(&blob_str).unwrap();
        let mut nonce_bytes = general_purpose::STANDARD.decode(&blob.nonce).unwrap();
        nonce_bytes.pop(); 
        blob.nonce = general_purpose::STANDARD.encode(nonce_bytes);
        
        let corrupted_blob_str = serde_json::to_string(&blob).unwrap();
        
        let v = Vault::new_with_blob(corrupted_blob_str).unwrap();
        let result = v.sign(password, "msg".to_string());
        
        match result {
            Err(AuthError::CorruptedVault) => assert!(true),
            Err(e) => panic!("Expected CorruptedVault, got {:?}", e),
            Ok(_) => panic!("Should fail on invalid nonce length"),
        }
    }

    #[test]
    fn test_kem_flow_via_vault() {
        let password = "secret".to_string();
        let vault = Vault::new(password.clone()).unwrap();
        let bob_pub_key = vault.get_public_kem_key(password.clone()).unwrap();

        let kem_result = generate_shared_secret(bob_pub_key).expect("Encapsulation failed");

        let recovered_secret = vault.recover_shared_secret(password.clone(), kem_result.ciphertext)
            .expect("Decapsulation failed");

        assert_eq!(
            kem_result.shared_secret, 
            recovered_secret, 
            "Alice and Bob must share the exact same secret"
        );
    }
}

#[cfg(test)]
mod interop_tests {
    use super::*;
    use std::io::Write; 

    #[test]
    #[ignore]
    fn generate_interop_vectors() {
        let password = "interop_test_pw".to_string();
        let vault = Vault::new(password.clone()).unwrap();
        
        let msg = "Hello from Rust";
        let pk = vault.get_public_signing_key(password.clone()).unwrap();
        let sig = vault.sign(password.clone(), msg.to_string()).unwrap();
        
        let json = format!(r#"{{
            "msg": "{}",
            "pk": "{}",
            "sig": "{}"
        }}"#, msg, pk, sig);
        
        let mut file = std::fs::File::create("../../proprietary/backend/interop_vectors.json").unwrap();
        file.write_all(json.as_bytes()).unwrap();
        println!("Interop vectors written.");
    }
}
