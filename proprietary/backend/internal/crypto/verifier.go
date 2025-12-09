package crypto

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign/dilithium/mode3" // Must match Rust's "dilithium3"
)

// VerifyIdentity checks if a signature matches the message using the stored public key.
// pubKeyB64: The Base64 encoded public key stored in Postgres
// message: The nonce/challenge sent to the client
// signatureB64: The signature returned by the mobile app
func VerifyIdentity(pubKeyB64, message, signatureB64 string) error {
	// 1. Decode Public Key
	pkBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return fmt.Errorf("invalid public key format: %w", err)
	}

	// 2. Load into CIRCL object
	pk := mode3.PublicKey{}
	if len(pkBytes) != mode3.PublicKeySize {
		return errors.New("public key size mismatch")
	}
	copy(pk[:], pkBytes)

	// 3. Decode Signature
	sigBytes, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("invalid signature format: %w", err)
	}

	// 4. Verify
	if !mode3.Verify(&pk, []byte(message), sigBytes) {
		return errors.New("signature verification failed") // AUTHENTICATION REJECTED
	}

	return nil // AUTHENTICATION SUCCESS
}
