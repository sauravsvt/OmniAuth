package crypto

import (
	"encoding/base64"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

func TestVerifyIdentity(t *testing.T) {
	// 1. Generate a valid keypair
	pk, sk, err := mode3.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	// 2. Prepare test data
	message := "test-challenge-message"

	// Pack keys to bytes
	pkBytes := pk.Bytes()

	// Sign message
	sig := make([]byte, mode3.SignatureSize)
	mode3.SignTo(sk, []byte(message), sig)

	// Encode to Base64 (as expected by Verifier)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pkBytes)
	signatureB64 := base64.StdEncoding.EncodeToString(sig)

	// 3. Test Case: Valid Signature
	t.Run("ValidSignature", func(t *testing.T) {
		err := VerifyIdentity(pubKeyB64, message, signatureB64)
		if err != nil {
			t.Errorf("Expected success, but got error: %v", err)
		}
	})

	// 4. Test Case: Invalid Signature
	t.Run("InvalidSignature", func(t *testing.T) {
		// Tamper with signature
		badSigBytes := make([]byte, len(sig))
		copy(badSigBytes, sig)
		badSigBytes[0] ^= 0xFF // Flip bits in first byte

		badSigB64 := base64.StdEncoding.EncodeToString(badSigBytes)

		err := VerifyIdentity(pubKeyB64, message, badSigB64)
		if err == nil {
			t.Error("Expected error for invalid signature, but got nil")
		}
	})

	// 5. Test Case: Wrong Message
	t.Run("WrongMessage", func(t *testing.T) {
		err := VerifyIdentity(pubKeyB64, "wrong-message", signatureB64)
		if err == nil {
			t.Error("Expected error for wrong message, but got nil")
		}
	})

	// 6. Test Case: Invalid Public Key Format
	t.Run("InvalidPublicKeyFormat", func(t *testing.T) {
		err := VerifyIdentity("not-base64", message, signatureB64)
		if err == nil {
			t.Error("Expected error for invalid public key format, but got nil")
		}
	})
}
