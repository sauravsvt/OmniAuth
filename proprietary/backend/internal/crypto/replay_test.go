package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// Simple in-memory challenge store for replay protection demo
type ChallengeStore struct {
	mu   sync.Mutex
	used map[string]bool
}

func NewChallengeStore() *ChallengeStore {
	return &ChallengeStore{used: make(map[string]bool)}
}

// Generate creates a fresh challenge
func (cs *ChallengeStore) Generate() string {
	nonce := make([]byte, 32)
	rand.Read(nonce)
	challenge := base64.StdEncoding.EncodeToString(nonce)
	return challenge
}

// VerifyAndConsume verifies a challenge can only be used once
// Returns true if challenge is fresh, false if replayed
func (cs *ChallengeStore) VerifyAndConsume(challenge string) bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	
	if cs.used[challenge] {
		return false // REPLAY DETECTED
	}
	cs.used[challenge] = true
	return true // FRESH
}

// TestReplayProtection demonstrates that a challenge cannot be reused
func TestReplayProtection(t *testing.T) {
	// Setup: Generate keypair
	pk, sk, err := mode3.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	pkBytes := pk.Bytes()
	pubKeyB64 := base64.StdEncoding.EncodeToString(pkBytes)

	// Challenge store (would be Redis/DB in production)
	cs := NewChallengeStore()

	// Step 1: Server issues a challenge
	challenge := cs.Generate()
	t.Logf("Issued challenge: %s...", challenge[:16])

	// Step 2: Client signs the challenge
	sig := make([]byte, mode3.SignatureSize)
	mode3.SignTo(sk, []byte(challenge), sig)
	signatureB64 := base64.StdEncoding.EncodeToString(sig)

	// Step 3: Server verifies signature AND consumes challenge (first use)
	t.Run("FirstUse_Valid", func(t *testing.T) {
		// Signature must be valid
		err := VerifyIdentity(pubKeyB64, challenge, signatureB64)
		if err != nil {
			t.Fatalf("Signature verification failed: %v", err)
		}

		// Challenge must be fresh
		if !cs.VerifyAndConsume(challenge) {
			t.Fatal("Challenge should be fresh on first use")
		}
	})

	// Step 4: Attacker replays the exact same (challenge, signature) pair
	t.Run("ReplayAttempt_Rejected", func(t *testing.T) {
		// Signature would still be cryptographically valid...
		err := VerifyIdentity(pubKeyB64, challenge, signatureB64)
		if err != nil {
			t.Logf("Signature verification result: %v", err)
			// This could fail if using a different key, but will pass for replay
		}

		// ...but the challenge is now stale
		if cs.VerifyAndConsume(challenge) {
			t.Fatal("SECURITY FAILURE: Replay attack succeeded!")
		}
		t.Log("Replay correctly rejected: challenge was already consumed")
	})

	// Step 5: Fresh challenge with same key works
	t.Run("NewChallenge_Valid", func(t *testing.T) {
		newChallenge := cs.Generate()
		
		sig := make([]byte, mode3.SignatureSize)
		mode3.SignTo(sk, []byte(newChallenge), sig)
		newSigB64 := base64.StdEncoding.EncodeToString(sig)

		err := VerifyIdentity(pubKeyB64, newChallenge, newSigB64)
		if err != nil {
			t.Fatalf("New challenge signature verification failed: %v", err)
		}

		if !cs.VerifyAndConsume(newChallenge) {
			t.Fatal("New challenge should be fresh")
		}
	})
}
