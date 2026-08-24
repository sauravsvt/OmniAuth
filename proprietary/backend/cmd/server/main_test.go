package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

func issueChallenge(t *testing.T, router *http.ServeMux) ChallengeResponse {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/v1/challenge", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("challenge endpoint returned %d: %s", rr.Code, rr.Body.String())
	}

	var challenge ChallengeResponse
	if err := json.NewDecoder(rr.Body).Decode(&challenge); err != nil {
		t.Fatalf("failed to decode challenge: %v", err)
	}
	if challenge.ChallengeID == "" || challenge.Challenge == "" || challenge.ExpiresAt == "" {
		t.Fatalf("challenge response missing fields: %+v", challenge)
	}
	return challenge
}

func TestHealthEndpoint(t *testing.T) {
	router := setupRouter(log.Default())
	req := httptest.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	expected := "OK"
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}

func TestVerifyEndpoint_Success(t *testing.T) {
	// 1. Generate Valid Data
	pk, sk, err := mode3.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	router := setupRouter(log.Default())
	challenge := issueChallenge(t, router)
	message := challenge.Challenge
	sig := make([]byte, mode3.SignatureSize)
	mode3.SignTo(sk, []byte(message), sig)

	payload := VerificationRequest{
		PublicKey:   base64.StdEncoding.EncodeToString(pk.Bytes()),
		ChallengeID: challenge.ChallengeID,
		Message:     message,
		Signature:   base64.StdEncoding.EncodeToString(sig),
	}

	body, _ := json.Marshal(payload)

	// 2. Perform Request
	req := httptest.NewRequest("POST", "/api/v1/verify", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// 3. Assertions
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Verify failed. Status: %d, Body: %s", rr.Code, rr.Body.String())
	}

	var resp VerificationResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}

	if !resp.Success {
		t.Errorf("Expected success=true, got failure: %s", resp.Error)
	}
}

func TestVerifyEndpoint_InvalidSignature(t *testing.T) {
	// 1. Generate Valid Key but Invalid Signature
	pk, _, _ := mode3.GenerateKey(nil)
	router := setupRouter(log.Default())
	challenge := issueChallenge(t, router)
	message := challenge.Challenge

	// Create "trash" signature
	sig := make([]byte, mode3.SignatureSize)
	// Leave it as zeros (invalid)

	payload := VerificationRequest{
		PublicKey:   base64.StdEncoding.EncodeToString(pk.Bytes()),
		ChallengeID: challenge.ChallengeID,
		Message:     message,
		Signature:   base64.StdEncoding.EncodeToString(sig),
	}

	body, _ := json.Marshal(payload)

	// 2. Perform Request
	req := httptest.NewRequest("POST", "/api/v1/verify", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// 3. Assertions
	// We expect 401 Unauthorized for bad signatures
	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("Expected 401 Unauthorized, got %d", status)
	}

	var resp VerificationResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	if resp.Success {
		t.Error("Expected success=false, got true")
	}
}

func TestVerifyEndpoint_ReplayRejected(t *testing.T) {
	pk, sk, err := mode3.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	router := setupRouter(log.Default())
	challenge := issueChallenge(t, router)

	sig := make([]byte, mode3.SignatureSize)
	mode3.SignTo(sk, []byte(challenge.Challenge), sig)

	payload := VerificationRequest{
		PublicKey:   base64.StdEncoding.EncodeToString(pk.Bytes()),
		ChallengeID: challenge.ChallengeID,
		Message:     challenge.Challenge,
		Signature:   base64.StdEncoding.EncodeToString(sig),
	}
	body, _ := json.Marshal(payload)

	first := httptest.NewRecorder()
	router.ServeHTTP(first, httptest.NewRequest("POST", "/api/v1/verify", bytes.NewBuffer(body)))
	if first.Code != http.StatusOK {
		t.Fatalf("first verification failed: %d %s", first.Code, first.Body.String())
	}

	replay := httptest.NewRecorder()
	router.ServeHTTP(replay, httptest.NewRequest("POST", "/api/v1/verify", bytes.NewBuffer(body)))
	if replay.Code != http.StatusUnauthorized {
		t.Fatalf("expected replay to be rejected, got %d %s", replay.Code, replay.Body.String())
	}
}
