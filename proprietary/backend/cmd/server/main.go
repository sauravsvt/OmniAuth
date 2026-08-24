package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/omniauth/backend/internal/crypto"
)

type VerificationRequest struct {
	PublicKey   string `json:"public_key"`
	ChallengeID string `json:"challenge_id"`
	Message     string `json:"message"`
	Signature   string `json:"signature"`
}

type VerificationResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

type ChallengeResponse struct {
	ChallengeID string `json:"challenge_id"`
	Challenge   string `json:"challenge"`
	ExpiresAt   string `json:"expires_at"`
}

type challengeRecord struct {
	challenge string
	expiresAt time.Time
}

type ChallengeStore struct {
	mu         sync.Mutex
	ttl        time.Duration
	challenges map[string]challengeRecord
}

func NewChallengeStore(ttl time.Duration) *ChallengeStore {
	return &ChallengeStore{
		ttl:        ttl,
		challenges: make(map[string]challengeRecord),
	}
}

func randomToken(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (cs *ChallengeStore) Generate(now time.Time) (ChallengeResponse, error) {
	id, err := randomToken(16)
	if err != nil {
		return ChallengeResponse{}, err
	}
	challenge, err := randomToken(32)
	if err != nil {
		return ChallengeResponse{}, err
	}
	expiresAt := now.Add(cs.ttl)

	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.challenges[id] = challengeRecord{
		challenge: challenge,
		expiresAt: expiresAt,
	}

	return ChallengeResponse{
		ChallengeID: id,
		Challenge:   challenge,
		ExpiresAt:   expiresAt.UTC().Format(time.RFC3339),
	}, nil
}

func (cs *ChallengeStore) Consume(id, challenge string, now time.Time) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	record, ok := cs.challenges[id]
	if !ok {
		return errors.New("challenge not found or already used")
	}
	if now.After(record.expiresAt) {
		delete(cs.challenges, id)
		return errors.New("challenge expired")
	}
	if record.challenge != challenge {
		return errors.New("challenge mismatch")
	}

	delete(cs.challenges, id)
	return nil
}

func main() {
	logger := log.New(os.Stdout, "[OmniAuth API] ", log.LstdFlags)

	mux := setupRouter(logger)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	logger.Printf("PQC prototype API gateway starting on port %s...", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		logger.Fatalf("Server failed: %v", err)
	}
}

func setupRouter(logger *log.Logger) *http.ServeMux {
	mux := http.NewServeMux()
	challenges := NewChallengeStore(5 * time.Minute)
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/api/v1/challenge", func(w http.ResponseWriter, r *http.Request) {
		challengeHandler(w, r, challenges)
	})
	mux.HandleFunc("/api/v1/verify", func(w http.ResponseWriter, r *http.Request) {
		verifyHandler(w, r, logger, challenges)
	})
	return mux
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func challengeHandler(w http.ResponseWriter, r *http.Request, challenges *ChallengeStore) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	challenge, err := challenges.Generate(time.Now())
	if err != nil {
		http.Error(w, "Could not generate challenge", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(challenge)
}

func verifyHandler(w http.ResponseWriter, r *http.Request, logger *log.Logger, challenges *ChallengeStore) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req VerificationRequest
	limitedBody := http.MaxBytesReader(w, r.Body, 64*1024)
	if err := json.NewDecoder(limitedBody).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate input
	if req.PublicKey == "" || req.ChallengeID == "" || req.Message == "" || req.Signature == "" {
		resp := VerificationResponse{Success: false, Error: "Missing required fields"}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(resp)
		return
	}

	start := time.Now()
	err := crypto.VerifyIdentity(req.PublicKey, req.Message, req.Signature)
	duration := time.Since(start)

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		logger.Printf("Verification failed: %v (took %s)", err, duration)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(VerificationResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	if err := challenges.Consume(req.ChallengeID, req.Message, time.Now()); err != nil {
		logger.Printf("Challenge rejected after valid signature: %v (took %s)", err, duration)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(VerificationResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	logger.Printf("Verification success (took %s)", duration)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(VerificationResponse{
		Success: true,
	})
}
