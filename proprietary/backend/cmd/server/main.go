package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/omniauth/backend/internal/crypto"
)

type VerificationRequest struct {
	PublicKey string `json:"public_key"`
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

type VerificationResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

func main() {
	logger := log.New(os.Stdout, "[OmniAuth API] ", log.LstdFlags)

	mux := setupRouter(logger)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	logger.Printf("🚀 Quantum-Proof API Gateway starting on port %s...", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		logger.Fatalf("Server failed: %v", err)
	}
}

func setupRouter(logger *log.Logger) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/api/v1/verify", func(w http.ResponseWriter, r *http.Request) {
		verifyHandler(w, r, logger)
	})
	return mux
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func verifyHandler(w http.ResponseWriter, r *http.Request, logger *log.Logger) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req VerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate input
	if req.PublicKey == "" || req.Message == "" || req.Signature == "" {
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
		logger.Printf("❌ Verification Failed: %v (took %s)", err, duration)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(VerificationResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	logger.Printf("✅ Verification Success (took %s)", duration)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(VerificationResponse{
		Success: true,
	})
}
