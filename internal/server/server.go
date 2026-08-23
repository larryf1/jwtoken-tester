package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"jwtoken-tester/internal/keyring"
	"jwtoken-tester/internal/tokenfactory"
)

const maxRequestBody = 1 << 20

type Server struct {
	ring    *keyring.KeyRing
	factory *tokenfactory.Factory
	issuer  string
}

func New(ring *keyring.KeyRing, factory *tokenfactory.Factory, issuer string) *Server {
	return &Server{ring: ring, factory: factory, issuer: issuer}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /.well-known/jwks.json", s.handleJWKS)
	mux.HandleFunc("GET /.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("POST /token", s.handleToken)
	return mux
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"service": "jwtoken-tester",
		"warning": "integration-test token issuer; ephemeral in-memory keys",
		"endpoints": []string{
			"GET /healthz",
			"GET /.well-known/jwks.json",
			"GET /.well-known/openid-configuration",
			"POST /token",
		},
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	doc := map[string]any{
		"status":    "ok",
		"algorithm": "RS256",
		"warning":   "test issuer: keys are ephemeral and in-memory; do not use in production",
	}
	if kid, err := s.ring.ActiveKid(); err == nil {
		doc["active_kid"] = kid
	}
	writeJSON(w, http.StatusOK, doc)
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	set, err := s.ring.JWKS()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	data, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	base := strings.TrimSuffix(s.issuer, "/")
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.issuer,
		"jwks_uri":                              base + "/.well-known/jwks.json",
		"token_endpoint":                        base + "/token",
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"token"},
		"claims_supported": []string{
			"iss", "sub", "aud", "exp", "nbf", "iat", "jti",
		},
	})
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	var req tokenfactory.Request
	body := http.MaxBytesReader(w, r.Body, maxRequestBody)
	if err := json.NewDecoder(body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}

	resp, err := s.factory.Mint(&req)
	if err != nil {
		switch {
		case errors.Is(err, tokenfactory.ErrInvalidRequest),
			errors.Is(err, tokenfactory.ErrUnsupportedAlg),
			errors.Is(err, tokenfactory.ErrTTLTooLong):
			writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, keyring.ErrNoActiveKey):
			writeError(w, http.StatusServiceUnavailable, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
