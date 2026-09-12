package server

import (
	"encoding/json"
	"errors"
	"github.com/larryf1/jwtoken-tester/internal/keyring"
	"github.com/larryf1/jwtoken-tester/internal/tokenfactory"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	maxRequestBody = 1 << 20
	rateLimitRPS   = 100
	rateLimitBurst = 200
)

type Server struct {
	ring     keyring.Ring
	Factory  *tokenfactory.Factory
	Issuer   string
	Version  string
	visitors map[string]*rate.Limiter
	lastSeen map[string]time.Time
	mu       sync.Mutex
}

func New(ring keyring.Ring, factory *tokenfactory.Factory, issuer string, version string) *Server {
	s := &Server{
		ring:     ring,
		Factory:  factory,
		Issuer:   issuer,
		Version:  version,
		visitors: make(map[string]*rate.Limiter),
		lastSeen: make(map[string]time.Time),
	}
	go s.cleanupVisitors()
	return s
}

func (s *Server) getVisitorLimiter(ip string) *rate.Limiter {
	s.mu.Lock()
	defer s.mu.Unlock()

	limiter, exists := s.visitors[ip]
	if !exists {
		limiter = rate.NewLimiter(rateLimitRPS, rateLimitBurst)
		s.visitors[ip] = limiter
	}
	s.lastSeen[ip] = time.Now()
	return limiter
}

func (s *Server) cleanupVisitors() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		for ip, lastSeen := range s.lastSeen {
			if time.Since(lastSeen) > 10*time.Minute {
				delete(s.visitors, ip)
				delete(s.lastSeen, ip)
			}
		}
		s.mu.Unlock()
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /version", s.handleVersion)
	mux.HandleFunc("GET /.well-known/jwks.json", s.handleJWKS)
	mux.HandleFunc("GET /.well-known/jwks.json/", s.handleJWKByKID)
	mux.HandleFunc("GET /.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("POST /token", s.handleToken)

	return s.securityHeaders(s.rateLimit(mux))
}

func (s *Server) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			ip = strings.Split(forwarded, ",")[0]
		}
		limiter := s.getVisitorLimiter(strings.TrimSpace(ip))
		if !limiter.Allow() {
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"version": s.Version,
	})
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"service": "jwtoken-tester",
		"version": s.Version,
		"warning": "integration-test token issuer; ephemeral in-memory keys",
		"endpoints": []string{
			"GET /healthz",
			"GET /.well-known/jwks.json",
			"GET /.well-known/jwks.json/{kid}",
			"GET /.well-known/openid-configuration",
			"POST /token",
		},
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	doc := map[string]any{
		"status":  "ok",
		"version": s.Version,
		"warning": "test issuer: keys are ephemeral and in-memory; do not use in production",
	}
	algorithms := s.ring.EnabledAlgorithms()
	if len(algorithms) > 0 {
		algStrs := make([]string, len(algorithms))
		for i, alg := range algorithms {
			algStrs[i] = string(alg)
		}
		doc["algorithms"] = algStrs
	}
	kids := make(map[string]string)
	for _, alg := range algorithms {
		if kid, err := s.ring.ActiveKid(alg); err == nil {
			kids[string(alg)] = kid
		}
	}
	if len(kids) > 0 {
		doc["active_kids"] = kids
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

func (s *Server) handleJWKByKID(w http.ResponseWriter, r *http.Request) {
	// Extract kid from path: /.well-known/jwks.json/<kid>
	kid := strings.TrimPrefix(r.URL.Path, "/.well-known/jwks.json/")
	if kid == "" {
		writeError(w, http.StatusBadRequest, "kid is required")
		return
	}

	key, err := s.ring.JWKByKID(kid)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	data, err := json.MarshalIndent(key, "", "  ")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	base := strings.TrimSuffix(s.Issuer, "/")
	algorithms := s.ring.EnabledAlgorithms()
	algStrs := make([]string, len(algorithms))
	for i, alg := range algorithms {
		algStrs[i] = string(alg)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.Issuer,
		"jwks_uri":                              base + "/.well-known/jwks.json",
		"token_endpoint":                        base + "/token",
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": algStrs,
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

	resp, err := s.Factory.Mint(&req)
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
