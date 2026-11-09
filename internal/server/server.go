// Package server provides the HTTP endpoints for the jwtoken-tester service.
//
//	Ephemeral JWT/JWKS test issuer for integration testing JWT-aware services.
//	This is a test tool only - not a production IdP. Keys are generated in-memory
//	and discarded on shutdown. No TLS is implemented; terminate TLS at a reverse proxy.
//
//	@title			jwtoken-tester API
//	@version		2.5.0
//	@contact.name	jwtoken-tester
//	@contact.url	https://github.com/larryf1/jwtoken-tester
//	@contact.email	larryf1@gmail.com
//	@license.name	MIT
//	@license.url	https://opensource.org/licenses/MIT
//	@securityDefinitions.apikey	BearerAuth
//	@in				header
//	@name			Authorization
//	@description	Type "Bearer" followed by a space and JWT.
//	@tag.name		Metadata
//	@tag.description	Service metadata and health
//	@tag.name		Keys
//	@tag.description	JWKS and key management endpoints
//	@tag.name		Tokens
//	@tag.description	Token minting endpoints
//	@tag.name		Introspection
//	@tag.description	RFC 7662 token introspection
//	@tag.name		Verification
//	@tag.description	Self-check token verification
//	@tag.name		Discovery
//	@tag.description	OpenID Connect and OAuth authorization server metadata
package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/larryf1/jwtoken-tester/v2/internal/keyring"
	"github.com/larryf1/jwtoken-tester/v2/internal/tokenfactory"
	"github.com/larryf1/jwtoken-tester/v2/internal/verify"
	"golang.org/x/time/rate"
)

const (
	maxRequestBody        = 1 << 20
	defaultRateLimitRPS   = 100
	defaultRateLimitBurst = 200
)

type Server struct {
	ring           keyring.Ring
	Factory        *tokenfactory.Factory
	Issuer         string
	Version        string
	rateLimitRPS   float64
	rateLimitBurst int
	visitors       map[string]*rate.Limiter
	lastSeen       map[string]time.Time
	mu             sync.Mutex

	audience            string
	scopes              []string
	discoveryExtra      map[string]any
	allowNegativeTokens bool

	logger        *slog.Logger
	cleanupCancel context.CancelFunc
	cleanupDone   chan struct{}
	closeOnce     sync.Once
}

// Option configures optional server behavior.
type Option func(*Server)

// WithAllowNegativeTokens enables deliberate negative token controls on POST /token.
func WithAllowNegativeTokens(allow bool) Option {
	return func(s *Server) { s.allowNegativeTokens = allow }
}

// WithLogger routes token audit events to logger. A nil logger is ignored so
// the default logger remains in effect.
func WithLogger(logger *slog.Logger) Option {
	return func(s *Server) {
		if logger != nil {
			s.logger = logger
		}
	}
}

// WithAudience sets the aud claim placed on tokens minted by /oauth/token. An
// empty value omits the claim, which is the default.
func WithAudience(audience string) Option {
	return func(s *Server) {
		s.audience = audience
	}
}

// WithScopes sets the scope names advertised as scopes_supported in discovery.
// It does not restrict scopes requested from /oauth/token.
func WithScopes(scopes []string) Option {
	return func(s *Server) {
		s.scopes = append([]string(nil), scopes...)
	}
}

// WithDiscoveryExtra merges extra metadata into both discovery documents.
// Derived core fields (issuer, jwks_uri, token_endpoint, introspection_endpoint)
// always win over the supplied values.
func WithDiscoveryExtra(extra map[string]any) Option {
	return func(s *Server) {
		if extra == nil {
			s.discoveryExtra = nil
			return
		}
		s.discoveryExtra = make(map[string]any, len(extra))
		for key, value := range extra {
			s.discoveryExtra[key] = value
		}
	}
}

func New(ring keyring.Ring, factory *tokenfactory.Factory, issuer string, version string, rateLimitRPS float64, rateLimitBurst int, opts ...Option) *Server {
	if rateLimitRPS <= 0 {
		rateLimitRPS = defaultRateLimitRPS
	}
	if rateLimitBurst <= 0 {
		rateLimitBurst = defaultRateLimitBurst
	}
	s := &Server{
		ring:           ring,
		Factory:        factory,
		Issuer:         issuer,
		Version:        version,
		rateLimitRPS:   rateLimitRPS,
		rateLimitBurst: rateLimitBurst,
		visitors:       make(map[string]*rate.Limiter),
		lastSeen:       make(map[string]time.Time),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cleanupCancel = cancel
	s.cleanupDone = make(chan struct{})
	go s.cleanupVisitors(ctx)
	return s
}

// Close stops the visitor-cleanup goroutine and waits for it to exit. It is
// idempotent and safe to call concurrently.
func (s *Server) Close() {
	s.closeOnce.Do(func() {
		if s.cleanupCancel != nil {
			s.cleanupCancel()
		}
		if s.cleanupDone != nil {
			<-s.cleanupDone
		}
	})
}

func (s *Server) getVisitorLimiter(ip string) *rate.Limiter {
	s.mu.Lock()
	defer s.mu.Unlock()

	limiter, exists := s.visitors[ip]
	if !exists {
		limiter = rate.NewLimiter(rate.Limit(s.rateLimitRPS), s.rateLimitBurst)
		s.visitors[ip] = limiter
	}
	s.lastSeen[ip] = time.Now()
	return limiter
}

func (s *Server) cleanupVisitors(ctx context.Context) {
	defer close(s.cleanupDone)
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
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
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /version", s.handleVersion)
	mux.HandleFunc("GET /.well-known/jwks.json", s.handleJWKS)
	mux.HandleFunc("GET /.well-known/jwks.json/", s.handleJWKByKID)
	mux.HandleFunc("GET /.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.handleAuthorizationServerMetadata)
	mux.HandleFunc("POST /token", s.handleToken)
	mux.HandleFunc("POST /oauth/token", s.handleOAuthClientCredentialsToken)
	mux.HandleFunc("POST /introspect", s.handleIntrospect)
	mux.HandleFunc("POST /v2/oauth/token", s.handleOAuthToken)
	mux.HandleFunc("POST /verify", s.handleVerify)

	return s.securityHeaders(s.rateLimit(s.requestID(mux)))
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

func (s *Server) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = generateRequestID()
		}
		w.Header().Set("X-Request-ID", requestID)
		// Store in context for handlers that need it
		ctx := context.WithValue(r.Context(), requestIDKey{}, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type requestIDKey struct{}

func generateRequestID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return time.Now().Format("20060102150405.000000")
	}
	return hex.EncodeToString(bytes)
}

func getRequestID(r *http.Request) string {
	if v := r.Context().Value(requestIDKey{}); v != nil {
		return v.(string)
	}
	return r.Header.Get("X-Request-ID")
}

// handleVersion returns the service version.
//
//	@ID			getVersion
//	@Tags		Metadata
//	@Summary	Version information
//	@Description	Returns the service version
//	@Success	200	{object}	VersionResponse	"Version information"
//	@Router	/version [get]
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"version": s.Version,
	})
}

// handleIndex returns basic service information and available endpoints.
//
//	@ID			getIndex
//	@Tags		Metadata
//	@Summary	Service index
//	@Description	Returns basic service information and available endpoints
//	@Success	200	{object}	IndexResponse	"Successful response"
//	@Router	/ [get]
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"service": "jwtoken-tester",
		"version": s.Version,
		"warning": "integration-test token issuer; ephemeral in-memory keys",
		"endpoints": []string{
			"GET /healthz",
			"GET /version",
			"GET /.well-known/jwks.json",
			"GET /.well-known/jwks.json/{kid}",
			"GET /.well-known/openid-configuration",
			"GET /.well-known/oauth-authorization-server",
			"POST /token",
			"POST /oauth/token",
			"POST /introspect",
			"POST /v2/oauth/token",
			"POST /verify",
		},
	})
}

// handleHealth returns a liveness probe with active key IDs per algorithm.
//
//	@ID			getHealth
//	@Tags		Metadata
//	@Summary	Health check
//	@Description	Liveness probe with active key IDs per algorithm
//	@Success	200	{object}	HealthResponse	"Service is healthy"
//	@Router	/healthz [get]
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

// handleJWKS returns the live public key set.
//
//	@ID			getJWKS
//	@Tags		Keys
//	@Summary	JSON Web Key Set (JWKS)
//	@Description	Returns the live public key set including active keys and retired keys still within their grace period. Each key includes RFC 7638 thumbprint-derived kid, use=sig, and algorithm (RS256, ES256, or EdDSA).
//	@Success	200	{object}	JWKS	"JWKS document"
//	@Failure	500	{object}	ErrorResponse	"Internal server error"
//	@Router	/.well-known/jwks.json [get]
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

// handleJWKByKID fetches a single public key by its thumbprint-derived kid.
//
//	@ID			getJWKByKID
//	@Tags		Keys
//	@Summary	Get single JWK by Key ID
//	@Description	Fetches a single public key from the live key set by its thumbprint-derived kid. Returns the same shape as one entry of the JWKS set. Retired keys still inside their grace window are reachable.
//	@Param		kid	path	string	true	"RFC 7638 thumbprint-derived Key ID"
//	@Success	200	{object}	JWK	"JWK document"
//	@Failure	400	{object}	ErrorResponse	"Missing kid parameter"
//	@Failure	404	{object}	ErrorResponse	"Key not found"
//	@Router	/.well-known/jwks.json/{kid} [get]
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

// discoveryDocument builds the single metadata document served at both the
// OIDC and RFC 8414 well-known paths. Extra metadata is applied first so the
// derived core endpoints cannot be overridden.
func (s *Server) discoveryDocument() map[string]any {
	base := strings.TrimSuffix(s.Issuer, "/")
	algorithms := s.ring.EnabledAlgorithms()
	algStrs := make([]string, len(algorithms))
	for i, alg := range algorithms {
		algStrs[i] = string(alg)
	}

	doc := make(map[string]any, len(s.discoveryExtra)+12)
	for key, value := range s.discoveryExtra {
		doc[key] = value
	}

	doc["subject_types_supported"] = []string{"public"}
	doc["id_token_signing_alg_values_supported"] = algStrs
	doc["response_types_supported"] = []string{"token"}
	doc["grant_types_supported"] = []string{"client_credentials"}
	doc["token_endpoint_auth_methods_supported"] = []string{
		"client_secret_basic", "client_secret_post", "none",
	}
	doc["claims_supported"] = []string{
		"iss", "sub", "aud", "exp", "nbf", "iat", "jti", "scope", "client_id",
	}
	if len(s.scopes) > 0 {
		doc["scopes_supported"] = append([]string(nil), s.scopes...)
	}

	// Derived core fields are written last so extras cannot replace them.
	doc["issuer"] = s.Issuer
	doc["jwks_uri"] = base + "/.well-known/jwks.json"
	doc["token_endpoint"] = base + "/oauth/token"
	doc["introspection_endpoint"] = base + "/introspect"
	return doc
}

// handleDiscovery returns the OpenID Connect discovery document.
//
//	@ID			getDiscovery
//	@Tags		Discovery
//	@Summary	OpenID Connect Discovery Document
//	@Description	Shared metadata document advertising issuer, derived jwks_uri, token_endpoint, introspection_endpoint, grant_types_supported, token_endpoint_auth_methods_supported, scopes_supported when configured, and id_token_signing_alg_values_supported listing all enabled algorithms.
//	@Success	200	{object}	DiscoveryResponse	"Discovery document"
//	@Router	/.well-known/openid-configuration [get]
func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.discoveryDocument())
}

// handleAuthorizationServerMetadata returns the OAuth 2.0 authorization server metadata.
//
//	@ID			getAuthorizationServerMetadata
//	@Tags		Discovery
//	@Summary	OAuth 2.0 Authorization Server Metadata (RFC 8414)
//	@Description	Serves the same metadata document as /.well-known/openid-configuration. Derived core fields (issuer, jwks_uri, token_endpoint, introspection_endpoint) cannot be overridden by DISCOVERY_EXTRA_JSON.
//	@Success	200	{object}	DiscoveryResponse	"Authorization server metadata"
//	@Router	/.well-known/oauth-authorization-server [get]
func (s *Server) handleAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.discoveryDocument())
}

// handleToken mints a signed JWT with the requested claims and algorithm.
//
//	@ID			mintToken
//	@Tags		Tokens
//	@Summary	Mint a JWT
//	@Description	Mints a JWT with the requested claims and algorithm. Empty body mints an anonymous token with defaults. Claim handling: iss, iat, nbf are injected automatically; explicit values in claims win. exp, iat, nbf accept epoch seconds, durations, or RFC 3339 timestamps. Omitted exp means now + DEFAULT_TTL (default 1h). Lifetimes beyond MAX_TTL (default 24h) are refused with 400. Algorithms: RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA (must be enabled). Negative controls require ALLOW_NEGATIVE_TOKENS.
//	@Param		request	body	TokenRequest	false	"Token minting request (empty body uses defaults)"
//	@Success	200	{object}	TokenResponse	"Token minted successfully"
//	@Failure	400	{object}	ErrorResponse	"Bad request (invalid JSON, unsupported algorithm, TTL too long)"
//	@Failure	403	{object}	ErrorResponse	"Negative token control is disabled"
//	@Failure	405	{object}	ErrorResponse	"Method not allowed"
//	@Failure	429	{object}	ErrorResponse	"Rate limit exceeded"
//	@Failure	503	{object}	ErrorResponse	"No active signing key available"
//	@Router	/token [post]
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	var req tokenfactory.Request
	body := http.MaxBytesReader(w, r.Body, maxRequestBody)
	if err := json.NewDecoder(body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	req.AllowNegative = s.allowNegativeTokens

	resp, err := s.Factory.Mint(&req)
	if err != nil {
		s.logTokenEvent(r, "token_mint_failed", map[string]any{
			"error":         err.Error(),
			"requested_alg": req.Alg,
			"control":       requestedControl(req),
		})
		switch {
		case errors.Is(err, tokenfactory.ErrInvalidRequest),
			errors.Is(err, tokenfactory.ErrUnsupportedAlg),
			errors.Is(err, tokenfactory.ErrTTLTooLong):
			writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, tokenfactory.ErrNegativeDisabled):
			writeError(w, http.StatusForbidden, err.Error())
		case errors.Is(err, keyring.ErrNoActiveKey):
			writeError(w, http.StatusServiceUnavailable, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	alg := req.Alg
	if alg == "" {
		alg = string(keyring.AlgRS256)
	}
	var kid string
	if alg != "none" && alg != "HS256" {
		signer, signerErr := s.ring.Signer(keyring.Algorithm(alg))
		if signerErr == nil {
			kid = signer.Kid()
		}
	}

	s.logTokenEvent(r, "token_minted", map[string]any{
		"alg":                alg,
		"kid":                kid,
		"control":            requestedControl(req),
		"expires_in":         resp.ExpiresIn,
		"has_custom_claims":  len(req.Claims) > 0,
		"has_custom_headers": len(req.Headers) > 0,
	})
	writeJSON(w, http.StatusOK, resp)
}

// verifyRequest is the self-check request. Unknown fields are rejected on
// purpose: a client that sends jwks, jwks_url, issuer, or a typo gets a 400
// instead of a silently ignored field and a misleading verdict.
type verifyRequest struct {
	Token  string    `json:"token"`
	Aud    audience  `json:"aud"`
	Alg    *[]string `json:"alg"`
	Leeway string    `json:"leeway"`
}

type audience []string

func (a *audience) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*a = nil
		return nil
	}
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = audience{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return errors.New("aud must be a string or an array of strings")
	}
	*a = audience(many)
	return nil
}

// handleVerify performs self-check verification against the live keyring.
//
//	@ID			verifyToken
//	@Tags		Verification
//	@Summary	Verify a token against this issuer's live keyring
//	@Description	Self-check verification: the token is checked only against the running issuer's live keyring. The endpoint accepts no caller-supplied key material or key locations and performs no outbound network request. Unknown request fields are rejected with 400. The issuer claim is always validated against this server's configured issuer. Failure reasons are a closed, ordered set: malformed, alg, kid, signature, expired, not_yet_valid, issuer, audience.
//	@Param		request	body	VerifyRequest	true	"Verification request"
//	@Success	200	{object}	VerifyResponse	"Verification completed; inspect valid and reason"
//	@Failure	400	{object}	ErrorResponse	"Invalid request (missing token, unknown field, bad alg or leeway, oversized body)"
//	@Failure	405	{object}	ErrorResponse	"Method not allowed"
//	@Failure	429	{object}	ErrorResponse	"Rate limit exceeded"
//	@Failure	500	{object}	ErrorResponse	"Verification failed for a reason outside the closed reason set"
//	@Router	/verify [post]
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	var req verifyRequest
	body := http.MaxBytesReader(w, r.Body, maxRequestBody)
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}

	tokenValue := strings.TrimSpace(req.Token)
	if tokenValue == "" {
		writeError(w, http.StatusBadRequest, "token is required")
		return
	}

	var leeway time.Duration
	if req.Leeway != "" {
		parsed, err := time.ParseDuration(req.Leeway)
		if err != nil || parsed < 0 {
			writeError(w, http.StatusBadRequest, "leeway must be a non-negative Go duration")
			return
		}
		leeway = parsed
	}

	var allowed []string
	if req.Alg != nil {
		if len(*req.Alg) == 0 {
			writeError(w, http.StatusBadRequest, "alg must not be empty")
			return
		}
		enabled := s.ring.EnabledAlgorithms()
		for _, alg := range *req.Alg {
			if alg == "" || !slices.Contains(enabled, keyring.Algorithm(alg)) {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("algorithm %q is not enabled", alg))
				return
			}
		}
		allowed = append(allowed, (*req.Alg)...)
	}

	verdict, err := verify.Verify(verify.Input{
		Token:          tokenValue,
		Keys:           verify.RingKeySource{Ring: s.ring},
		ExpectedIssuer: s.Issuer,
		AllowedAlgs:    allowed,
		Audience:       []string(req.Aud),
		Leeway:         leeway,
		Now:            time.Now().UTC(),
	})
	if err != nil {
		s.logTokenEvent(r, "token_verified", map[string]any{
			"valid": false,
			"error": "verification failed",
		})
		writeError(w, http.StatusInternalServerError, "verification failed")
		return
	}

	attrs := map[string]any{"valid": verdict.Valid}
	if !verdict.Valid {
		attrs["reason"] = string(verdict.Reason)
	}
	if verdict.Kid != "" {
		attrs["kid"] = verdict.Kid
	}
	if verdict.KidStatus != "" {
		attrs["kid_status"] = string(verdict.KidStatus)
	}
	if verdict.Alg != "" {
		attrs["alg"] = verdict.Alg
	}
	s.logTokenEvent(r, "token_verified", attrs)

	writeJSON(w, http.StatusOK, verdict)
}

const oauthFormContentType = "application/x-www-form-urlencoded"

func setNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{
		"error":             code,
		"error_description": description,
	})
}

func parseOAuthForm(w http.ResponseWriter, r *http.Request) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != oauthFormContentType {
		return errors.New("request body must be application/x-www-form-urlencoded")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	return r.ParseForm()
}

func oauthClientID(r *http.Request) string {
	if username, _, ok := r.BasicAuth(); ok {
		if clientID := strings.TrimSpace(username); clientID != "" {
			return clientID
		}
	}
	return strings.TrimSpace(r.PostForm.Get("client_id"))
}

func normalizeScope(raw string) string {
	return strings.Join(strings.Fields(raw), " ")
}

// selectAlgorithm validates an explicit algorithm or falls back to RS256 when
// enabled, then to the first enabled algorithm.
func (s *Server) selectAlgorithm(raw string) (keyring.Algorithm, error) {
	enabled := s.ring.EnabledAlgorithms()
	if alg := strings.TrimSpace(raw); alg != "" {
		candidate := keyring.Algorithm(alg)
		if !slices.Contains(enabled, candidate) {
			return "", fmt.Errorf("algorithm %q is not enabled", alg)
		}
		return candidate, nil
	}
	if slices.Contains(enabled, keyring.AlgRS256) {
		return keyring.AlgRS256, nil
	}
	if len(enabled) > 0 {
		return enabled[0], nil
	}
	return keyring.AlgRS256, nil
}

// selectTTL parses an optional non-negative Go duration and enforces MAX_TTL.
// The boolean reports whether the caller supplied a value.
func (s *Server) selectTTL(raw string) (time.Duration, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false, nil
	}
	ttl, err := time.ParseDuration(raw)
	if err != nil || ttl < 0 {
		return 0, false, errors.New("ttl must be a non-negative Go duration")
	}
	if maxTTL := s.Factory.MaxTTL(); maxTTL > 0 && ttl > maxTTL {
		return 0, false, fmt.Errorf("ttl exceeds maximum allowed lifetime %s", maxTTL)
	}
	return ttl, true, nil
}

func oauthErrorCode(err error) string {
	switch {
	case errors.Is(err, keyring.ErrNoActiveKey):
		return "temporarily_unavailable"
	case errors.Is(err, tokenfactory.ErrInvalidRequest),
		errors.Is(err, tokenfactory.ErrUnsupportedAlg),
		errors.Is(err, tokenfactory.ErrTTLTooLong):
		return "invalid_request"
	default:
		return "server_error"
	}
}

func (s *Server) logOAuthMintFailure(r *http.Request, code string, attrs map[string]any) {
	if attrs == nil {
		attrs = map[string]any{}
	}
	attrs["error"] = code
	s.logTokenEvent(r, "oauth_token_mint_failed", attrs)
}

// handleOAuthClientCredentialsToken mints a token with OAuth 2.0 client credentials.
//
//	@ID			mintOAuthClientCredentialsToken
//	@Tags		Tokens
//	@Summary	Mint a token with OAuth 2.0 client credentials
//	@Description	RFC 6749 client-credentials token endpoint for generic OAuth clients. The request body must be application/x-www-form-urlencoded. Authentication is permissive: a client identifier is required, but client_secret is never validated. Claims: iss, sub and client_id from the client identifier, iat, nbf, exp, jti, a space-normalized scope when requested, and aud only when AUDIENCE is configured.
//	@Param		request	body	OAuthTokenRequest	true	"OAuth token request"
//	@Success	200	{object}	OAuthTokenResponse	"Token minted successfully"
//	@Failure	400	{object}	OAuthErrorResponse	"Invalid request, unsupported grant type, disabled algorithm, invalid TTL, or oversized body"
//	@Failure	405	{object}	OAuthErrorResponse	"Method not allowed"
//	@Failure	429	{object}	ErrorResponse	"Rate limit exceeded"
//	@Failure	500	{object}	OAuthErrorResponse	"Internal token-minting failure"
//	@Failure	503	{object}	OAuthErrorResponse	"No active signing key available"
//	@Router	/oauth/token [post]
func (s *Server) handleOAuthClientCredentialsToken(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)

	if err := parseOAuthForm(w, r); err != nil {
		s.logOAuthMintFailure(r, "invalid_request", nil)
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "request body must be application/x-www-form-urlencoded")
		return
	}

	grantType := strings.TrimSpace(r.PostForm.Get("grant_type"))
	if grantType == "" {
		s.logOAuthMintFailure(r, "invalid_request", nil)
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "grant_type is required")
		return
	}
	if grantType != "client_credentials" {
		s.logOAuthMintFailure(r, "unsupported_grant_type", map[string]any{"grant_type": grantType})
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "only client_credentials is supported")
		return
	}

	clientID := oauthClientID(r)
	if clientID == "" {
		s.logOAuthMintFailure(r, "invalid_request", nil)
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "client_id is required")
		return
	}

	scope := normalizeScope(r.PostForm.Get("scope"))
	alg, err := s.selectAlgorithm(r.PostForm.Get("alg"))
	if err != nil {
		s.logOAuthMintFailure(r, "invalid_request", map[string]any{"alg": r.PostForm.Get("alg")})
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	ttl, ttlSet, err := s.selectTTL(r.PostForm.Get("ttl"))
	if err != nil {
		s.logOAuthMintFailure(r, "invalid_request", map[string]any{"ttl": r.PostForm.Get("ttl")})
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	jti, err := generateJTI()
	if err != nil {
		s.logOAuthMintFailure(r, "server_error", nil)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not generate token ID")
		return
	}

	claims := map[string]any{
		"sub":       clientID,
		"client_id": clientID,
		"jti":       jti,
	}
	if scope != "" {
		claims["scope"] = scope
	}
	if s.audience != "" {
		claims["aud"] = s.audience
	}
	if ttlSet {
		claims["exp"] = ttl.String()
	}

	resp, err := s.Factory.Mint(&tokenfactory.Request{Claims: claims, Alg: string(alg)})
	if err != nil {
		s.logOAuthMintFailure(r, oauthErrorCode(err), map[string]any{
			"alg":   string(alg),
			"scope": scope,
		})
		switch {
		case errors.Is(err, tokenfactory.ErrInvalidRequest),
			errors.Is(err, tokenfactory.ErrUnsupportedAlg),
			errors.Is(err, tokenfactory.ErrTTLTooLong):
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		case errors.Is(err, keyring.ErrNoActiveKey):
			writeOAuthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "no active signing key")
		default:
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "token minting failed")
		}
		return
	}

	response := map[string]any{
		"access_token": resp.AccessToken,
		"token_type":   resp.TokenType,
		"expires_in":   resp.ExpiresIn,
	}
	if scope != "" {
		response["scope"] = scope
	}
	s.logTokenEvent(r, "oauth_token_minted", map[string]any{
		"alg":        string(alg),
		"scope":      scope,
		"expires_in": resp.ExpiresIn,
	})
	writeJSON(w, http.StatusOK, response)
}

// handleIntrospect verifies a token against this server's live keyring (RFC 7662).
//
//	@ID			introspectToken
//	@Tags		Introspection
//	@Summary	Introspect a token (RFC 7662)
//	@Description	Verifies the supplied token against this server's live keyring and configured issuer. The request body must be application/x-www-form-urlencoded; token_type_hint is accepted and ignored. Authentication is permissive and no client identifier is required. Active tokens echo every token claim plus authoritative active: true and token_type: Bearer. Expired, not-yet-valid, wrong-issuer, unknown-key, bad-signature, and malformed tokens return 200 with exactly {"active": false} and no claim fields.
//	@Param		request	body	IntrospectionRequest	true	"Introspection request"
//	@Success	200	{object}	IntrospectionResponse	"Introspection result; inspect active"
//	@Failure	400	{object}	OAuthErrorResponse	"Invalid request (missing token, non-form body, oversized body)"
//	@Failure	405	{object}	OAuthErrorResponse	"Method not allowed"
//	@Failure	429	{object}	ErrorResponse	"Rate limit exceeded"
//	@Failure	500	{object}	OAuthErrorResponse	"Verification failed unexpectedly"
//	@Router	/introspect [post]
func (s *Server) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)

	if err := parseOAuthForm(w, r); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "request body must be application/x-www-form-urlencoded")
		return
	}

	tokenValue := strings.TrimSpace(r.PostForm.Get("token"))
	if tokenValue == "" {
		s.logTokenEvent(r, "token_introspected", map[string]any{"active": false, "reason": "missing_token"})
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "token is required")
		return
	}

	verdict, err := verify.Verify(verify.Input{
		Token:          tokenValue,
		Keys:           verify.RingKeySource{Ring: s.ring},
		ExpectedIssuer: s.Issuer,
		Now:            time.Now().UTC(),
	})
	if err != nil {
		s.logTokenEvent(r, "token_introspected", map[string]any{"active": false, "reason": "error"})
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "verification failed")
		return
	}

	attrs := map[string]any{"active": verdict.Valid}
	if !verdict.Valid {
		attrs["reason"] = string(verdict.Reason)
	}
	s.logTokenEvent(r, "token_introspected", attrs)

	if !verdict.Valid {
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}

	response := make(map[string]any, len(verdict.Claims)+2)
	for key, value := range verdict.Claims {
		response[key] = value
	}
	response["active"] = true
	response["token_type"] = "Bearer"
	writeJSON(w, http.StatusOK, response)
}

// handleOAuthToken mints a legacy v2 OAuth-style JWT.
//
//	@ID			mintOAuthV2Token
//	@Tags		Tokens
//	@Summary	Mint a legacy v2 OAuth-style JWT
//	@Description	Legacy bespoke endpoint retained for compatibility. Discovery advertises /oauth/token instead; use this route only when the v2 claim profile is required. Mints a signed v2 token using X-Client-Id and the comma-separated Scope query parameter. Requested scopes are copied into the token's capabilities claim. The JWT also includes sub, aud, idtyp, allowedResources, version, client_id, and the standard iss, iat, nbf, exp, and jti claims.
//	@Param		X-Client-Id	header	string	true	"Client identifier" example(client-id)
//	@Param		X-Client-Secret	header	string	false	"Accepted for request compatibility but not validated by this test issuer"
//	@Param		Scope	query	string	true	"Comma-separated capabilities to place in the token" example(capability1,capability2)
//	@Param		alg	query	string	false	"Enabled signing algorithm; defaults to RS256 when enabled, else the first enabled algorithm" enum(RS256,ES256,EdDSA) example(ES256)
//	@Param		ttl	query	string	false	"Non-negative Go duration capped by MAX_TTL" example(5m)
//	@Success	200	{object}	TokenResponse	"Token minted successfully"
//	@Failure	400	{object}	ErrorResponse	"Missing client ID or scope"
//	@Failure	405	{object}	ErrorResponse	"Method not allowed"
//	@Failure	429	{object}	ErrorResponse	"Rate limit exceeded"
//	@Failure	503	{object}	ErrorResponse	"No active signing key available"
//	@Router	/v2/oauth/token [post]
func (s *Server) handleOAuthToken(w http.ResponseWriter, r *http.Request) {
	clientID := strings.TrimSpace(r.Header.Get("X-Client-Id"))
	if clientID == "" {
		writeError(w, http.StatusBadRequest, "X-Client-Id is required")
		return
	}

	capabilities := oauthCapabilities(r)
	if len(capabilities) == 0 {
		writeError(w, http.StatusBadRequest, "Scope is required")
		return
	}

	alg, err := s.selectAlgorithm(r.URL.Query().Get("alg"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ttl, ttlSet, err := s.selectTTL(r.URL.Query().Get("ttl"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	jti, err := generateJTI()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not generate token ID")
		return
	}

	claims := map[string]any{
		"sub":          clientID,
		"aud":          "client",
		"capabilities": capabilities,
		"idtyp":        "app",
		"allowedResources": map[string]any{
			"allowedPartners": []string{"partner"},
		},
		"version":   "2.0",
		"jti":       jti,
		"client_id": clientID,
	}
	if ttlSet {
		claims["exp"] = ttl.String()
	}
	resp, err := s.Factory.Mint(&tokenfactory.Request{Claims: claims, Alg: string(alg)})
	if err != nil {
		s.logTokenEvent(r, "token_mint_failed", map[string]any{"error": err.Error()})
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

	kid := ""
	if signer, signerErr := s.ring.Signer(alg); signerErr == nil && signer != nil {
		kid = signer.Kid()
	}
	s.logTokenEvent(r, "token_minted", map[string]any{
		"alg":        string(alg),
		"kid":        kid,
		"expires_in": resp.ExpiresIn,
	})
	writeJSON(w, http.StatusOK, resp)
}

func oauthCapabilities(r *http.Request) []string {
	var capabilities []string
	for key, values := range r.URL.Query() {
		if !strings.EqualFold(strings.TrimSpace(key), "scope") {
			continue
		}
		for _, value := range values {
			for _, capability := range strings.Split(value, ",") {
				if capability = strings.TrimSpace(capability); capability != "" {
					capabilities = append(capabilities, capability)
				}
			}
		}
	}
	return capabilities
}

func generateJTI() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	bytes[6] = (bytes[6] & 0x0f) | 0x40
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(bytes)
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:]), nil
}

func (s *Server) logTokenEvent(r *http.Request, event string, attrs map[string]any) {
	requestID := getRequestID(r)
	ip := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ip = strings.Split(forwarded, ",")[0]
	}

	args := []any{
		"event", event,
		"request_id", requestID,
		"client_ip", strings.TrimSpace(ip),
		"method", r.Method,
		"path", r.URL.Path,
	}
	for k, v := range attrs {
		args = append(args, k, v)
	}
	logger := s.logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.Info("token_audit", args...)
}

func requestedControl(req tokenfactory.Request) string {
	if req.Corrupt != "" {
		return req.Corrupt
	}
	if req.DuplicateClaim != "" {
		return "duplicate_claims"
	}
	if req.Alg == "none" {
		return "none"
	}
	if req.KID != "" {
		return "kid_override"
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
