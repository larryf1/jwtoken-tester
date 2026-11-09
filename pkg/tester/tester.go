// Package tester provides an in-process JWT issuer for tests. It starts an
// httptest server that publishes discovery and JWKS documents, and it can mint
// signed tokens without exposing private key material or internal types.
package tester

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"github.com/larryf1/jwtoken-tester/v2/internal/keyring"
	"github.com/larryf1/jwtoken-tester/v2/internal/server"
	"github.com/larryf1/jwtoken-tester/v2/internal/tokenfactory"
)

// Algorithm identifies a supported signing algorithm.
type Algorithm string

const (
	// RS256 signs with RSA PKCS#1 v1.5 and SHA-256.
	RS256 Algorithm = "RS256"
	// ES256 signs with ECDSA P-256 and SHA-256.
	ES256 Algorithm = "ES256"
	// EdDSA signs with Ed25519.
	EdDSA Algorithm = "EdDSA"
	RS384 Algorithm = "RS384"
	RS512 Algorithm = "RS512"
	PS256 Algorithm = "PS256"
	PS384 Algorithm = "PS384"
	PS512 Algorithm = "PS512"
	ES384 Algorithm = "ES384"
	ES512 Algorithm = "ES512"
	HS256 Algorithm = "HS256"
	None  Algorithm = "none"
)

var (
	// ErrUnsupportedAlgorithm reports an algorithm that is not enabled.
	ErrUnsupportedAlgorithm = errors.New("tester: unsupported algorithm")
	// ErrTTLTooLong reports a requested lifetime above the configured maximum.
	ErrTTLTooLong = errors.New("tester: requested lifetime exceeds maximum allowed")
	// ErrInvalidRequest reports malformed claims or headers.
	ErrInvalidRequest = errors.New("tester: invalid token request")
	// ErrKeyNotFound reports an unknown or pruned key ID.
	ErrKeyNotFound = errors.New("tester: key not found")
)

var supportedAlgorithms = []Algorithm{RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA}

// MintRequest describes a token to mint.
type MintRequest struct {
	// Claims are added to the token payload. Omitted exp, iat, nbf, and iss
	// claims are filled in from the server configuration.
	Claims map[string]any
	// Algorithm selects the signing algorithm. The zero value selects RS256.
	Algorithm Algorithm
	// Headers are added to the protected JOSE header.
	Headers        map[string]any
	KID            string
	Typ            string
	CTY            string
	Corrupt        string
	DuplicateClaim string
}

// Token is a minted bearer token.
type Token struct {
	AccessToken string
	TokenType   string
	ExpiresIn   time.Duration
}

// KeyInfo describes a key published by the issuer. Retired keys remain listed
// until the grace period elapses and they are pruned.
type KeyInfo struct {
	KID       string
	Algorithm Algorithm
	CreatedAt time.Time
	RetiredAt time.Time
	Retired   bool
}

// TestingT is the subset of testing.TB used by NewServer.
type TestingT interface {
	Helper()
	Cleanup(func())
}

// Server is a running in-process issuer. The caller owns it and must call
// Close to release the listener and background goroutines.
type Server struct {
	ts             *httptest.Server
	ring           *keyring.KeyRing
	factory        *tokenfactory.Factory
	internal       *server.Server
	handler        http.Handler
	issuer         string
	negativeTokens bool

	cancel       context.CancelFunc
	rotationDone <-chan struct{}
	closeOnce    sync.Once
}

// Start starts an in-process issuer. The returned server must be closed by the
// caller. When no issuer option is supplied, the bound server URL is used as
// the issuer.
func Start(opts ...Option) (*Server, error) {
	cfg := defaultConfig()
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}

	algorithms, err := internalAlgorithms(cfg.algorithms)
	if err != nil {
		return nil, err
	}

	ring, err := keyring.New(cfg.gracePeriod, algorithms, keyring.WithRSABits(cfg.rsaBits))
	if err != nil {
		return nil, fmt.Errorf("tester: initialize key ring: %w", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("tester: listen: %w", err)
	}

	ts := httptest.NewUnstartedServer(nil)
	ts.Listener = listener
	issuer := cfg.issuer
	if issuer == "" {
		issuer = "http://" + listener.Addr().String()
	}

	factory := tokenfactory.NewFactory(ring, issuer, cfg.defaultTTL, cfg.maxTTL)
	if len(cfg.hmacSecret) > 0 {
		factory.SetHMACSecret(cfg.hmacSecret)
	}
	internal := server.New(ring, factory, issuer, "test-version", cfg.rateLimitRPS, cfg.rateLimitBurst,
		server.WithLogger(cfg.logger),
		server.WithAudience(cfg.audience),
		server.WithScopes(cfg.scopes),
		server.WithDiscoveryExtra(cfg.discoveryExtra),
		server.WithAllowNegativeTokens(cfg.negativeTokens),
	)
	ts.Config.Handler = internal.Handler()

	ctx, cancel := context.WithCancel(context.Background())
	rotationDone := ring.StartRotation(ctx, cfg.rotationInterval, cfg.logger)

	ts.Start()

	return &Server{
		ts:             ts,
		ring:           ring,
		factory:        factory,
		internal:       internal,
		handler:        ts.Config.Handler,
		issuer:         issuer,
		negativeTokens: cfg.negativeTokens,
		cancel:         cancel,
		rotationDone:   rotationDone,
	}, nil
}

// NewServer starts an issuer for a test, registers cleanup on t, and returns
// the server. It panics if startup fails.
func NewServer(t TestingT, opts ...Option) *Server {
	t.Helper()
	s, err := Start(opts...)
	if err != nil {
		panic(fmt.Sprintf("tester.NewServer: %v", err))
	}
	t.Cleanup(s.Close)
	return s
}

// URL returns the base URL of the running server.
func (s *Server) URL() string {
	return s.ts.URL
}

// Issuer returns the effective issuer URL used in tokens and discovery.
func (s *Server) Issuer() string {
	return s.issuer
}

// Client returns the HTTP client bound to the test server.
func (s *Server) Client() *http.Client {
	return s.ts.Client()
}

// Handler returns the HTTP handler served by the issuer.
func (s *Server) Handler() http.Handler {
	return s.handler
}

// Mint signs a token described by req.
func (s *Server) Mint(req MintRequest) (*Token, error) {
	resp, err := s.factory.Mint(&tokenfactory.Request{
		Claims:  req.Claims,
		Alg:     string(req.Algorithm),
		Headers: req.Headers,
		KID:     req.KID, Typ: req.Typ, CTY: req.CTY, Corrupt: req.Corrupt, DuplicateClaim: req.DuplicateClaim, AllowNegative: s.negativeTokens,
	})
	if err != nil {
		return nil, mapMintError(err)
	}
	return &Token{
		AccessToken: resp.AccessToken,
		TokenType:   resp.TokenType,
		ExpiresIn:   time.Duration(resp.ExpiresIn) * time.Second,
	}, nil
}

// Keys returns the active and retired keys ordered by key ID. The result is a
// snapshot; later rotation does not mutate it.
func (s *Server) Keys() []KeyInfo {
	snapshot := s.ring.Snapshot()
	keys := make([]KeyInfo, 0, len(snapshot))
	for _, k := range snapshot {
		keys = append(keys, KeyInfo{
			KID:       k.Kid(),
			Algorithm: Algorithm(k.Algorithm),
			CreatedAt: k.CreatedAt,
			RetiredAt: k.RetiredAt,
			Retired:   !k.RetiredAt.IsZero(),
		})
	}
	return keys
}

// ActiveKeyID returns the key ID currently used to sign alg.
func (s *Server) ActiveKeyID(alg Algorithm) (string, error) {
	kid, err := s.ring.ActiveKid(keyring.Algorithm(alg))
	if err != nil {
		return "", mapKeyError(err)
	}
	return kid, nil
}

// PublicKey returns the public key with the given key ID.
func (s *Server) PublicKey(kid string) (crypto.PublicKey, error) {
	public, err := s.ring.PublicKeyByKID(kid)
	if err != nil {
		return nil, mapKeyError(err)
	}
	return public, nil
}

// PublicKeyPEM returns the PKIX-encoded ("PUBLIC KEY") PEM form of the public
// key with the given key ID.
func (s *Server) PublicKeyPEM(kid string) ([]byte, error) {
	public, err := s.PublicKey(kid)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return nil, fmt.Errorf("tester: marshal public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// JWKSJSON returns the active and retired public keys as compact JSON, ordered
// by key ID.
func (s *Server) JWKSJSON() ([]byte, error) {
	set, err := s.ring.JWKS()
	if err != nil {
		return nil, fmt.Errorf("tester: build JWKS: %w", err)
	}
	data, err := json.Marshal(set)
	if err != nil {
		return nil, fmt.Errorf("tester: marshal JWKS: %w", err)
	}
	return data, nil
}

// Rotate replaces the active key for every enabled algorithm. Previous keys
// remain published until the grace period elapses.
func (s *Server) Rotate() error {
	if err := s.ring.Rotate(); err != nil {
		return fmt.Errorf("tester: rotate keys: %w", err)
	}
	return nil
}

// PruneAt drops retired keys whose grace period elapsed at now.
func (s *Server) PruneAt(now time.Time) {
	s.ring.PruneAt(now)
}

// Close stops the listener, cancels key rotation, stops internal cleanup, and
// waits for those goroutines. It is idempotent and safe to call concurrently.
// Mint and the key accessors continue to work because they use in-memory state.
func (s *Server) Close() {
	s.closeOnce.Do(func() {
		s.ts.Close()
		s.cancel()
		<-s.rotationDone
		s.internal.Close()
	})
}

func internalAlgorithms(algs []Algorithm) ([]keyring.Algorithm, error) {
	if len(algs) == 0 {
		return nil, fmt.Errorf("%w: at least one algorithm must be enabled", ErrUnsupportedAlgorithm)
	}
	internal := make([]keyring.Algorithm, 0, len(algs))
	for _, alg := range algs {
		if !isSupported(alg) {
			return nil, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, alg)
		}
		internal = append(internal, keyring.Algorithm(alg))
	}
	return internal, nil
}

func isSupported(alg Algorithm) bool {
	for _, supported := range supportedAlgorithms {
		if alg == supported {
			return true
		}
	}
	return false
}

func mapMintError(err error) error {
	switch {
	case errors.Is(err, tokenfactory.ErrUnsupportedAlg), errors.Is(err, keyring.ErrUnsupportedAlg):
		return fmt.Errorf("%w: %v", ErrUnsupportedAlgorithm, err)
	case errors.Is(err, tokenfactory.ErrTTLTooLong):
		return fmt.Errorf("%w: %v", ErrTTLTooLong, err)
	case errors.Is(err, tokenfactory.ErrInvalidRequest):
		return fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	case errors.Is(err, tokenfactory.ErrNegativeDisabled):
		return fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	case errors.Is(err, keyring.ErrKeyNotFound):
		return fmt.Errorf("%w: %v", ErrKeyNotFound, err)
	default:
		return err
	}
}

func mapKeyError(err error) error {
	switch {
	case errors.Is(err, keyring.ErrKeyNotFound):
		return fmt.Errorf("%w: %v", ErrKeyNotFound, err)
	case errors.Is(err, keyring.ErrUnsupportedAlg):
		return fmt.Errorf("%w: %v", ErrUnsupportedAlgorithm, err)
	default:
		return err
	}
}

type config struct {
	issuer           string
	defaultTTL       time.Duration
	maxTTL           time.Duration
	rotationInterval time.Duration
	gracePeriod      time.Duration
	algorithms       []Algorithm
	rateLimitRPS     float64
	rateLimitBurst   int
	logger           *slog.Logger
	audience         string
	scopes           []string
	discoveryExtra   map[string]any
	rsaBits          int
	hmacSecret       []byte
	negativeTokens   bool
}

func defaultConfig() *config {
	return &config{
		defaultTTL:       time.Hour,
		maxTTL:           24 * time.Hour,
		rotationInterval: 0,
		gracePeriod:      25 * time.Hour,
		algorithms:       []Algorithm{RS256, ES256, EdDSA},
		rateLimitRPS:     100,
		rateLimitBurst:   200,
		logger:           slog.New(slog.DiscardHandler),
		rsaBits:          2048,
	}
}

// Option configures Start and NewServer.
type Option func(*config)

// WithIssuer sets the issuer claim and discovery base URL. An empty value
// selects the bound server URL, which is also the default.
func WithIssuer(issuer string) Option {
	return func(c *config) {
		c.issuer = issuer
	}
}

// WithDefaultTTL sets the lifetime used when a request omits exp.
func WithDefaultTTL(ttl time.Duration) Option {
	return func(c *config) {
		c.defaultTTL = ttl
	}
}

// WithMaxTTL sets the maximum allowed token lifetime. A non-positive value
// disables the cap.
func WithMaxTTL(ttl time.Duration) Option {
	return func(c *config) {
		c.maxTTL = ttl
	}
}

// WithRotationInterval sets how often keys rotate. A non-positive value
// disables rotation, which is the default.
func WithRotationInterval(interval time.Duration) Option {
	return func(c *config) {
		c.rotationInterval = interval
	}
}

// WithGracePeriod sets how long retired keys remain published.
func WithGracePeriod(grace time.Duration) Option {
	return func(c *config) {
		c.gracePeriod = grace
	}
}

// WithAlgorithms sets the enabled signing algorithms.
func WithAlgorithms(algs ...Algorithm) Option {
	return func(c *config) {
		c.algorithms = algs
	}
}

// WithRSAKeyBits configures generated RSA key size; valid values are at least 1024.
func WithRSAKeyBits(bits int) Option { return func(c *config) { c.rsaBits = bits } }

// WithHMACSecret enables HS256 using an explicit secret of at least 32 bytes.
func WithHMACSecret(secret []byte) Option {
	return func(c *config) { c.hmacSecret = bytes.Clone(secret) }
}

// WithNegativeTokens enables unsigned and deliberately malformed Mint requests.
func WithNegativeTokens(enabled bool) Option { return func(c *config) { c.negativeTokens = enabled } }

// WithRateLimit sets the per-IP request rate and burst allowance. A
// non-positive rate or burst selects the 100 RPS / 200 burst default.
func WithRateLimit(rps float64, burst int) Option {
	return func(c *config) {
		c.rateLimitRPS = rps
		c.rateLimitBurst = burst
	}
}

// WithLogger routes issuer events to logger. By default the embedded issuer
// emits no log output.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) {
		if logger != nil {
			c.logger = logger
		}
	}
}

// WithAudience sets the aud claim placed on tokens minted by /oauth/token. An
// empty value omits the claim, which is the default.
func WithAudience(audience string) Option {
	return func(c *config) {
		c.audience = audience
	}
}

// WithScopes sets the scope names advertised as scopes_supported in discovery.
// It does not restrict scopes requested from /oauth/token.
func WithScopes(scopes ...string) Option {
	return func(c *config) {
		c.scopes = append([]string(nil), scopes...)
	}
}

// WithDiscoveryExtra merges extra metadata into both discovery documents.
// Derived core fields always win over the supplied values.
func WithDiscoveryExtra(extra map[string]any) Option {
	return func(c *config) {
		if extra == nil {
			c.discoveryExtra = nil
			return
		}
		c.discoveryExtra = make(map[string]any, len(extra))
		for key, value := range extra {
			c.discoveryExtra[key] = value
		}
	}
}
