package tester

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"jwtoken-tester/internal/keyring"
	"jwtoken-tester/internal/server"
	"jwtoken-tester/internal/tokenfactory"
)

type Server struct {
	ts      *httptest.Server
	ring    *keyring.KeyRing
	factory *tokenfactory.Factory
	issuer  string
}

type TestingT interface {
	Helper()
	Cleanup(func())
	Fatalf(format string, args ...any)
}

func NewServer(t TestingT, opts ...Option) (*Server, string) {
	t.Helper()

	cfg := defaultConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	ring, err := keyring.New(cfg.gracePeriod, cfg.algorithms)
	if err != nil {
		t.Fatalf("keyring.New() error = %v", err)
	}

	var issuer string
	useAutoIssuer := cfg.issuer == "http://127.0.0.1:8080"
	if !useAutoIssuer {
		issuer = cfg.issuer
	}

	// Create server with a placeholder issuer first to get the URL
	factory := tokenfactory.NewFactory(ring, issuer, cfg.defaultTTL, cfg.maxTTL)
	srv := server.New(ring, factory, issuer)
	handler := srv.Handler()

	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	// If auto-issuer, use the test server's URL as issuer
	// Update both the internal server's issuer and recreate factory
	if useAutoIssuer {
		issuer = ts.URL
		srv.Issuer = issuer
		factory = tokenfactory.NewFactory(ring, issuer, cfg.defaultTTL, cfg.maxTTL)
		srv.Factory = factory
	}

	s := &Server{
		ts:      ts,
		ring:    ring,
		factory: factory,
		issuer:  issuer,
	}

	if cfg.rotationInterval > 0 {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
		ring.StartRotation(ctx, cfg.rotationInterval, logger)
	}

	return s, ts.URL
}

func (s *Server) URL() string {
	return s.ts.URL
}

func (s *Server) TokenFactory() *tokenfactory.Factory {
	return s.factory
}

func (s *Server) KeyRing() *keyring.KeyRing {
	return s.ring
}

func (s *Server) Issuer() string {
	return s.issuer
}

func (s *Server) Client() *http.Client {
	return s.ts.Client()
}

func (s *Server) Close() {
	s.ts.Close()
}

type config struct {
	issuer           string
	defaultTTL       time.Duration
	maxTTL           time.Duration
	rotationInterval time.Duration
	gracePeriod      time.Duration
	algorithms       []keyring.Algorithm
}

func defaultConfig() *config {
	return &config{
		issuer:           "http://127.0.0.1:8080",
		defaultTTL:       time.Hour,
		maxTTL:           24 * time.Hour,
		rotationInterval: 0,
		gracePeriod:      25 * time.Hour,
		algorithms:       []keyring.Algorithm{keyring.AlgRS256, keyring.AlgES256, keyring.AlgEdDSA},
	}
}

type Option func(*config)

func WithIssuer(issuer string) Option {
	return func(c *config) {
		c.issuer = issuer
	}
}

func WithDefaultTTL(ttl time.Duration) Option {
	return func(c *config) {
		c.defaultTTL = ttl
	}
}

func WithMaxTTL(ttl time.Duration) Option {
	return func(c *config) {
		c.maxTTL = ttl
	}
}

func WithRotationInterval(interval time.Duration) Option {
	return func(c *config) {
		c.rotationInterval = interval
	}
}

func WithGracePeriod(grace time.Duration) Option {
	return func(c *config) {
		c.gracePeriod = grace
	}
}

func WithAlgorithms(algs ...keyring.Algorithm) Option {
	return func(c *config) {
		c.algorithms = algs
	}
}
