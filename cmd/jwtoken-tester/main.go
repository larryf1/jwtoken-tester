package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/larryf1/jwtoken-tester/internal/keyring"
	"github.com/larryf1/jwtoken-tester/internal/server"
	"github.com/larryf1/jwtoken-tester/internal/tokenfactory"
)

var Version string

type serveConfig struct {
	Listen         string
	Issuer         string
	DefaultTTL     time.Duration
	MaxTTL         time.Duration
	RotationPeriod time.Duration
	GracePeriod    time.Duration
	Algorithms     string
	RateLimitRPS   float64
	RateLimitBurst int
}

type printTokenConfig struct {
	Issuer     string
	DefaultTTL time.Duration
	MaxTTL     time.Duration
	Algorithms string
	Claims     string
	Alg        string
	Headers    string
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		runServe(logger, os.Args[2:])
	case "print-token":
		runPrintToken(logger, os.Args[2:])
	case "healthcheck":
		runHealthcheck(os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
	default:
		_, err := fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		if err != nil {
			return
		}
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`jwtoken-tester - ephemeral JWT/JWKS test issuer

Usage:
  jwtoken-tester <command> [flags]

Commands:
  serve         Run the HTTP server (default)
  print-token   Generate a single JWT and print it to stdout
  healthcheck   Probe the local server's health endpoint
  help          Show this help

Examples:
  jwtoken-tester serve
  jwtoken-tester serve --listen 0.0.0.0:8080 --issuer https://test.example.com
  jwtoken-tester print-token --sub user-123 --aud my-service --alg RS256
  jwtoken-tester print-token --claims '{"sub":"user-1","roles":["admin"]}'`)
}

func runServe(logger *slog.Logger, args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)

	cfg := serveConfig{
		Listen:         envStr("LISTEN", "127.0.0.1:8080"),
		Issuer:         envStr("ISSUER", "http://127.0.0.1:8080"),
		DefaultTTL:     envDur("DEFAULT_TTL", time.Hour),
		MaxTTL:         envDur("MAX_TTL", 24*time.Hour),
		RotationPeriod: envDur("ROTATION_INTERVAL", 30*time.Minute),
		GracePeriod:    envDur("GRACE_PERIOD", 25*time.Hour),
		Algorithms:     envStr("ALGORITHMS", "RS256,ES256,EdDSA"),
		RateLimitRPS:   envFloat("RATE_LIMIT_RPS", 100),
		RateLimitBurst: envInt("RATE_LIMIT_BURST", 200),
	}

	Version = resolveVersion()

	fs.StringVar(&cfg.Listen, "listen", cfg.Listen, "address to bind (env LISTEN)")
	fs.StringVar(&cfg.Issuer, "issuer", cfg.Issuer, "external issuer / base URL (env ISSUER)")
	fs.DurationVar(&cfg.DefaultTTL, "default-ttl", cfg.DefaultTTL, "lifetime when exp omitted (env DEFAULT_TTL)")
	fs.DurationVar(&cfg.MaxTTL, "max-ttl", cfg.MaxTTL, "maximum token lifetime, 0 disables cap (env MAX_TTL)")
	fs.DurationVar(&cfg.RotationPeriod, "rotation-interval", cfg.RotationPeriod, "key rotation cadence, 0 disables (env ROTATION_INTERVAL)")
	fs.DurationVar(&cfg.GracePeriod, "grace-period", cfg.GracePeriod, "retired keys stay published this long (env GRACE_PERIOD)")
	fs.StringVar(&cfg.Algorithms, "algorithms", cfg.Algorithms, "comma-separated algorithms to enable: RS256,ES256,EdDSA (env ALGORITHMS)")
	fs.Float64Var(&cfg.RateLimitRPS, "rate-limit-rps", cfg.RateLimitRPS, "requests per second per IP (env RATE_LIMIT_RPS)")
	fs.IntVar(&cfg.RateLimitBurst, "rate-limit-burst", cfg.RateLimitBurst, "burst allowance per IP (env RATE_LIMIT_BURST)")

	if err := fs.Parse(args); err != nil {
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	enabledAlgs := parseAlgorithms(cfg.Algorithms)
	ring, err := keyring.New(cfg.GracePeriod, enabledAlgs)
	if err != nil {
		logger.Error("initializing key ring", "error", err)
		os.Exit(1)
	}
	ring.StartRotation(ctx, cfg.RotationPeriod, logger)

	factory := tokenfactory.NewFactory(ring, cfg.Issuer, cfg.DefaultTTL, cfg.MaxTTL)
	srv := server.New(ring, factory, cfg.Issuer, Version, cfg.RateLimitRPS, cfg.RateLimitBurst)
	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		logger.Info("jwtoken-tester listening",
			"addr", cfg.Listen,
			"issuer", cfg.Issuer,
			"default_ttl", cfg.DefaultTTL.String(),
			"max_ttl", cfg.MaxTTL.String(),
			"algorithms", cfg.Algorithms,
			"rate_limit_rps", cfg.RateLimitRPS,
			"rate_limit_burst", cfg.RateLimitBurst,
		)
		logger.Warn("TEST ISSUER ONLY: keys are generated in memory and never persisted; do not expose to production traffic")
		warnIfRemoteBind(logger, cfg.Listen)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server exited unexpectedly", "error", err)
			stop()
		}
	}()

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
	}
	logger.Info("stopped; ephemeral signing keys discarded")
}

// resolveVersion returns the version baked in at build time. Builds without
// -ldflags fall back to the Semrel-maintained VERSION file, then to Go build
// metadata. It never returns a "dev" placeholder.
func resolveVersion() string {
	if v := strings.TrimSpace(Version); v != "" && v != "dev" {
		return v
	}
	if versionBytes, err := os.ReadFile("VERSION"); err == nil {
		if v := strings.TrimSpace(string(versionBytes)); v != "" {
			return v
		}
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := strings.TrimPrefix(info.Main.Version, "v"); v != "" && v != "(devel)" {
			return v
		}
		if revision := vcsRevision(info); revision != "" {
			return "0.0.0-" + revision
		}
	}
	return "0.0.0-unknown"
}

func vcsRevision(info *debug.BuildInfo) string {
	var revision string
	var modified bool
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			modified = setting.Value == "true"
		}
	}
	if revision == "" {
		return ""
	}
	if len(revision) > 7 {
		revision = revision[:7]
	}
	if modified {
		revision += "-dirty"
	}
	return revision
}

func runPrintToken(logger *slog.Logger, args []string) {
	fs := flag.NewFlagSet("print-token", flag.ExitOnError)

	cfg := printTokenConfig{
		Issuer:     envStr("ISSUER", "http://127.0.0.1:8080"),
		DefaultTTL: envDur("DEFAULT_TTL", time.Hour),
		MaxTTL:     envDur("MAX_TTL", 24*time.Hour),
		Algorithms: envStr("ALGORITHMS", "RS256,ES256,EdDSA"),
	}

	fs.StringVar(&cfg.Issuer, "issuer", cfg.Issuer, "issuer URL for token (env ISSUER)")
	fs.DurationVar(&cfg.DefaultTTL, "default-ttl", cfg.DefaultTTL, "default token lifetime (env DEFAULT_TTL)")
	fs.DurationVar(&cfg.MaxTTL, "max-ttl", cfg.MaxTTL, "maximum token lifetime, 0 disables cap (env MAX_TTL)")
	fs.StringVar(&cfg.Algorithms, "algorithms", cfg.Algorithms, "comma-separated algorithms to enable (env ALGORITHMS)")
	fs.StringVar(&cfg.Claims, "claims", "", `JSON object with custom claims (e.g. '{"sub":"user-1","roles":["admin"]}')`)
	fs.StringVar(&cfg.Alg, "alg", "RS256", "signing algorithm: RS256, ES256, EdDSA")
	fs.StringVar(&cfg.Headers, "headers", "", `JSON object with extra JOSE headers`)

	if err := fs.Parse(args); err != nil {
		return
	}

	enabledAlgs := parseAlgorithms(cfg.Algorithms)
	if len(enabledAlgs) == 0 {
		logger.Error("no algorithms enabled")
		os.Exit(1)
	}

	ring, err := keyring.New(cfg.MaxTTL, enabledAlgs)
	if err != nil {
		logger.Error("initializing key ring", "error", err)
		os.Exit(1)
	}

	factory := tokenfactory.NewFactory(ring, cfg.Issuer, cfg.DefaultTTL, cfg.MaxTTL)

	var claims map[string]any
	if cfg.Claims != "" {
		if err := json.Unmarshal([]byte(cfg.Claims), &claims); err != nil {
			logger.Error("parsing claims", "error", err)
			os.Exit(1)
		}
	}

	var headers map[string]any
	if cfg.Headers != "" {
		if err := json.Unmarshal([]byte(cfg.Headers), &headers); err != nil {
			logger.Error("parsing headers", "error", err)
			os.Exit(1)
		}
	}

	resp, err := factory.Mint(&tokenfactory.Request{
		Claims:  claims,
		Alg:     cfg.Alg,
		Headers: headers,
	})
	if err != nil {
		logger.Error("minting token", "error", err)
		os.Exit(1)
	}

	fmt.Println(resp.AccessToken)
}

// runHealthcheck probes the local /healthz endpoint. It exists so a container
// healthcheck can use the statically linked binary instead of requiring curl or
// wget, which distroless images do not provide.
func runHealthcheck(args []string) {
	fs := flag.NewFlagSet("healthcheck", flag.ExitOnError)

	url := fs.String("url", "", "health endpoint URL (default derived from LISTEN)")
	timeout := fs.Duration("timeout", 3*time.Second, "probe timeout")

	if err := fs.Parse(args); err != nil {
		return
	}

	target := *url
	if target == "" {
		target = healthcheckURL(envStr("LISTEN", "127.0.0.1:8080"))
	}

	client := &http.Client{Timeout: *timeout}
	resp, err := client.Get(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthcheck: %s returned %s\n", target, resp.Status)
		os.Exit(1)
	}
}

func healthcheckURL(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "http://127.0.0.1:8080/healthz"
	}
	switch host {
	case "", "0.0.0.0", "::":
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/healthz"
}

func envStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envDur(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

func envFloat(key string, def float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return def
	}
	return f
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return i
}

func parseAlgorithms(s string) []keyring.Algorithm {
	var algs []keyring.Algorithm
	for _, part := range strings.Split(s, ",") {
		alg := strings.TrimSpace(part)
		if alg == "" {
			continue
		}
		algs = append(algs, keyring.Algorithm(alg))
	}
	return algs
}

func warnIfRemoteBind(logger *slog.Logger, addr string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	switch host {
	case "", "localhost", "127.0.0.1", "::1":
		return
	}
	logger.Warn("binding a non-loopback address exposes this test issuer on the network", "host", host)
}
