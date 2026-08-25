package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"jwtoken-tester/internal/keyring"
	"jwtoken-tester/internal/server"
	"jwtoken-tester/internal/tokenfactory"
)

type config struct {
	Listen         string
	Issuer         string
	DefaultTTL     time.Duration
	MaxTTL         time.Duration
	RotationPeriod time.Duration
	GracePeriod    time.Duration
	Algorithms     string
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := loadConfig(logger)

	enabledAlgs := parseAlgorithms(cfg.Algorithms)
	ring, err := keyring.New(cfg.GracePeriod, enabledAlgs)
	if err != nil {
		logger.Error("initializing key ring", "error", err)
		os.Exit(1)
	}
	ring.StartRotation(ctx, cfg.RotationPeriod, logger)

	factory := tokenfactory.NewFactory(ring, cfg.Issuer, cfg.DefaultTTL, cfg.MaxTTL)
	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           server.New(ring, factory, cfg.Issuer).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		logger.Info("jwtoken-tester listening",
			"addr", cfg.Listen,
			"issuer", cfg.Issuer,
			"default_ttl", cfg.DefaultTTL.String(),
			"max_ttl", cfg.MaxTTL.String(),
			"algorithms", cfg.Algorithms,
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

func loadConfig(logger *slog.Logger) config {
	envStr := func(key, def string) string {
		if v := os.Getenv(key); v != "" {
			return v
		}
		return def
	}
	envDur := func(key string, def time.Duration) time.Duration {
		v := os.Getenv(key)
		if v == "" {
			return def
		}
		d, err := time.ParseDuration(v)
		if err != nil {
			logger.Warn("ignoring malformed env duration", "key", key, "value", v)
			return def
		}
		return d
	}

	cfg := config{
		Listen:         envStr("LISTEN", "127.0.0.1:8080"),
		Issuer:         envStr("ISSUER", "http://127.0.0.1:8080"),
		DefaultTTL:     envDur("DEFAULT_TTL", time.Hour),
		MaxTTL:         envDur("MAX_TTL", 24*time.Hour),
		RotationPeriod: envDur("ROTATION_INTERVAL", 30*time.Minute),
		GracePeriod:    envDur("GRACE_PERIOD", 25*time.Hour),
		Algorithms:     envStr("ALGORITHMS", "RS256,ES256,EdDSA"),
	}

	flag.StringVar(&cfg.Listen, "listen", cfg.Listen, "address to bind (env LISTEN)")
	flag.StringVar(&cfg.Issuer, "issuer", cfg.Issuer, "external issuer / base URL (env ISSUER)")
	flag.DurationVar(&cfg.DefaultTTL, "default-ttl", cfg.DefaultTTL, "lifetime when exp omitted (env DEFAULT_TTL)")
	flag.DurationVar(&cfg.MaxTTL, "max-ttl", cfg.MaxTTL, "maximum token lifetime, 0 disables cap (env MAX_TTL)")
	flag.DurationVar(&cfg.RotationPeriod, "rotation-interval", cfg.RotationPeriod, "key rotation cadence, 0 disables (env ROTATION_INTERVAL)")
	flag.DurationVar(&cfg.GracePeriod, "grace-period", cfg.GracePeriod, "retired keys stay published this long (env GRACE_PERIOD)")
	flag.StringVar(&cfg.Algorithms, "algorithms", cfg.Algorithms, "comma-separated algorithms to enable: RS256,ES256,EdDSA (env ALGORITHMS)")
	flag.Parse()

	return cfg
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
