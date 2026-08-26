package main

import (
	"context"
	"crypto"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v4/jwk"
)

type config struct {
	Port         string
	IssuerURL    string
	JWKSURL      string
	AllowedAud   string
	RefreshEvery time.Duration
}

type keyCache struct {
	mu      sync.RWMutex
	keys    map[string]crypto.PublicKey
	fetched time.Time
	jwksURL string
	refresh time.Duration
	client  *http.Client
}

func newKeyCache(jwksURL string, refresh time.Duration) *keyCache {
	return &keyCache{
		keys:    make(map[string]crypto.PublicKey),
		jwksURL: jwksURL,
		refresh: refresh,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *keyCache) getKey(kid string) (crypto.PublicKey, error) {
	c.mu.RLock()
	key, ok := c.keys[kid]
	fetched := c.fetched
	c.mu.RUnlock()

	if ok && time.Since(fetched) < c.refresh {
		return key, nil
	}

	// Refresh cache
	return c.refreshAndGet(kid)
}

func (c *keyCache) refreshAndGet(kid string) (crypto.PublicKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.jwksURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, jwt.ErrSignatureInvalid
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	set, err := jwk.Parse(body)
	if err != nil {
		return nil, err
	}

	newKeys := make(map[string]crypto.PublicKey)
	for idx, key := range set.All() {
		_ = idx
		keyID, _ := key.KeyID()
		// Export the public key from the JWK
		var rawKey crypto.PublicKey
		pubKey, err := key.PublicKey()
		if err != nil {
			continue
		}
		rawKey, err = jwk.Export[crypto.PublicKey](pubKey)
		if err != nil {
			continue
		}
		newKeys[keyID] = rawKey
	}

	c.mu.Lock()
	c.keys = newKeys
	c.fetched = time.Now()
	c.mu.Unlock()

	key, ok := newKeys[kid]
	if !ok {
		return nil, jwt.ErrSignatureInvalid
	}
	return key, nil
}

func main() {
	cfg := config{
		Port:         getEnv("PORT", "8081"),
		IssuerURL:    getEnv("ISSUER_URL", "http://jwtoken-tester:8080"),
		JWKSURL:      getEnv("JWKS_URL", "http://jwtoken-tester:8080/.well-known/jwks.json"),
		AllowedAud:   getEnv("ALLOWED_AUD", "demo-service"),
		RefreshEvery: getEnvDuration("JWKS_REFRESH", 5*time.Minute),
	}

	log.Printf("Starting demo protected service on :%s", cfg.Port)
	log.Printf("Using issuer: %s", cfg.IssuerURL)
	log.Printf("Using JWKS: %s", cfg.JWKSURL)
	log.Printf("Allowed audience: %s", cfg.AllowedAud)

	keyCache := newKeyCache(cfg.JWKSURL, cfg.RefreshEvery)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"service": "demo-protected-service",
		})
	})

	mux.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			http.Error(w, "Invalid Authorization format", http.StatusUnauthorized)
			return
		}
		tokenString := parts[1]

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
					if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
						return nil, jwt.ErrSignatureInvalid
					}
				}
			}

			kid, ok := token.Header["kid"].(string)
			if !ok {
				return nil, jwt.ErrSignatureInvalid
			}

			return keyCache.getKey(kid)
		}, jwt.WithValidMethods([]string{"RS256", "ES256", "EdDSA"}), jwt.WithIssuer(cfg.IssuerURL), jwt.WithAudience(cfg.AllowedAud))

		if err != nil {
			log.Printf("Token validation failed: %v", err)
			http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
			return
		}

		if !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		claims := token.Claims.(jwt.MapClaims)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"message": "Access granted",
			"claims":  claims,
		})
	})

	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Shutdown error: %v", err)
		}
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed: %v", err)
	}
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getEnvDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
