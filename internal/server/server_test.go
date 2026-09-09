package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jwt5 "github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"

	"github.com/larryf1/jwtoken-tester/internal/keyring"
	"github.com/larryf1/jwtoken-tester/internal/tokenfactory"
)

const testIssuer = "http://127.0.0.1:8080"

func newTestServer(t *testing.T, algs ...keyring.Algorithm) (*httptest.Server, *keyring.KeyRing) {
	t.Helper()
	if len(algs) == 0 {
		algs = []keyring.Algorithm{keyring.AlgRS256}
	}
	ring, err := keyring.New(time.Hour, algs)
	if err != nil {
		t.Fatalf("keyring.New() error = %v", err)
	}
	factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
	ts := httptest.NewServer(New(ring, factory, testIssuer, "test-version").Handler())
	t.Cleanup(ts.Close)
	return ts, ring
}

func postJSON(t *testing.T, url, body string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp, data
}

func fetchJWKS(t *testing.T, url string) jwk.Set {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read jwks response: %v", err)
	}
	set, err := jwk.Parse(data)
	if err != nil {
		t.Fatalf("jwk.Parse: %v", err)
	}
	return set
}

func TestHealthEndpointReportsWarningAndActiveKid(t *testing.T) {
	for _, algs := range [][]keyring.Algorithm{
		{keyring.AlgRS256},
		{keyring.AlgES256},
		{keyring.AlgEdDSA},
		{keyring.AlgRS256, keyring.AlgES256, keyring.AlgEdDSA},
	} {
		t.Run(strings.Join(mapAlgorithms(algs), ","), func(t *testing.T) {
			ts, _ := newTestServer(t, algs...)

			resp, err := http.Get(ts.URL + "/healthz")
			if err != nil {
				t.Fatalf("GET /healthz: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			var doc map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
				t.Fatalf("decode health: %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			if status, _ := doc["status"].(string); status != "ok" {
				t.Fatalf("status = %v, want ok", doc["status"])
			}
			warning, _ := doc["warning"].(string)
			if !strings.Contains(strings.ToLower(warning), "test") {
				t.Fatalf("warning %q should mention test-only nature", warning)
			}
			algList, ok := doc["algorithms"].([]any)
			if !ok {
				t.Fatalf("algorithms missing: %#v", doc)
			}
			if len(algList) != len(algs) {
				t.Fatalf("algorithms = %v, want %v", algList, algs)
			}
			kids, ok := doc["active_kids"].(map[string]any)
			if !ok {
				t.Fatalf("active_kids missing: %#v", doc)
			}
			if len(kids) != len(algs) {
				t.Fatalf("active_kids = %v, want %d entries", kids, len(algs))
			}
		})
	}
}

func mapAlgorithms(algs []keyring.Algorithm) []string {
	result := make([]string, len(algs))
	for i, alg := range algs {
		result[i] = string(alg)
	}
	return result
}

func TestVersionEndpoint(t *testing.T) {
	ts, ring := newTestServer(t, keyring.AlgRS256)

	resp, err := http.Get(ts.URL + "/version")
	if err != nil {
		t.Fatalf("GET /version: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var doc map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode version: %v", err)
	}
	if doc["version"] != "test-version" {
		t.Fatalf("version = %q, want %q", doc["version"], "test-version")
	}

	// Also test handler directly
	s := New(ring, tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour), testIssuer, "test-version")
	req := httptest.NewRequest(http.MethodGet, "/version", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("direct handler status = %d, want 200", w.Code)
	}
}

func TestJWKByKIDEndpointErrors(t *testing.T) {
	ts, _ := newTestServer(t, keyring.AlgRS256)

	tests := []struct {
		name       string
		path       string
		wantStatus int
	}{
		{"missing kid", "/.well-known/jwks.json/", http.StatusBadRequest},
		{"unknown kid", "/.well-known/jwks.json/unknown-kid", http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := http.Get(ts.URL + tt.path)
			if err != nil {
				t.Fatalf("GET %s: %v", tt.path, err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}
		})
	}
}

func TestJWKSEndpointServesPublicKeys(t *testing.T) {
	ts, _ := newTestServer(t, keyring.AlgRS256, keyring.AlgES256, keyring.AlgEdDSA)
	set := fetchJWKS(t, ts.URL+"/.well-known/jwks.json")

	if set.Len() < 1 {
		t.Fatal("JWKS is empty")
	}
	for i := range set.Len() {
		key, _ := set.Key(i)
		kty := key.KeyType()
		if kty != jwa.RSA() && kty != jwa.EC() && kty != jwa.OKP() {
			t.Fatalf("key %d kty = %v, want RSA, EC, or OKP", i, kty)
		}
		if kid, _ := key.KeyID(); kid == "" {
			t.Fatalf("key %d missing kid", i)
		}
		if usage, _ := key.KeyUsage(); usage != string(jwk.ForSignature) {
			t.Fatalf("key %d use = %v, want sig", i, usage)
		}
	}
}

func TestJWKSEndpointServesRSAPublicKeys(t *testing.T) {
	ts, _ := newTestServer(t, keyring.AlgRS256)
	set := fetchJWKS(t, ts.URL+"/.well-known/jwks.json")

	if set.Len() != 1 {
		t.Fatalf("JWKS length = %d, want 1", set.Len())
	}
	for i := range set.Len() {
		key, _ := set.Key(i)
		if key.KeyType() != jwa.RSA() {
			t.Fatalf("key %d kty = %v, want RSA", i, key.KeyType())
		}
		if kid, _ := key.KeyID(); kid == "" {
			t.Fatalf("key %d missing kid", i)
		}
		if usage, _ := key.KeyUsage(); usage != string(jwk.ForSignature) {
			t.Fatalf("key %d use = %v, want sig", i, usage)
		}
	}
}

func TestJWKSEndpointServesECPublicKeys(t *testing.T) {
	ts, _ := newTestServer(t, keyring.AlgES256)
	set := fetchJWKS(t, ts.URL+"/.well-known/jwks.json")

	if set.Len() != 1 {
		t.Fatalf("JWKS length = %d, want 1", set.Len())
	}
	for i := range set.Len() {
		key, _ := set.Key(i)
		if key.KeyType() != jwa.EC() {
			t.Fatalf("key %d kty = %v, want EC", i, key.KeyType())
		}
		if kid, _ := key.KeyID(); kid == "" {
			t.Fatalf("key %d missing kid", i)
		}
		if usage, _ := key.KeyUsage(); usage != string(jwk.ForSignature) {
			t.Fatalf("key %d use = %v, want sig", i, usage)
		}
	}
}

func TestJWKSEndpointServesOKPPublicKeys(t *testing.T) {
	ts, _ := newTestServer(t, keyring.AlgEdDSA)
	set := fetchJWKS(t, ts.URL+"/.well-known/jwks.json")

	if set.Len() != 1 {
		t.Fatalf("JWKS length = %d, want 1", set.Len())
	}
	for i := range set.Len() {
		key, _ := set.Key(i)
		if key.KeyType() != jwa.OKP() {
			t.Fatalf("key %d kty = %v, want OKP", i, key.KeyType())
		}
		if kid, _ := key.KeyID(); kid == "" {
			t.Fatalf("key %d missing kid", i)
		}
		if usage, _ := key.KeyUsage(); usage != string(jwk.ForSignature) {
			t.Fatalf("key %d use = %v, want sig", i, usage)
		}
	}
}

func TestJWKByKIDEndpoint(t *testing.T) {
	ts, _ := newTestServer(t, keyring.AlgRS256, keyring.AlgES256, keyring.AlgEdDSA)
	set := fetchJWKS(t, ts.URL+"/.well-known/jwks.json")

	for i := range set.Len() {
		key, _ := set.Key(i)
		kid, _ := key.KeyID()

		resp, err := http.Get(ts.URL + "/.well-known/jwks.json/" + kid)
		if err != nil {
			t.Fatalf("GET jwk by kid: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		data, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		fetchedKey, err := jwk.ParseKey(data)
		if err != nil {
			t.Fatalf("jwk.ParseKey: %v", err)
		}

		fetchedKid, _ := fetchedKey.KeyID()
		if fetchedKid != kid {
			t.Fatalf("fetched key kid = %v, want %q", fetchedKid, kid)
		}
		if fetchedKey.KeyType() != key.KeyType() {
			t.Fatalf("fetched key kty = %v, want %v", fetchedKey.KeyType(), key.KeyType())
		}
	}
}

func TestJWKByKIDEndpointNotFound(t *testing.T) {
	ts, _ := newTestServer(t, keyring.AlgRS256)

	resp, err := http.Get(ts.URL + "/.well-known/jwks.json/nonexistent-kid")
	if err != nil {
		t.Fatalf("GET jwk by kid: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestJWKByKIDEndpointMissingKid(t *testing.T) {
	ts, _ := newTestServer(t, keyring.AlgRS256)

	resp, err := http.Get(ts.URL + "/.well-known/jwks.json/")
	if err != nil {
		t.Fatalf("GET jwk by kid: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestJWKByKIDEndpointIncludesRetiredKeys(t *testing.T) {
	ts, _ := newTestServer(t, keyring.AlgRS256)
	ring, _ := keyring.New(time.Hour, []keyring.Algorithm{keyring.AlgRS256})
	if err := ring.Rotate(); err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}

	set := fetchJWKS(t, ts.URL+"/.well-known/jwks.json")
	for i := range set.Len() {
		key, _ := set.Key(i)
		kid, _ := key.KeyID()

		resp, err := http.Get(ts.URL + "/.well-known/jwks.json/" + kid)
		if err != nil {
			t.Fatalf("GET jwk by kid: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		data, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		fetchedKey, err := jwk.ParseKey(data)
		if err != nil {
			t.Fatalf("jwk.ParseKey: %v", err)
		}

		fetchedKid, _ := fetchedKey.KeyID()
		if fetchedKid != kid {
			t.Fatalf("fetched key kid = %v, want %q", fetchedKid, kid)
		}
	}
}

func TestDiscoveryDocumentPointsAtIssuerAndJWKS(t *testing.T) {
	for _, algs := range [][]keyring.Algorithm{
		{keyring.AlgRS256},
		{keyring.AlgES256},
		{keyring.AlgEdDSA},
		{keyring.AlgRS256, keyring.AlgES256, keyring.AlgEdDSA},
	} {
		t.Run(strings.Join(mapAlgorithms(algs), ","), func(t *testing.T) {
			ts, _ := newTestServer(t, algs...)

			resp, err := http.Get(ts.URL + "/.well-known/openid-configuration")
			if err != nil {
				t.Fatalf("GET discovery: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			var doc map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
				t.Fatalf("decode discovery: %v", err)
			}
			if doc["issuer"] != testIssuer {
				t.Fatalf("issuer = %v, want %q", doc["issuer"], testIssuer)
			}
			if doc["jwks_uri"] != testIssuer+"/.well-known/jwks.json" {
				t.Fatalf("jwks_uri = %v", doc["jwks_uri"])
			}
			algsList, ok := doc["id_token_signing_alg_values_supported"].([]any)
			if !ok {
				t.Fatalf("signing algs missing: %#v", doc)
			}
			if len(algsList) != len(algs) {
				t.Fatalf("signing algs = %#v, want %d entries", doc["id_token_signing_alg_values_supported"], len(algs))
			}
			for i, alg := range algs {
				if algsList[i] != string(alg) {
					t.Fatalf("signing algs[%d] = %v, want %s", i, algsList[i], alg)
				}
			}
		})
	}
}

func TestTokenEndpointRoundTripValidatedByGolangJWT(t *testing.T) {
	for _, alg := range []keyring.Algorithm{keyring.AlgRS256, keyring.AlgES256, keyring.AlgEdDSA} {
		t.Run(string(alg), func(t *testing.T) {
			ts, _ := newTestServer(t, alg)

			body := `{"claims":{"sub":"user-1","roles":["admin","dev"],"aud":["svc-a"],"tenant":"acme"},"alg":"` + string(alg) + `"}`
			resp, data := postJSON(t, ts.URL+"/token", body)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, body = %s", resp.StatusCode, data)
			}

			var minted tokenfactory.Response
			if err := json.Unmarshal(data, &minted); err != nil {
				t.Fatalf("decode token response: %v", err)
			}
			if minted.TokenType != "Bearer" || minted.AccessToken == "" {
				t.Fatalf("unexpected response: %#v", minted)
			}
			if minted.ExpiresIn != 3600 {
				t.Fatalf("expires_in = %d, want 3600", minted.ExpiresIn)
			}

			set := fetchJWKS(t, ts.URL+"/.well-known/jwks.json")
			parser := jwt5.NewParser(jwt5.WithValidMethods([]string{string(alg)}), jwt5.WithIssuer(testIssuer))
			parsed, err := parser.Parse(minted.AccessToken, func(tk *jwt5.Token) (any, error) {
				kid, _ := tk.Header["kid"].(string)
				key, ok := set.LookupKeyID(kid)
				if !ok {
					return nil, fmt.Errorf("unknown kid %q", kid)
				}
				return exportPublicKey(t, key)
			})
			if err != nil {
				t.Fatalf("golang-jwt rejected minted token: %v", err)
			}

			claims := parsed.Claims.(jwt5.MapClaims)
			if claims["sub"] != "user-1" {
				t.Fatalf("sub = %v, want user-1", claims["sub"])
			}
			if claims["iss"] != testIssuer {
				t.Fatalf("iss = %v, want %q", claims["iss"], testIssuer)
			}
			if claims["tenant"] != "acme" {
				t.Fatalf("custom claim tenant = %v, want acme", claims["tenant"])
			}
			roles, ok := claims["roles"].([]any)
			if !ok || len(roles) != 2 || roles[0] != "admin" || roles[1] != "dev" {
				t.Fatalf("roles = %#v, want [admin dev]", claims["roles"])
			}
		})
	}
}

func exportPublicKey(t *testing.T, key jwk.Key) (any, error) {
	t.Helper()
	var pub any
	var err error
	switch key.KeyType() {
	case jwa.RSA():
		pub, err = jwk.Export[*rsa.PublicKey](key)
	case jwa.EC():
		pub, err = jwk.Export[*ecdsa.PublicKey](key)
	case jwa.OKP():
		pub, err = jwk.Export[ed25519.PublicKey](key)
	default:
		return nil, fmt.Errorf("unsupported key type: %v", key.KeyType())
	}
	if err != nil {
		return nil, fmt.Errorf("export public key: %w", err)
	}
	return pub, nil
}

func TestEmptyBodyMintsDefaultAnonymousToken(t *testing.T) {
	ts, _ := newTestServer(t, keyring.AlgRS256)

	resp, data := postJSON(t, ts.URL+"/token", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, data)
	}

	var minted tokenfactory.Response
	if err := json.Unmarshal(data, &minted); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	set := fetchJWKS(t, ts.URL+"/.well-known/jwks.json")
	parser := jwt5.NewParser(jwt5.WithValidMethods([]string{"RS256"}))
	if _, err := parser.Parse(minted.AccessToken, func(tk *jwt5.Token) (any, error) {
		kid, _ := tk.Header["kid"].(string)
		key, ok := set.LookupKeyID(kid)
		if !ok {
			return nil, fmt.Errorf("unknown kid %q", kid)
		}
		return exportPublicKey(t, key)
	}); err != nil {
		t.Fatalf("anonymous token rejected: %v", err)
	}
}

func TestMalformedBodyRejected(t *testing.T) {
	ts, _ := newTestServer(t, keyring.AlgRS256)
	resp, _ := postJSON(t, ts.URL+"/token", "{not json")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestUnsupportedAlgRejected(t *testing.T) {
	ts, _ := newTestServer(t, keyring.AlgRS256)
	resp, _ := postJSON(t, ts.URL+"/token", `{"alg":"HS256"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestOversizedLifetimeRejected(t *testing.T) {
	ts, _ := newTestServer(t, keyring.AlgRS256)
	resp, _ := postJSON(t, ts.URL+"/token", `{"claims":{"exp":"48h"}}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestWrongMethodOnTokenEndpoint(t *testing.T) {
	ts, _ := newTestServer(t, keyring.AlgRS256)
	resp, err := http.Get(ts.URL + "/token")
	if err != nil {
		t.Fatalf("GET /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
}

func TestIndexListsEndpoints(t *testing.T) {
	ts, _ := newTestServer(t, keyring.AlgRS256)
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(data), "/.well-known/jwks.json") {
		t.Fatalf("index does not list jwks endpoint: %s", data)
	}
}

func TestJWKSEndpointHandlesKeyringError(t *testing.T) {
	ts, ring := newTestServer(t, keyring.AlgRS256)
	_ = ts

	handler := New(ring, tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour), testIssuer, "test-version").Handler()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	errorHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusInternalServerError, "boom")
	})
	req2 := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w2 := httptest.NewRecorder()
	errorHandler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w2.Code)
	}
}

func TestTokenEndpointReturns400ForInvalidJSON(t *testing.T) {
	ts, _ := newTestServer(t, keyring.AlgRS256)
	resp, _ := postJSON(t, ts.URL+"/token", "{invalid")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestTokenEndpointReturns400ForUnsupportedAlg(t *testing.T) {
	ts, _ := newTestServer(t, keyring.AlgRS256)
	resp, _ := postJSON(t, ts.URL+"/token", `{"alg":"HS256"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestTokenEndpointReturns400ForTTLTooLong(t *testing.T) {
	ts, _ := newTestServer(t, keyring.AlgRS256)
	resp, _ := postJSON(t, ts.URL+"/token", `{"claims":{"exp":"48h"}}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestTokenEndpointReturns503WhenNoActiveKey(t *testing.T) {
	ring := &noActiveKeyRing{}
	factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
	s := New(ring, factory, testIssuer, "test-version")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(`{"claims":{"sub":"u"}}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	s.handleToken(w, req)

	_ = w
}

func TestJWKSEndpointHandlesMarshalError(t *testing.T) {
	ring, _ := keyring.New(time.Hour, []keyring.Algorithm{keyring.AlgRS256})
	factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
	s := New(ring, factory, testIssuer, "test-version")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	s.handleJWKS(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

func TestHandleTokenErrorPaths(t *testing.T) {
	ring, _ := keyring.New(time.Hour, []keyring.Algorithm{keyring.AlgRS256})
	factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
	s := New(ring, factory, testIssuer, "test-version")

	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{"invalid JSON", "{invalid", http.StatusBadRequest},
		{"unsupported alg", `{"alg":"HS256"}`, http.StatusBadRequest},
		{"TTL too long", `{"claims":{"exp":"48h"}}`, http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			s.handleToken(w, req)
			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}
}

type noActiveKeyRing struct{}

func (n *noActiveKeyRing) Signer(keyring.Algorithm) (*keyring.Key, error) {
	return nil, keyring.ErrNoActiveKey
}

func (n *noActiveKeyRing) JWKS() (jwk.Set, error) {
	return jwk.NewSet(), nil
}

func (n *noActiveKeyRing) JWKByKID(string) (jwk.Key, error) {
	return nil, keyring.ErrNoActiveKey
}

func (n *noActiveKeyRing) ActiveKid(keyring.Algorithm) (string, error) {
	return "", keyring.ErrNoActiveKey
}

func (n *noActiveKeyRing) RotateAt(time.Time) error {
	return nil
}

func (n *noActiveKeyRing) Prune() {}

func (n *noActiveKeyRing) PruneAt(time.Time) {}

func (n *noActiveKeyRing) StartRotation(context.Context, time.Duration, *slog.Logger) {}

func (n *noActiveKeyRing) Rotate() error { return nil }

func (n *noActiveKeyRing) EnabledAlgorithms() []keyring.Algorithm {
	return []keyring.Algorithm{keyring.AlgRS256}
}

type failingJWKSRing struct{}

func (f *failingJWKSRing) Signer(keyring.Algorithm) (*keyring.Key, error) {
	return nil, keyring.ErrNoActiveKey
}
func (f *failingJWKSRing) ActiveKid(keyring.Algorithm) (string, error) {
	return "", keyring.ErrNoActiveKey
}
func (f *failingJWKSRing) JWKS() (jwk.Set, error) {
	return nil, errors.New("jwks failed")
}
func (f *failingJWKSRing) JWKByKID(string) (jwk.Key, error) {
	return nil, errors.New("jwks failed")
}
func (f *failingJWKSRing) Rotate() error {
	return nil
}
func (f *failingJWKSRing) RotateAt(time.Time) error {
	return nil
}
func (f *failingJWKSRing) Prune() {}

func (f *failingJWKSRing) PruneAt(time.Time) {}

func (f *failingJWKSRing) StartRotation(context.Context, time.Duration, *slog.Logger) {}

func (f *failingJWKSRing) EnabledAlgorithms() []keyring.Algorithm {
	return []keyring.Algorithm{keyring.AlgRS256}
}

func TestJWKSEndpointHandlesError(t *testing.T) {
	ring := &failingJWKSRing{}
	factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
	s := New(ring, factory, testIssuer, "test-version")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	s.handleJWKS(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

func TestHandleTokenNoActiveKeyReturns503(t *testing.T) {
	ring := &noActiveKeyRing{}
	factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
	s := New(ring, factory, testIssuer, "test-version")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(`{"claims":{"sub":"u"}}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	s.handleToken(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}

func TestHandleTokenEmptyBody(t *testing.T) {
	ts, _ := newTestServer(t, keyring.AlgRS256)
	resp, _ := http.Post(ts.URL+"/token", "application/json", strings.NewReader(""))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

type internalErrRing struct{}

func (r *internalErrRing) Signer(keyring.Algorithm) (*keyring.Key, error) {
	return nil, errors.New("unexpected error")
}
func (r *internalErrRing) ActiveKid(keyring.Algorithm) (string, error) {
	return "", errors.New("unexpected error")
}
func (r *internalErrRing) JWKS() (jwk.Set, error) { return jwk.NewSet(), nil }
func (r *internalErrRing) JWKByKID(string) (jwk.Key, error) {
	return nil, errors.New("unexpected error")
}
func (r *internalErrRing) Rotate() error                                              { return nil }
func (r *internalErrRing) RotateAt(time.Time) error                                   { return nil }
func (r *internalErrRing) Prune()                                                     {}
func (r *internalErrRing) PruneAt(time.Time)                                          {}
func (r *internalErrRing) StartRotation(context.Context, time.Duration, *slog.Logger) {}
func (r *internalErrRing) EnabledAlgorithms() []keyring.Algorithm {
	return []keyring.Algorithm{keyring.AlgRS256}
}

func TestHandleTokenInternalServerError(t *testing.T) {
	ring := &internalErrRing{}
	factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
	s := New(ring, factory, testIssuer, "test-version")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(`{"claims":{"sub":"u"}}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	s.handleToken(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

type marshalErrorKey struct {
	jwk.Key
}

type failingMarshalRing struct{}

func (f *failingMarshalRing) Signer(keyring.Algorithm) (*keyring.Key, error) {
	return nil, keyring.ErrNoActiveKey
}
func (f *failingMarshalRing) ActiveKid(keyring.Algorithm) (string, error) {
	return "", keyring.ErrNoActiveKey
}
func (f *failingMarshalRing) JWKS() (jwk.Set, error) {
	set := jwk.NewSet()
	key := &marshalErrorKey{}
	if err := set.AddKey(key); err != nil {
		return nil, err
	}
	return set, nil
}
func (f *failingMarshalRing) JWKByKID(string) (jwk.Key, error) {
	return nil, errors.New("marshal error")
}
func (f *failingMarshalRing) Rotate() error                                              { return nil }
func (f *failingMarshalRing) RotateAt(time.Time) error                                   { return nil }
func (f *failingMarshalRing) Prune()                                                     {}
func (f *failingMarshalRing) PruneAt(time.Time)                                          {}
func (f *failingMarshalRing) StartRotation(context.Context, time.Duration, *slog.Logger) {}
func (f *failingMarshalRing) EnabledAlgorithms() []keyring.Algorithm {
	return []keyring.Algorithm{keyring.AlgRS256}
}

func TestJWKSEndpointMarshalError(t *testing.T) {
	ring := &failingMarshalRing{}
	factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
	s := New(ring, factory, testIssuer, "test-version")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	s.handleJWKS(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}
