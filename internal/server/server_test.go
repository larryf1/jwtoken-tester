package server

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jwt5 "github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"

	"jwtoken-tester/internal/keyring"
	"jwtoken-tester/internal/tokenfactory"
)

const testIssuer = "http://127.0.0.1:8080"

func newTestServer(t *testing.T) (*httptest.Server, *keyring.KeyRing) {
	t.Helper()
	ring, err := keyring.New(time.Hour)
	if err != nil {
		t.Fatalf("keyring.New() error = %v", err)
	}
	factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
	ts := httptest.NewServer(New(ring, factory, testIssuer).Handler())
	t.Cleanup(ts.Close)
	return ts, ring
}

func postJSON(t *testing.T, url, body string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
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
	defer resp.Body.Close()
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
	ts, _ := newTestServer(t)

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()

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
	if _, ok := doc["active_kid"].(string); !ok {
		t.Fatalf("active_kid missing: %#v", doc)
	}
}

func TestJWKSEndpointServesRSAPublicKeys(t *testing.T) {
	ts, _ := newTestServer(t)
	set := fetchJWKS(t, ts.URL+"/.well-known/jwks.json")

	if set.Len() < 1 {
		t.Fatal("JWKS is empty")
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

func TestDiscoveryDocumentPointsAtIssuerAndJWKS(t *testing.T) {
	ts, _ := newTestServer(t)

	resp, err := http.Get(ts.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer resp.Body.Close()

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
	algs, ok := doc["id_token_signing_alg_values_supported"].([]any)
	if !ok || len(algs) != 1 || algs[0] != "RS256" {
		t.Fatalf("signing algs = %#v, want [RS256]", doc["id_token_signing_alg_values_supported"])
	}
}

func TestTokenEndpointRoundTripValidatedByGolangJWT(t *testing.T) {
	ts, _ := newTestServer(t)

	body := `{"claims":{"sub":"user-1","roles":["admin","dev"],"aud":["svc-a"],"tenant":"acme"}}`
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
	parser := jwt5.NewParser(jwt5.WithValidMethods([]string{"RS256"}), jwt5.WithIssuer(testIssuer))
	parsed, err := parser.Parse(minted.AccessToken, func(tk *jwt5.Token) (any, error) {
		kid, _ := tk.Header["kid"].(string)
		key, ok := set.LookupKeyID(kid)
		if !ok {
			return nil, fmt.Errorf("unknown kid %q", kid)
		}
		return jwk.Export[*rsa.PublicKey](key)
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
}

func TestEmptyBodyMintsDefaultAnonymousToken(t *testing.T) {
	ts, _ := newTestServer(t)

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
		return jwk.Export[*rsa.PublicKey](key)
	}); err != nil {
		t.Fatalf("anonymous token rejected: %v", err)
	}
}

func TestMalformedBodyRejected(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, _ := postJSON(t, ts.URL+"/token", "{not json")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestUnsupportedAlgRejected(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, _ := postJSON(t, ts.URL+"/token", `{"alg":"HS256"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestOversizedLifetimeRejected(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, _ := postJSON(t, ts.URL+"/token", `{"claims":{"exp":"48h"}}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestWrongMethodOnTokenEndpoint(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/token")
	if err != nil {
		t.Fatalf("GET /token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
}

func TestIndexListsEndpoints(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(data), "/.well-known/jwks.json") {
		t.Fatalf("index does not list jwks endpoint: %s", data)
	}
}
