package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	jwt5 "github.com/golang-jwt/jwt/v5"
	"github.com/larryf1/jwtoken-tester/v2/internal/keyring"
	"github.com/larryf1/jwtoken-tester/v2/internal/tokenfactory"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
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
	ts := httptest.NewServer(New(ring, factory, testIssuer, "test-version", 100, 200).Handler())
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
		{keyring.AlgRS384, keyring.AlgPS256, keyring.AlgES384},
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
	s := New(ring, tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour), testIssuer, "test-version", 100, 200)
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
		{keyring.AlgRS384, keyring.AlgPS256, keyring.AlgPS512, keyring.AlgES384, keyring.AlgES512},
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
			if doc["token_endpoint"] != testIssuer+"/oauth/token" {
				t.Fatalf("token_endpoint = %v, want %q", doc["token_endpoint"], testIssuer+"/oauth/token")
			}
			if doc["introspection_endpoint"] != testIssuer+"/introspect" {
				t.Fatalf("introspection_endpoint = %v, want %q", doc["introspection_endpoint"], testIssuer+"/introspect")
			}
			claims, ok := doc["claims_supported"].([]any)
			if !ok {
				t.Fatalf("claims_supported missing: %#v", doc["claims_supported"])
			}
			wantClaims := []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti", "scope", "client_id"}
			if len(claims) != len(wantClaims) {
				t.Fatalf("claims_supported = %#v, want %v", claims, wantClaims)
			}
			for i, name := range wantClaims {
				if claims[i] != name {
					t.Fatalf("claims_supported[%d] = %v, want %q", i, claims[i], name)
				}
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

func TestOAuthV2TokenEndpointMintsClientClaims(t *testing.T) {
	ts, _ := newTestServer(t, keyring.AlgRS256)
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v2/oauth/token?%20Scope=capability1,capability2", nil)
	if err != nil {
		t.Fatalf("create OAuth request: %v", err)
	}
	req.Header.Set("X-Client-Id", "client-id")
	req.Header.Set("X-Client-Secret", "REDACTED")
	req.Header.Set("Accept", "application/json")

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /v2/oauth/token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read OAuth response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, data)
	}

	var minted tokenfactory.Response
	if err := json.Unmarshal(data, &minted); err != nil {
		t.Fatalf("decode OAuth response: %v", err)
	}
	if minted.TokenType != "Bearer" || minted.AccessToken == "" || minted.ExpiresIn <= 0 {
		t.Fatalf("unexpected OAuth response: %#v", minted)
	}
	if strings.Contains(minted.AccessToken, "REDACTED") {
		t.Fatal("client secret was included in the access token")
	}

	set := fetchJWKS(t, ts.URL+"/.well-known/jwks.json")
	parser := jwt5.NewParser(jwt5.WithValidMethods([]string{"RS256"}), jwt5.WithIssuer(testIssuer))
	parsed, err := parser.Parse(minted.AccessToken, func(tk *jwt5.Token) (any, error) {
		kid, _ := tk.Header["kid"].(string)
		key, ok := set.LookupKeyID(kid)
		if !ok {
			return nil, fmt.Errorf("unknown kid %q", kid)
		}
		return exportPublicKey(t, key)
	})
	if err != nil {
		t.Fatalf("invalid OAuth access token: %v", err)
	}
	claims := parsed.Claims.(jwt5.MapClaims)
	if claims["sub"] != "client-id" || claims["client_id"] != "client-id" {
		t.Fatalf("client identity claims = sub:%v client_id:%v", claims["sub"], claims["client_id"])
	}
	audience, ok := claims["aud"].([]any)
	if !ok || len(audience) != 1 || audience[0] != "client" || claims["idtyp"] != "app" || claims["iss"] != testIssuer || claims["version"] != "2.0" {
		t.Fatalf("unexpected standard OAuth claims: %#v", claims)
	}
	capabilities, ok := claims["capabilities"].([]any)
	if !ok || len(capabilities) != 2 || capabilities[0] != "capability1" || capabilities[1] != "capability2" {
		t.Fatalf("capabilities = %#v, want [capability1 capability2]", claims["capabilities"])
	}
	resources, ok := claims["allowedResources"].(map[string]any)
	if !ok {
		t.Fatalf("allowedResources = %#v", claims["allowedResources"])
	}
	partners, ok := resources["allowedPartners"].([]any)
	if !ok || len(partners) != 1 || partners[0] != "partner" {
		t.Fatalf("allowedPartners = %#v, want [partner]", resources["allowedPartners"])
	}
	for _, name := range []string{"iat", "nbf", "exp"} {
		if _, ok := claims[name]; !ok {
			t.Errorf("claim %q is missing", name)
		}
	}
	if jti, ok := claims["jti"].(string); !ok || len(jti) != 36 {
		t.Errorf("jti = %#v, want UUID-formatted string", claims["jti"])
	}
}

func TestOAuthV2TokenEndpointRequiresClientIDAndScope(t *testing.T) {
	ts, _ := newTestServer(t, keyring.AlgRS256)
	tests := []struct {
		name string
		url  string
		id   string
	}{
		{name: "missing client ID", url: ts.URL + "/v2/oauth/token?Scope=capability1"},
		{name: "missing scope", url: ts.URL + "/v2/oauth/token", id: "client-id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, tt.url, nil)
			if err != nil {
				t.Fatalf("create request: %v", err)
			}
			if tt.id != "" {
				req.Header.Set("X-Client-Id", tt.id)
			}
			resp, err := ts.Client().Do(req)
			if err != nil {
				t.Fatalf("POST OAuth token: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}
		})
	}
}

func TestOAuthV2TokenEndpointMapsNoActiveKeyToUnavailable(t *testing.T) {
	ring := &noActiveKeyRing{}
	factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
	server := New(ring, factory, testIssuer, "test-version", 100, 200)
	req := httptest.NewRequest(http.MethodPost, "/v2/oauth/token?scope=read", nil)
	req.Header.Set("X-Client-Id", "client-id")
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

func TestJWKByKIDReturnsInternalServerErrorForRingFailure(t *testing.T) {
	ring := &failingJWKSRing{}
	factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
	server := New(ring, factory, testIssuer, "test-version", 100, 200)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json/kid", nil)
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

func TestOAuthCapabilitiesIgnoresOtherParametersAndEmptyValues(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?other=ignored&%20SCOPE%20=read,,write&scope=%20,%20", nil)
	capabilities := oauthCapabilities(req)
	want := []string{"read", "write"}
	if !reflect.DeepEqual(capabilities, want) {
		t.Fatalf("oauthCapabilities() = %v, want %v", capabilities, want)
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

func TestNegativeTokenGateComesFromServerOption(t *testing.T) {
	ring, err := keyring.New(time.Hour, []keyring.Algorithm{keyring.AlgRS256})
	if err != nil {
		t.Fatal(err)
	}
	factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
	disabled := httptest.NewServer(New(ring, factory, testIssuer, "test", 100, 200).Handler())
	defer disabled.Close()
	resp, _ := postJSON(t, disabled.URL+"/token", `{"alg":"none","allow_negative":true}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("body opt-in status = %d, want 403", resp.StatusCode)
	}
	enabled := httptest.NewServer(New(ring, factory, testIssuer, "test", 100, 200, WithAllowNegativeTokens(true)).Handler())
	defer enabled.Close()
	resp, data := postJSON(t, enabled.URL+"/token", `{"alg":"none"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enabled status = %d, body = %s", resp.StatusCode, data)
	}
}

func TestNewAlgorithmsVerifyThroughHTTP(t *testing.T) {
	for _, alg := range []keyring.Algorithm{keyring.AlgRS384, keyring.AlgRS512, keyring.AlgPS256, keyring.AlgPS384, keyring.AlgPS512, keyring.AlgES384, keyring.AlgES512} {
		t.Run(string(alg), func(t *testing.T) {
			ts, ring := newTestServer(t, alg)
			factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
			minted, err := factory.Mint(&tokenfactory.Request{Alg: string(alg)})
			if err != nil {
				t.Fatal(err)
			}
			body, _ := json.Marshal(map[string]string{"token": minted.AccessToken})
			resp, data := postJSON(t, ts.URL+"/verify", string(body))
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("verify status = %d, body=%s", resp.StatusCode, data)
			}
			var verdict map[string]any
			if err := json.Unmarshal(data, &verdict); err != nil {
				t.Fatal(err)
			}
			if verdict["valid"] != true {
				t.Fatalf("verify verdict = %s", data)
			}
		})
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
	if !strings.Contains(string(data), "POST /verify") {
		t.Fatalf("index does not list verify endpoint: %s", data)
	}
	for _, endpoint := range []string{"GET /version", "POST /oauth/token", "POST /introspect", "GET /.well-known/oauth-authorization-server"} {
		if !strings.Contains(string(data), endpoint) {
			t.Errorf("index does not list %s: %s", endpoint, data)
		}
	}
}

func TestJWKSEndpointHandlesKeyringError(t *testing.T) {
	ts, ring := newTestServer(t, keyring.AlgRS256)
	_ = ts

	handler := New(ring, tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour), testIssuer, "test-version", 100, 200).Handler()
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
	s := New(ring, factory, testIssuer, "test-version", 100, 200)

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(`{"claims":{"sub":"u"}}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	s.handleToken(w, req)

	_ = w
}

func TestJWKSEndpointHandlesMarshalError(t *testing.T) {
	ring, _ := keyring.New(time.Hour, []keyring.Algorithm{keyring.AlgRS256})
	factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
	s := New(ring, factory, testIssuer, "test-version", 100, 200)

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
	s := New(ring, factory, testIssuer, "test-version", 100, 200)

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

func (n *noActiveKeyRing) SignerByKID(string, keyring.Algorithm) (*keyring.Key, error) {
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

func (n *noActiveKeyRing) Lookup(string) (crypto.PublicKey, keyring.KeyStatus, error) {
	return nil, "", keyring.ErrKeyNotFound
}

func (n *noActiveKeyRing) RotateAt(time.Time) error {
	return nil
}

func (n *noActiveKeyRing) Prune() {}

func (n *noActiveKeyRing) PruneAt(time.Time) {}

func (n *noActiveKeyRing) StartRotation(context.Context, time.Duration, *slog.Logger) <-chan struct{} {
	return closedRotation()
}

func (n *noActiveKeyRing) Rotate() error { return nil }

func (n *noActiveKeyRing) EnabledAlgorithms() []keyring.Algorithm {
	return []keyring.Algorithm{keyring.AlgRS256}
}

type failingJWKSRing struct{}

func (f *failingJWKSRing) Signer(keyring.Algorithm) (*keyring.Key, error) {
	return nil, keyring.ErrNoActiveKey
}
func (f *failingJWKSRing) SignerByKID(string, keyring.Algorithm) (*keyring.Key, error) {
	return nil, errors.New("jwks failed")
}
func (f *failingJWKSRing) ActiveKid(keyring.Algorithm) (string, error) {
	return "", keyring.ErrNoActiveKey
}
func (f *failingJWKSRing) Lookup(string) (crypto.PublicKey, keyring.KeyStatus, error) {
	return nil, "", errors.New("jwks failed")
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

func (f *failingJWKSRing) StartRotation(context.Context, time.Duration, *slog.Logger) <-chan struct{} {
	return closedRotation()
}

func (f *failingJWKSRing) EnabledAlgorithms() []keyring.Algorithm {
	return []keyring.Algorithm{keyring.AlgRS256}
}

func TestJWKSEndpointHandlesError(t *testing.T) {
	ring := &failingJWKSRing{}
	factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
	s := New(ring, factory, testIssuer, "test-version", 100, 200)

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
	s := New(ring, factory, testIssuer, "test-version", 100, 200)

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
func (r *internalErrRing) SignerByKID(string, keyring.Algorithm) (*keyring.Key, error) {
	return nil, errors.New("unexpected error")
}
func (r *internalErrRing) ActiveKid(keyring.Algorithm) (string, error) {
	return "", errors.New("unexpected error")
}
func (r *internalErrRing) Lookup(string) (crypto.PublicKey, keyring.KeyStatus, error) {
	return nil, "", errors.New("unexpected error")
}
func (r *internalErrRing) JWKS() (jwk.Set, error) { return jwk.NewSet(), nil }
func (r *internalErrRing) JWKByKID(string) (jwk.Key, error) {
	return nil, errors.New("unexpected error")
}
func (r *internalErrRing) Rotate() error            { return nil }
func (r *internalErrRing) RotateAt(time.Time) error { return nil }
func (r *internalErrRing) Prune()                   {}
func (r *internalErrRing) PruneAt(time.Time)        {}
func (r *internalErrRing) StartRotation(context.Context, time.Duration, *slog.Logger) <-chan struct{} {
	return closedRotation()
}
func (r *internalErrRing) EnabledAlgorithms() []keyring.Algorithm {
	return []keyring.Algorithm{keyring.AlgRS256}
}

func TestHandleTokenInternalServerError(t *testing.T) {
	ring := &internalErrRing{}
	factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
	s := New(ring, factory, testIssuer, "test-version", 100, 200)

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
func (f *failingMarshalRing) SignerByKID(string, keyring.Algorithm) (*keyring.Key, error) {
	return nil, keyring.ErrNoActiveKey
}
func (f *failingMarshalRing) ActiveKid(keyring.Algorithm) (string, error) {
	return "", keyring.ErrNoActiveKey
}
func (f *failingMarshalRing) Lookup(string) (crypto.PublicKey, keyring.KeyStatus, error) {
	return nil, "", keyring.ErrKeyNotFound
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
func (f *failingMarshalRing) Rotate() error            { return nil }
func (f *failingMarshalRing) RotateAt(time.Time) error { return nil }
func (f *failingMarshalRing) Prune()                   {}
func (f *failingMarshalRing) PruneAt(time.Time)        {}
func (f *failingMarshalRing) StartRotation(context.Context, time.Duration, *slog.Logger) <-chan struct{} {
	return closedRotation()
}

func closedRotation() <-chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}
func (f *failingMarshalRing) EnabledAlgorithms() []keyring.Algorithm {
	return []keyring.Algorithm{keyring.AlgRS256}
}

func TestJWKSEndpointMarshalError(t *testing.T) {
	ring := &failingMarshalRing{}
	factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
	s := New(ring, factory, testIssuer, "test-version", 100, 200)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	s.handleJWKS(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

func TestSecurityHeadersPresent(t *testing.T) {
	ts, _ := newTestServer(t, keyring.AlgRS256)

	endpoints := []string{
		"/",
		"/healthz",
		"/version",
		"/.well-known/jwks.json",
		"/.well-known/openid-configuration",
		"/token",
	}

	for _, ep := range endpoints {
		t.Run(ep, func(t *testing.T) {
			resp, err := http.Get(ts.URL + ep)
			if err != nil {
				t.Fatalf("GET %s: %v", ep, err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
				t.Errorf("X-Content-Type-Options missing on %s", ep)
			}
			if resp.Header.Get("X-Frame-Options") != "DENY" {
				t.Errorf("X-Frame-Options missing on %s", ep)
			}
			if resp.Header.Get("Referrer-Policy") != "no-referrer" {
				t.Errorf("Referrer-Policy missing on %s", ep)
			}
			if resp.Header.Get("Content-Security-Policy") != "default-src 'none'; frame-ancestors 'none'" {
				t.Errorf("Content-Security-Policy missing on %s: %s", ep, resp.Header.Get("Content-Security-Policy"))
			}
		})
	}
}

func TestRateLimitEnforced(t *testing.T) {
	// Use small burst for deterministic testing
	ring, _ := keyring.New(time.Hour, []keyring.Algorithm{keyring.AlgRS256})
	factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
	srv := New(ring, factory, testIssuer, "test-version", 100, 10)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()

	// Make requests up to burst limit (10)
	for i := 0; i < 10; i++ {
		srv.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i, w.Code)
		}
		w = httptest.NewRecorder()
	}

	// Next request should be rate limited
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after burst, got %d", w.Code)
	}
	if w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("rate limit response should be JSON")
	}
}

func TestRateLimitPerIP(t *testing.T) {
	// Use small burst for deterministic testing
	ring, _ := keyring.New(time.Hour, []keyring.Algorithm{keyring.AlgRS256})
	factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
	srv := New(ring, factory, testIssuer, "test-version", 100, 10)

	// Simulate two different IPs via X-Forwarded-For
	req1 := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req1.Header.Set("X-Forwarded-For", "10.0.0.1")
	w1 := httptest.NewRecorder()

	req2 := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req2.Header.Set("X-Forwarded-For", "10.0.0.2")
	w2 := httptest.NewRecorder()

	// Exhaust burst for IP 1 (10 requests)
	for i := 0; i < 10; i++ {
		srv.Handler().ServeHTTP(w1, req1)
		if w1.Code != http.StatusOK {
			t.Fatalf("IP1 request %d: status = %d, want 200", i, w1.Code)
		}
		w1 = httptest.NewRecorder()
	}

	// IP 1 should be rate limited
	srv.Handler().ServeHTTP(w1, req1)
	if w1.Code != http.StatusTooManyRequests {
		t.Fatalf("IP1 expected 429, got %d", w1.Code)
	}

	// IP 2 should still work (separate limiter)
	srv.Handler().ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("IP2 expected 200, got %d", w2.Code)
	}
}

func TestTokenEndpointHasSecurityHeaders(t *testing.T) {
	ts, _ := newTestServer(t, keyring.AlgRS256)

	resp, err := http.Post(ts.URL+"/token", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("X-Content-Type-Options missing on /token")
	}
	if resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Error("X-Frame-Options missing on /token")
	}
}

func TestRequestIDHeaderGenerated(t *testing.T) {
	ts, _ := newTestServer(t, keyring.AlgRS256)

	endpoints := []string{
		"/",
		"/healthz",
		"/version",
		"/.well-known/jwks.json",
		"/.well-known/openid-configuration",
		"/token",
	}

	for _, ep := range endpoints {
		t.Run(ep, func(t *testing.T) {
			var resp *http.Response
			var err error
			if ep == "/token" {
				resp, err = http.Post(ts.URL+ep, "application/json", strings.NewReader(`{}`))
			} else {
				resp, err = http.Get(ts.URL + ep)
			}
			if err != nil {
				t.Fatalf("request %s: %v", ep, err)
			}
			defer func() { _ = resp.Body.Close() }()

			requestID := resp.Header.Get("X-Request-ID")
			if requestID == "" {
				t.Errorf("X-Request-ID missing on %s", ep)
			}
			if len(requestID) != 32 {
				t.Errorf("X-Request-ID invalid length on %s: got %d, want 32", ep, len(requestID))
			}
		})
	}
}

func TestRequestIDHeaderPropagated(t *testing.T) {
	ts, _ := newTestServer(t, keyring.AlgRS256)

	customID := "custom-request-id-12345"
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/healthz", nil)
	req.Header.Set("X-Request-ID", customID)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.Header.Get("X-Request-ID") != customID {
		t.Errorf("X-Request-ID not propagated: got %s, want %s", resp.Header.Get("X-Request-ID"), customID)
	}
}

func TestTokenAuditLogFields(t *testing.T) {
	ring, _ := keyring.New(time.Hour, []keyring.Algorithm{keyring.AlgRS256})
	factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
	srv := New(ring, factory, testIssuer, "test-version", 100, 200)

	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger := slog.New(handler)
	slog.SetDefault(logger)

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(`{"claims":{"sub":"user-1"},"alg":"RS256"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var logEntry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &logEntry); err != nil {
		t.Fatalf("invalid log JSON: %v", err)
	}

	if logEntry["event"] != "token_minted" {
		t.Errorf("event = %v, want token_minted", logEntry["event"])
	}
	if logEntry["alg"] != "RS256" {
		t.Errorf("alg = %v, want RS256", logEntry["alg"])
	}
	if logEntry["kid"] == "" {
		t.Error("kid missing from audit log")
	}
	if logEntry["expires_in"].(float64) != 3600 {
		t.Errorf("expires_in = %v, want 3600", logEntry["expires_in"])
	}
	if logEntry["request_id"] == "" {
		t.Error("request_id missing from audit log")
	}
	if logEntry["client_ip"] == "" {
		t.Error("client_ip missing from audit log")
	}
}

func TestTokenAuditLogOnFailure(t *testing.T) {
	ring, _ := keyring.New(time.Hour, []keyring.Algorithm{keyring.AlgRS256})
	factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
	srv := New(ring, factory, testIssuer, "test-version", 100, 200)

	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger := slog.New(handler)
	slog.SetDefault(logger)

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(`{"alg":"HS256"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	var logEntry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &logEntry); err != nil {
		t.Fatalf("invalid log JSON: %v", err)
	}

	if logEntry["event"] != "token_mint_failed" {
		t.Errorf("event = %v, want token_mint_failed", logEntry["event"])
	}
	if logEntry["error"] == "" {
		t.Error("error missing from audit log")
	}
}

func TestTokenAuditLogUsesForwardedFor(t *testing.T) {
	ring, _ := keyring.New(time.Hour, []keyring.Algorithm{keyring.AlgRS256})
	factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
	srv := New(ring, factory, testIssuer, "test-version", 100, 200)

	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger := slog.New(handler)
	slog.SetDefault(logger)

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(`{"claims":{"sub":"user-1"},"alg":"RS256"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "203.0.113.7, 198.51.100.9")
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var logEntry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &logEntry); err != nil {
		t.Fatalf("invalid log JSON: %v", err)
	}
	if logEntry["client_ip"] != "203.0.113.7" {
		t.Errorf("client_ip = %v, want first X-Forwarded-For hop 203.0.113.7", logEntry["client_ip"])
	}
}

func TestNewAppliesDefaultRateLimit(t *testing.T) {
	ring, err := keyring.New(time.Hour, []keyring.Algorithm{keyring.AlgRS256})
	if err != nil {
		t.Fatalf("keyring.New() error = %v", err)
	}
	factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)

	s := New(ring, factory, testIssuer, "test-version", 0, 0)

	if s.rateLimitRPS != defaultRateLimitRPS {
		t.Errorf("rateLimitRPS = %v, want default %v", s.rateLimitRPS, defaultRateLimitRPS)
	}
	if s.rateLimitBurst != defaultRateLimitBurst {
		t.Errorf("rateLimitBurst = %v, want default %v", s.rateLimitBurst, defaultRateLimitBurst)
	}
}

func TestWithLoggerRoutesAuditEvents(t *testing.T) {
	ring, err := keyring.New(time.Hour, []keyring.Algorithm{keyring.AlgRS256})
	if err != nil {
		t.Fatalf("keyring.New() error = %v", err)
	}
	factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	srv := New(ring, factory, testIssuer, "test-version", 100, 200, WithLogger(logger))
	t.Cleanup(srv.Close)

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(`{"claims":{"sub":"user-1"},"alg":"RS256"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var logEntry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &logEntry); err != nil {
		t.Fatalf("invalid log JSON: %v", err)
	}
	if logEntry["event"] != "token_minted" {
		t.Errorf("event = %v, want token_minted", logEntry["event"])
	}
}

func TestCloseStopsCleanupGoroutine(t *testing.T) {
	ring, err := keyring.New(time.Hour, []keyring.Algorithm{keyring.AlgRS256})
	if err != nil {
		t.Fatalf("keyring.New() error = %v", err)
	}
	factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
	srv := New(ring, factory, testIssuer, "test-version", 100, 200)

	srv.Close()

	select {
	case <-srv.cleanupDone:
	default:
		t.Fatal("cleanup goroutine still running after Close")
	}
}

func TestCloseIsIdempotentAndConcurrentSafe(t *testing.T) {
	ring, err := keyring.New(time.Hour, []keyring.Algorithm{keyring.AlgRS256})
	if err != nil {
		t.Fatalf("keyring.New() error = %v", err)
	}
	factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
	srv := New(ring, factory, testIssuer, "test-version", 100, 200)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			srv.Close()
		}()
	}
	wg.Wait()

	srv.Close()
	select {
	case <-srv.cleanupDone:
	default:
		t.Fatal("cleanup goroutine still running after Close")
	}
}

func mintVerifyToken(t *testing.T, ring keyring.Ring, claims map[string]any) string {
	t.Helper()
	factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
	resp, err := factory.Mint(&tokenfactory.Request{Claims: claims, Alg: string(keyring.AlgRS256)})
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	return resp.AccessToken
}

func signedVerifyToken(t *testing.T, ring keyring.Ring, claims map[string]any, header map[string]any) string {
	t.Helper()
	key, err := ring.Signer(keyring.AlgRS256)
	if err != nil {
		t.Fatalf("Signer() error = %v", err)
	}
	tok := jwt5.NewWithClaims(jwt5.SigningMethodRS256, jwt5.MapClaims(claims))
	for name, value := range header {
		tok.Header[name] = value
	}
	signed, err := tok.SignedString(key.Private)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func tamperServerToken(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[2] == "" {
		return token
	}
	if parts[2][0] == 'A' {
		parts[2] = "B" + parts[2][1:]
	} else {
		parts[2] = "A" + parts[2][1:]
	}
	return strings.Join(parts, ".")
}

func decodeVerdict(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var verdict map[string]any
	if err := json.Unmarshal(data, &verdict); err != nil {
		t.Fatalf("decode verdict: %v (body %s)", err, data)
	}
	return verdict
}

func TestVerifyEndpointAcceptsValidToken(t *testing.T) {
	ts, ring := newTestServer(t, keyring.AlgRS256)
	token := mintVerifyToken(t, ring, map[string]any{
		"sub":   "user-1",
		"aud":   "my-service",
		"roles": []string{"admin"},
	})

	resp, data := postJSON(t, ts.URL+"/verify", `{"token":"`+token+`","aud":["my-service"]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, data)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	verdict := decodeVerdict(t, data)
	if verdict["valid"] != true {
		t.Fatalf("verdict = %#v", verdict)
	}
	if verdict["reason"] != nil {
		t.Fatalf("valid verdict has reason: %#v", verdict)
	}
	if verdict["kid_status"] != "active" {
		t.Fatalf("kid_status = %v, want active", verdict["kid_status"])
	}
	if verdict["alg"] != "RS256" {
		t.Fatalf("alg = %v", verdict["alg"])
	}
	header, ok := verdict["header"].(map[string]any)
	if !ok || header["kid"] == "" {
		t.Fatalf("header = %#v", verdict["header"])
	}
	claims, ok := verdict["claims"].(map[string]any)
	if !ok || claims["sub"] != "user-1" || claims["roles"] == nil {
		t.Fatalf("claims = %#v", verdict["claims"])
	}
	if verdict["unverified_claims"] != nil {
		t.Fatalf("valid verdict carries unverified_claims: %#v", verdict["unverified_claims"])
	}
}

func TestVerifyEndpointReportsFailureReasons(t *testing.T) {
	ts, ring := newTestServer(t, keyring.AlgRS256)

	cases := []struct {
		name      string
		token     string
		body      string
		reason    string
		kidStatus string
		label     string
	}{
		{
			name:      "expired",
			token:     mintVerifyToken(t, ring, map[string]any{"sub": "user-1", "exp": "-5m"}),
			reason:    "expired",
			kidStatus: "active",
			label:     "claims",
		},
		{
			name:      "unknown kid",
			token:     signedVerifyToken(t, ring, map[string]any{"iss": testIssuer, "sub": "user-1", "exp": time.Now().Add(time.Hour).Unix()}, map[string]any{"kid": "unknown-kid"}),
			reason:    "kid",
			kidStatus: "unknown",
			label:     "unverified_claims",
		},
		{
			name:      "bad signature",
			token:     tamperServerToken(mintVerifyToken(t, ring, map[string]any{"sub": "user-1"})),
			reason:    "signature",
			kidStatus: "active",
			label:     "unverified_claims",
		},
		{
			name:   "wrong issuer",
			token:  mintVerifyToken(t, ring, map[string]any{"sub": "user-1", "iss": "https://attacker.example"}),
			reason: "issuer",
			label:  "claims",
		},
		{
			name:   "wrong audience",
			token:  mintVerifyToken(t, ring, map[string]any{"sub": "user-1", "aud": "other-service"}),
			body:   `,"aud":"my-service"`,
			reason: "audience",
			label:  "claims",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, data := postJSON(t, ts.URL+"/verify", `{"token":"`+tc.token+`"`+tc.body+`}`)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, data)
			}
			verdict := decodeVerdict(t, data)
			if verdict["valid"] != false {
				t.Fatalf("verdict = %#v", verdict)
			}
			if verdict["reason"] != tc.reason {
				t.Fatalf("reason = %v, want %s", verdict["reason"], tc.reason)
			}
			if verdict["error"] == "" || verdict["error"] == nil {
				t.Fatalf("error is empty: %#v", verdict)
			}
			if tc.kidStatus != "" && verdict["kid_status"] != tc.kidStatus {
				t.Fatalf("kid_status = %v, want %s", verdict["kid_status"], tc.kidStatus)
			}
			if verdict[tc.label] == nil {
				t.Fatalf("%s is missing: %#v", tc.label, verdict)
			}
		})
	}
}

func TestVerifyEndpointLeewayAdmitsRecentlyExpired(t *testing.T) {
	ts, ring := newTestServer(t, keyring.AlgRS256)
	token := mintVerifyToken(t, ring, map[string]any{"sub": "user-1", "exp": "-30s"})

	resp, data := postJSON(t, ts.URL+"/verify", `{"token":"`+token+`","leeway":"1m"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, data)
	}
	verdict := decodeVerdict(t, data)
	if verdict["valid"] != true {
		t.Fatalf("verdict = %#v", verdict)
	}
}

func TestVerifyEndpointRequestErrors(t *testing.T) {
	ts, _ := newTestServer(t, keyring.AlgRS256)

	cases := map[string]string{
		"missing token":      `{}`,
		"empty token":        `{"token":""}`,
		"blank token":        `{"token":"   "}`,
		"invalid json":       `{invalid`,
		"unknown jwks field": `{"token":"x","jwks":{}}`,
		"unknown jwks_url":   `{"token":"x","jwks_url":"http://example.invalid"}`,
		"unknown issuer":     `{"token":"x","issuer":"http://example.invalid"}`,
		"empty alg list":     `{"token":"x","alg":[]}`,
		"disabled alg":       `{"token":"x","alg":["HS256"]}`,
		"bad leeway":         `{"token":"x","leeway":"soon"}`,
		"negative leeway":    `{"token":"x","leeway":"-1s"}`,
		"bad audience shape": `{"token":"x","aud":123}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			resp, data := postJSON(t, ts.URL+"/verify", body)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s)", resp.StatusCode, data)
			}
			if !strings.Contains(string(data), "error") {
				t.Fatalf("error response = %s", data)
			}
		})
	}

	t.Run("oversized body", func(t *testing.T) {
		body := `{"token":"` + strings.Repeat("a", maxRequestBody+1) + `"}`
		resp, data := postJSON(t, ts.URL+"/verify", body)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body %s)", resp.StatusCode, data)
		}
	})
}

func TestVerifyEndpointRejectsMethodsAndExternalKeysWithoutFetching(t *testing.T) {
	ring, err := keyring.New(time.Hour, []keyring.Algorithm{keyring.AlgRS256})
	if err != nil {
		t.Fatalf("keyring.New() error = %v", err)
	}
	factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
	srv := New(ring, factory, testIssuer, "test-version", 100, 200)
	t.Cleanup(srv.Close)

	getReq := httptest.NewRequest(http.MethodGet, "/verify", nil)
	getRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /verify status = %d, want 405", getRec.Code)
	}

	originalTransport := http.DefaultTransport
	transport := &recordingTransport{}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = originalTransport })

	for _, body := range []string{
		`{"token":"x","jwks":{}}`,
		`{"token":"x","jwks_url":"http://example.invalid/jwks.json"}`,
		`{"token":"x","issuer":"http://example.invalid"}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/verify", strings.NewReader(body))
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body %s status = %d, want 400", body, rec.Code)
		}
	}
	if transport.calls != 0 {
		t.Fatalf("verification made %d outbound requests, want 0", transport.calls)
	}
}

type recordingTransport struct {
	calls int
}

func (r *recordingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	r.calls++
	return nil, errors.New("unexpected outbound request")
}

func TestVerifyEndpointMapsUnclassifiableTo500(t *testing.T) {
	ring, err := keyring.New(time.Hour, []keyring.Algorithm{keyring.AlgRS256})
	if err != nil {
		t.Fatalf("keyring.New() error = %v", err)
	}
	token := mintVerifyToken(t, ring, map[string]any{"sub": "user-1"})

	srv := New(&internalErrRing{}, nil, testIssuer, "test-version", 100, 200)
	t.Cleanup(srv.Close)

	req := httptest.NewRequest(http.MethodPost, "/verify", strings.NewReader(`{"token":"`+token+`"}`))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (body %s)", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
	}
	if !strings.Contains(rec.Body.String(), "error") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestVerifyEndpointAuditsWithoutTokenContents(t *testing.T) {
	ring, err := keyring.New(time.Hour, []keyring.Algorithm{keyring.AlgRS256})
	if err != nil {
		t.Fatalf("keyring.New() error = %v", err)
	}
	factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)

	var buf bytes.Buffer
	srv := New(ring, factory, testIssuer, "test-version", 100, 200, WithLogger(slog.New(slog.NewJSONHandler(&buf, nil))))
	t.Cleanup(srv.Close)

	resp, err := factory.Mint(&tokenfactory.Request{
		Alg:    string(keyring.AlgRS256),
		Claims: map[string]any{"sub": "sensitive-subject", "exp": "-5m"},
	})
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/verify", strings.NewReader(`{"token":"`+resp.AccessToken+`"}`))
	req.Header.Set("X-Request-ID", "audit-request-id")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("decode audit log: %v (%s)", err, buf.String())
	}
	if entry["event"] != "token_verified" {
		t.Fatalf("event = %v", entry["event"])
	}
	if entry["valid"] != false || entry["reason"] != "expired" {
		t.Fatalf("audit outcome = %#v", entry)
	}
	if entry["kid"] == "" || entry["kid_status"] != "active" || entry["alg"] != "RS256" {
		t.Fatalf("audit key fields = %#v", entry)
	}
	if entry["request_id"] != "audit-request-id" || entry["path"] != "/verify" || entry["method"] != http.MethodPost {
		t.Fatalf("audit request fields = %#v", entry)
	}
	logged := buf.String()
	if strings.Contains(logged, resp.AccessToken) || strings.Contains(logged, "sensitive-subject") {
		t.Fatalf("audit log leaked token or claims: %s", logged)
	}
}

func newOptionTestServer(t *testing.T, opts []Option, algs ...keyring.Algorithm) (*httptest.Server, *keyring.KeyRing, *Server) {
	t.Helper()
	if len(algs) == 0 {
		algs = []keyring.Algorithm{keyring.AlgRS256}
	}
	ring, err := keyring.New(time.Hour, algs)
	if err != nil {
		t.Fatalf("keyring.New() error = %v", err)
	}
	factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
	srv := New(ring, factory, testIssuer, "test-version", 100, 200, opts...)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() {
		ts.Close()
		srv.Close()
	})
	return ts, ring, srv
}

func postForm(t *testing.T, client *http.Client, target string, form url.Values) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("create form request: %v", err)
	}
	req.Header.Set("Content-Type", oauthFormContentType)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp, data
}

func decodeBody(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("decode response %s: %v", data, err)
	}
	return doc
}

func tokenAlgorithm(t *testing.T, token string) string {
	t.Helper()
	parsed, _, err := jwt5.NewParser().ParseUnverified(token, jwt5.MapClaims{})
	if err != nil {
		t.Fatalf("parse token header: %v", err)
	}
	alg, _ := parsed.Header["alg"].(string)
	return alg
}

func oauthTokenClaims(t *testing.T, ts *httptest.Server, token string, alg keyring.Algorithm) jwt5.MapClaims {
	t.Helper()
	set := fetchJWKS(t, ts.URL+"/.well-known/jwks.json")
	parser := jwt5.NewParser(jwt5.WithValidMethods([]string{string(alg)}), jwt5.WithIssuer(testIssuer))
	parsed, err := parser.Parse(token, func(tk *jwt5.Token) (any, error) {
		kid, _ := tk.Header["kid"].(string)
		key, ok := set.LookupKeyID(kid)
		if !ok {
			return nil, fmt.Errorf("unknown kid %q", kid)
		}
		return exportPublicKey(t, key)
	})
	if err != nil {
		t.Fatalf("parse minted token: %v", err)
	}
	return parsed.Claims.(jwt5.MapClaims)
}

func TestDiscoveryDocumentAdvertisesOAuthMetadata(t *testing.T) {
	ts, _, _ := newOptionTestServer(t, nil)

	resp, err := http.Get(ts.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	doc := decodeBody(t, data)

	wantStrings := map[string]string{
		"issuer":                 testIssuer,
		"jwks_uri":               testIssuer + "/.well-known/jwks.json",
		"token_endpoint":         testIssuer + "/oauth/token",
		"introspection_endpoint": testIssuer + "/introspect",
	}
	for key, want := range wantStrings {
		if doc[key] != want {
			t.Errorf("%s = %v, want %q", key, doc[key], want)
		}
	}
	for _, key := range []string{"authorization_endpoint", "code_challenge_methods_supported", "userinfo_endpoint", "scopes_supported"} {
		if _, ok := doc[key]; ok {
			t.Errorf("%s should be absent: %v", key, doc[key])
		}
	}
	wantLists := map[string][]string{
		"grant_types_supported":                 {"client_credentials"},
		"token_endpoint_auth_methods_supported": {"client_secret_basic", "client_secret_post", "none"},
		"response_types_supported":              {"token"},
		"subject_types_supported":               {"public"},
		"claims_supported":                      {"iss", "sub", "aud", "exp", "nbf", "iat", "jti", "scope", "client_id"},
		"id_token_signing_alg_values_supported": {"RS256"},
	}
	for key, want := range wantLists {
		got, ok := doc[key].([]any)
		if !ok {
			t.Errorf("%s missing or wrong type: %#v", key, doc[key])
			continue
		}
		gotStrings := make([]string, len(got))
		for i, value := range got {
			gotStrings[i], _ = value.(string)
		}
		if !reflect.DeepEqual(gotStrings, want) {
			t.Errorf("%s = %v, want %v", key, gotStrings, want)
		}
	}
}

func TestBothDiscoveryPathsAgree(t *testing.T) {
	ts, _, _ := newOptionTestServer(t, []Option{WithScopes([]string{"read", "write"})})

	fetch := func(path string) map[string]any {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		data, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status = %d", path, resp.StatusCode)
		}
		return decodeBody(t, data)
	}

	oidc := fetch("/.well-known/openid-configuration")
	authServer := fetch("/.well-known/oauth-authorization-server")
	if !reflect.DeepEqual(oidc, authServer) {
		t.Fatalf("discovery documents differ:\nOIDC: %#v\nRFC 8414: %#v", oidc, authServer)
	}
	if scopes, ok := authServer["scopes_supported"].([]any); !ok || len(scopes) != 2 || scopes[0] != "read" || scopes[1] != "write" {
		t.Fatalf("scopes_supported = %#v", authServer["scopes_supported"])
	}

	resp, err := http.Post(ts.URL+"/.well-known/oauth-authorization-server", "application/json", nil)
	if err != nil {
		t.Fatalf("POST RFC 8414 metadata: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST RFC 8414 metadata status = %d, want 405", resp.StatusCode)
	}
}

func TestDiscoveryExtraMetadataIsAdditiveAndCoreFieldsWin(t *testing.T) {
	extra := map[string]any{
		"service_documentation":  "https://example.test/docs",
		"issuer":                 "https://attacker.example",
		"jwks_uri":               "https://attacker.example/jwks",
		"token_endpoint":         "https://attacker.example/token",
		"introspection_endpoint": "https://attacker.example/introspect",
	}
	ts, _, _ := newOptionTestServer(t, []Option{WithDiscoveryExtra(extra)})

	for _, path := range []string{"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		data, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		doc := decodeBody(t, data)
		if doc["service_documentation"] != extra["service_documentation"] {
			t.Errorf("%s service_documentation = %v", path, doc["service_documentation"])
		}
		if doc["issuer"] != testIssuer {
			t.Errorf("%s issuer = %v, want derived", path, doc["issuer"])
		}
		if doc["jwks_uri"] != testIssuer+"/.well-known/jwks.json" {
			t.Errorf("%s jwks_uri = %v, want derived", path, doc["jwks_uri"])
		}
		if doc["token_endpoint"] != testIssuer+"/oauth/token" {
			t.Errorf("%s token_endpoint = %v, want derived", path, doc["token_endpoint"])
		}
		if doc["introspection_endpoint"] != testIssuer+"/introspect" {
			t.Errorf("%s introspection_endpoint = %v, want derived", path, doc["introspection_endpoint"])
		}
	}
}

func TestOAuthTokenEndpointMintsGenericClaims(t *testing.T) {
	ts, _, _ := newOptionTestServer(t, nil, keyring.AlgRS256)

	resp, data := postForm(t, ts.Client(), ts.URL+"/oauth/token", url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {"test-client"},
		"scope":      {"  read   write "},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, data)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := resp.Header.Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q, want no-cache", got)
	}
	doc := decodeBody(t, data)
	if doc["token_type"] != "Bearer" {
		t.Errorf("token_type = %v", doc["token_type"])
	}
	if doc["scope"] != "read write" {
		t.Errorf("scope = %v, want normalized", doc["scope"])
	}
	if doc["expires_in"].(float64) != 3600 {
		t.Errorf("expires_in = %v, want 3600", doc["expires_in"])
	}
	token, _ := doc["access_token"].(string)
	if token == "" {
		t.Fatal("access_token missing")
	}

	claims := oauthTokenClaims(t, ts, token, keyring.AlgRS256)
	if claims["iss"] != testIssuer || claims["sub"] != "test-client" || claims["client_id"] != "test-client" {
		t.Errorf("identity claims = %#v", claims)
	}
	if claims["scope"] != "read write" {
		t.Errorf("scope claim = %v", claims["scope"])
	}
	if _, ok := claims["aud"]; ok {
		t.Errorf("aud should be omitted: %v", claims["aud"])
	}
	for _, legacy := range []string{"capabilities", "idtyp", "allowedResources", "version"} {
		if _, ok := claims[legacy]; ok {
			t.Errorf("legacy claim %q should be absent", legacy)
		}
	}
	for _, name := range []string{"iat", "nbf", "exp"} {
		if _, ok := claims[name]; !ok {
			t.Errorf("claim %q missing", name)
		}
	}
	if jti, ok := claims["jti"].(string); !ok || len(jti) != 36 {
		t.Errorf("jti = %#v, want UUID-formatted string", claims["jti"])
	}
}

func TestOAuthTokenEndpointScopeAndAudienceOptions(t *testing.T) {
	t.Run("scope omitted", func(t *testing.T) {
		ts, _, _ := newOptionTestServer(t, nil)
		resp, data := postForm(t, ts.Client(), ts.URL+"/oauth/token", url.Values{
			"grant_type": {"client_credentials"},
			"client_id":  {"client"},
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, body = %s", resp.StatusCode, data)
		}
		doc := decodeBody(t, data)
		if _, ok := doc["scope"]; ok {
			t.Errorf("response scope should be absent: %v", doc["scope"])
		}
		claims := oauthTokenClaims(t, ts, doc["access_token"].(string), keyring.AlgRS256)
		if _, ok := claims["scope"]; ok {
			t.Errorf("token scope should be absent: %v", claims["scope"])
		}
	})

	t.Run("audience configured", func(t *testing.T) {
		ts, _, _ := newOptionTestServer(t, []Option{WithAudience("my-api")})
		resp, data := postForm(t, ts.Client(), ts.URL+"/oauth/token", url.Values{
			"grant_type": {"client_credentials"},
			"client_id":  {"client"},
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, body = %s", resp.StatusCode, data)
		}
		claims := oauthTokenClaims(t, ts, decodeBody(t, data)["access_token"].(string), keyring.AlgRS256)
		if !strings.Contains(fmt.Sprint(claims["aud"]), "my-api") {
			t.Errorf("aud = %v, want my-api", claims["aud"])
		}
	})

	t.Run("unlisted scope accepted", func(t *testing.T) {
		ts, _, _ := newOptionTestServer(t, []Option{WithScopes([]string{"read"})})
		resp, data := postForm(t, ts.Client(), ts.URL+"/oauth/token", url.Values{
			"grant_type": {"client_credentials"},
			"client_id":  {"client"},
			"scope":      {"admin"},
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, body = %s", resp.StatusCode, data)
		}
		claims := oauthTokenClaims(t, ts, decodeBody(t, data)["access_token"].(string), keyring.AlgRS256)
		if claims["scope"] != "admin" {
			t.Errorf("scope = %v, want admin", claims["scope"])
		}
	})
}

func TestOAuthTokenEndpointAuthentication(t *testing.T) {
	ts, _, _ := newOptionTestServer(t, nil)

	tests := []struct {
		name     string
		build    func() *http.Request
		wantCode int
	}{
		{
			name: "basic auth",
			build: func() *http.Request {
				req, _ := http.NewRequest(http.MethodPost, ts.URL+"/oauth/token", strings.NewReader("grant_type=client_credentials"))
				req.Header.Set("Content-Type", oauthFormContentType)
				req.SetBasicAuth("basic-client", "basic-secret")
				return req
			},
			wantCode: http.StatusOK,
		},
		{
			name: "form secret",
			build: func() *http.Request {
				req, _ := http.NewRequest(http.MethodPost, ts.URL+"/oauth/token", strings.NewReader("grant_type=client_credentials&client_id=form-client&client_secret=wrong"))
				req.Header.Set("Content-Type", oauthFormContentType)
				return req
			},
			wantCode: http.StatusOK,
		},
		{
			name: "client id only",
			build: func() *http.Request {
				req, _ := http.NewRequest(http.MethodPost, ts.URL+"/oauth/token", strings.NewReader("grant_type=client_credentials&client_id=id-only"))
				req.Header.Set("Content-Type", oauthFormContentType)
				return req
			},
			wantCode: http.StatusOK,
		},
		{
			name: "missing client id",
			build: func() *http.Request {
				req, _ := http.NewRequest(http.MethodPost, ts.URL+"/oauth/token", strings.NewReader("grant_type=client_credentials"))
				req.Header.Set("Content-Type", oauthFormContentType)
				return req
			},
			wantCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := ts.Client().Do(tt.build())
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != tt.wantCode {
				data, _ := io.ReadAll(resp.Body)
				t.Fatalf("status = %d, want %d (body %s)", resp.StatusCode, tt.wantCode, data)
			}
		})
	}
}

func TestOAuthTokenEndpointRejectsBadRequests(t *testing.T) {
	ts, _, _ := newOptionTestServer(t, nil)

	tests := []struct {
		name      string
		form      url.Values
		body      string
		content   string
		wantCode  int
		wantError string
	}{
		{name: "missing grant type", form: url.Values{"client_id": {"client"}}, wantCode: http.StatusBadRequest, wantError: "invalid_request"},
		{name: "unsupported grant type", form: url.Values{"grant_type": {"password"}, "client_id": {"client"}}, wantCode: http.StatusBadRequest, wantError: "unsupported_grant_type"},
		{name: "json body", body: `{"grant_type":"client_credentials","client_id":"client"}`, content: "application/json", wantCode: http.StatusBadRequest, wantError: "invalid_request"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resp *http.Response
			var data []byte
			var err error
			if tt.body != "" {
				req, reqErr := http.NewRequest(http.MethodPost, ts.URL+"/oauth/token", strings.NewReader(tt.body))
				if reqErr != nil {
					t.Fatalf("create request: %v", reqErr)
				}
				req.Header.Set("Content-Type", tt.content)
				resp, err = ts.Client().Do(req)
				if err != nil {
					t.Fatalf("request: %v", err)
				}
				defer func() { _ = resp.Body.Close() }()
				data, _ = io.ReadAll(resp.Body)
			} else {
				resp, data = postForm(t, ts.Client(), ts.URL+"/oauth/token", tt.form)
			}
			if resp.StatusCode != tt.wantCode {
				t.Fatalf("status = %d, want %d (body %s)", resp.StatusCode, tt.wantCode, data)
			}
			doc := decodeBody(t, data)
			if doc["error"] != tt.wantError {
				t.Errorf("error = %v, want %q", doc["error"], tt.wantError)
			}
			if doc["error_description"] == "" || doc["error_description"] == nil {
				t.Errorf("error_description missing: %#v", doc)
			}
		})
	}

	resp, err := http.Get(ts.URL + "/oauth/token")
	if err != nil {
		t.Fatalf("GET /oauth/token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /oauth/token status = %d, want 405", resp.StatusCode)
	}
}

func TestOAuthTokenEndpointAlgorithmSelection(t *testing.T) {
	t.Run("explicit algorithm honored", func(t *testing.T) {
		ts, _, _ := newOptionTestServer(t, nil, keyring.AlgRS256, keyring.AlgES256)
		resp, data := postForm(t, ts.Client(), ts.URL+"/oauth/token", url.Values{
			"grant_type": {"client_credentials"},
			"client_id":  {"client"},
			"alg":        {"ES256"},
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, body = %s", resp.StatusCode, data)
		}
		token := decodeBody(t, data)["access_token"].(string)
		if got := tokenAlgorithm(t, token); got != "ES256" {
			t.Errorf("token alg = %q, want ES256", got)
		}
	})

	t.Run("falls back to first enabled when RS256 disabled", func(t *testing.T) {
		ts, _, _ := newOptionTestServer(t, nil, keyring.AlgES256)
		resp, data := postForm(t, ts.Client(), ts.URL+"/oauth/token", url.Values{
			"grant_type": {"client_credentials"},
			"client_id":  {"client"},
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, body = %s", resp.StatusCode, data)
		}
		token := decodeBody(t, data)["access_token"].(string)
		if got := tokenAlgorithm(t, token); got != "ES256" {
			t.Errorf("token alg = %q, want ES256", got)
		}
	})

	t.Run("RS256 preferred when enabled", func(t *testing.T) {
		ts, _, _ := newOptionTestServer(t, nil, keyring.AlgES256, keyring.AlgRS256)
		resp, data := postForm(t, ts.Client(), ts.URL+"/oauth/token", url.Values{
			"grant_type": {"client_credentials"},
			"client_id":  {"client"},
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, body = %s", resp.StatusCode, data)
		}
		token := decodeBody(t, data)["access_token"].(string)
		if got := tokenAlgorithm(t, token); got != "RS256" {
			t.Errorf("token alg = %q, want RS256", got)
		}
	})

	for _, alg := range []string{"EdDSA", "HS256", "not-an-alg"} {
		t.Run("rejects "+alg, func(t *testing.T) {
			ts, _, _ := newOptionTestServer(t, nil, keyring.AlgRS256)
			resp, data := postForm(t, ts.Client(), ts.URL+"/oauth/token", url.Values{
				"grant_type": {"client_credentials"},
				"client_id":  {"client"},
				"alg":        {alg},
			})
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s)", resp.StatusCode, data)
			}
			if doc := decodeBody(t, data); doc["error"] != "invalid_request" {
				t.Errorf("error = %v, want invalid_request", doc["error"])
			}
		})
	}
}

func TestOAuthTokenEndpointTTLSelection(t *testing.T) {
	tests := []struct {
		name       string
		ttl        string
		wantCode   int
		wantExpiry float64
	}{
		{name: "honored", ttl: "5m", wantCode: http.StatusOK, wantExpiry: 300},
		{name: "zero allowed", ttl: "0s", wantCode: http.StatusOK, wantExpiry: 0},
		{name: "cap enforced", ttl: "25h", wantCode: http.StatusBadRequest},
		{name: "invalid", ttl: "soon", wantCode: http.StatusBadRequest},
		{name: "negative", ttl: "-1s", wantCode: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts, _, _ := newOptionTestServer(t, nil)
			resp, data := postForm(t, ts.Client(), ts.URL+"/oauth/token", url.Values{
				"grant_type": {"client_credentials"},
				"client_id":  {"client"},
				"ttl":        {tt.ttl},
			})
			if resp.StatusCode != tt.wantCode {
				t.Fatalf("status = %d, want %d (body %s)", resp.StatusCode, tt.wantCode, data)
			}
			doc := decodeBody(t, data)
			if tt.wantCode != http.StatusOK {
				if doc["error"] != "invalid_request" {
					t.Errorf("error = %v, want invalid_request", doc["error"])
				}
				return
			}
			if doc["expires_in"].(float64) != tt.wantExpiry {
				t.Errorf("expires_in = %v, want %v", doc["expires_in"], tt.wantExpiry)
			}
			if tt.wantExpiry == 0 {
				return
			}
			claims := oauthTokenClaims(t, ts, doc["access_token"].(string), keyring.AlgRS256)
			exp, _ := claims["exp"].(float64)
			iat, _ := claims["iat"].(float64)
			if got := exp - iat; got != tt.wantExpiry {
				t.Errorf("exp - iat = %v, want %v", got, tt.wantExpiry)
			}
		})
	}
}

func TestOAuthTokenEndpointBodyLimit(t *testing.T) {
	ts, _, _ := newOptionTestServer(t, nil)
	form := url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {"client"},
		"junk":       {strings.Repeat("a", maxRequestBody)},
	}
	resp, data := postForm(t, ts.Client(), ts.URL+"/oauth/token", form)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", resp.StatusCode, data)
	}
	if doc := decodeBody(t, data); doc["error"] != "invalid_request" {
		t.Errorf("error = %v, want invalid_request", doc["error"])
	}
}

func TestOAuthTokenEndpointErrorMappings(t *testing.T) {
	t.Run("no active key", func(t *testing.T) {
		ring := &noActiveKeyRing{}
		factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
		srv := New(ring, factory, testIssuer, "test-version", 100, 200)
		ts := httptest.NewServer(srv.Handler())
		t.Cleanup(func() {
			ts.Close()
			srv.Close()
		})
		resp, data := postForm(t, ts.Client(), ts.URL+"/oauth/token", url.Values{
			"grant_type": {"client_credentials"},
			"client_id":  {"client"},
		})
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503 (body %s)", resp.StatusCode, data)
		}
		doc := decodeBody(t, data)
		if doc["error"] != "temporarily_unavailable" || doc["error_description"] == nil {
			t.Errorf("body = %#v", doc)
		}
	})

	t.Run("internal failure", func(t *testing.T) {
		ring := &internalErrRing{}
		factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
		srv := New(ring, factory, testIssuer, "test-version", 100, 200)
		ts := httptest.NewServer(srv.Handler())
		t.Cleanup(func() {
			ts.Close()
			srv.Close()
		})
		resp, data := postForm(t, ts.Client(), ts.URL+"/oauth/token", url.Values{
			"grant_type": {"client_credentials"},
			"client_id":  {"client"},
		})
		if resp.StatusCode != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500 (body %s)", resp.StatusCode, data)
		}
		doc := decodeBody(t, data)
		if doc["error"] != "server_error" || doc["error_description"] == nil {
			t.Errorf("body = %#v", doc)
		}
	})
}

func TestOAuthTokenEndpointAuditing(t *testing.T) {
	ring, err := keyring.New(time.Hour, []keyring.Algorithm{keyring.AlgRS256})
	if err != nil {
		t.Fatalf("keyring.New() error = %v", err)
	}
	factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
	var buf bytes.Buffer
	srv := New(ring, factory, testIssuer, "test-version", 100, 200,
		WithLogger(slog.New(slog.NewJSONHandler(&buf, nil))),
		WithAudience("my-api"),
	)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() {
		ts.Close()
		srv.Close()
	})

	resp, data := postForm(t, ts.Client(), ts.URL+"/oauth/token", url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"audit-client"},
		"client_secret": {"super-secret"},
		"scope":         {"read write"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, data)
	}
	token := decodeBody(t, data)["access_token"].(string)

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("decode audit log: %v (%s)", err, buf.String())
	}
	if entry["event"] != "oauth_token_minted" {
		t.Errorf("event = %v, want oauth_token_minted", entry["event"])
	}
	if entry["alg"] != "RS256" || entry["scope"] != "read write" || entry["expires_in"].(float64) != 3600 {
		t.Errorf("audit fields = %#v", entry)
	}
	if entry["path"] != "/oauth/token" || entry["method"] != http.MethodPost || entry["request_id"] == "" {
		t.Errorf("audit request fields = %#v", entry)
	}
	logged := buf.String()
	if strings.Contains(logged, "super-secret") || strings.Contains(logged, token) {
		t.Fatalf("audit log leaked secret or token: %s", logged)
	}

	buf.Reset()
	resp, data = postForm(t, ts.Client(), ts.URL+"/oauth/token", url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"audit-client"},
		"client_secret": {"super-secret"},
		"alg":           {"EdDSA"},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", resp.StatusCode, data)
	}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("decode failure audit log: %v (%s)", err, buf.String())
	}
	if entry["event"] != "oauth_token_mint_failed" || entry["error"] != "invalid_request" {
		t.Errorf("failure audit fields = %#v", entry)
	}
	if strings.Contains(buf.String(), "super-secret") {
		t.Fatalf("failure audit log leaked secret: %s", buf.String())
	}
}

func TestIntrospectReportsActiveToken(t *testing.T) {
	ts, ring, _ := newOptionTestServer(t, nil)
	token := mintVerifyToken(t, ring, map[string]any{
		"sub":          "user-1",
		"scope":        "read write",
		"custom_claim": "custom-value",
	})

	resp, data := postForm(t, ts.Client(), ts.URL+"/introspect", url.Values{
		"token":           {token},
		"token_type_hint": {"refresh_token"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, data)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := resp.Header.Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q, want no-cache", got)
	}
	doc := decodeBody(t, data)
	if doc["active"] != true {
		t.Fatalf("active = %v, want true", doc["active"])
	}
	if doc["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", doc["token_type"])
	}
	if doc["sub"] != "user-1" || doc["scope"] != "read write" || doc["custom_claim"] != "custom-value" {
		t.Errorf("claims not echoed: %#v", doc)
	}
}

func TestIntrospectActiveAndTokenTypeAreAuthoritative(t *testing.T) {
	ts, ring, _ := newOptionTestServer(t, nil)
	token := mintVerifyToken(t, ring, map[string]any{
		"sub":        "user-1",
		"active":     false,
		"token_type": "Custom",
	})

	resp, data := postForm(t, ts.Client(), ts.URL+"/introspect", url.Values{"token": {token}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, data)
	}
	doc := decodeBody(t, data)
	if doc["active"] != true {
		t.Errorf("active = %v, want true", doc["active"])
	}
	if doc["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", doc["token_type"])
	}
}

func TestIntrospectReportsInactiveTokens(t *testing.T) {
	ts, ring, _ := newOptionTestServer(t, nil)

	cases := []struct {
		name  string
		token string
	}{
		{name: "expired", token: mintVerifyToken(t, ring, map[string]any{"sub": "user-1", "exp": "-5m", "custom_claim": "secret"})},
		{name: "not yet valid", token: mintVerifyToken(t, ring, map[string]any{"sub": "user-1", "nbf": "1h"})},
		{name: "wrong issuer", token: mintVerifyToken(t, ring, map[string]any{"sub": "user-1", "iss": "https://attacker.example"})},
		{name: "unknown kid", token: signedVerifyToken(t, ring, map[string]any{"iss": testIssuer, "sub": "user-1", "exp": time.Now().Add(time.Hour).Unix()}, map[string]any{"kid": "unknown-kid"})},
		{name: "bad signature", token: tamperServerToken(mintVerifyToken(t, ring, map[string]any{"sub": "user-1"}))},
		{name: "malformed", token: "not-a-compact-jws"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, data := postForm(t, ts.Client(), ts.URL+"/introspect", url.Values{"token": {tc.token}})
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, data)
			}
			doc := decodeBody(t, data)
			if len(doc) != 1 || doc["active"] != false {
				t.Fatalf("inactive response = %#v, want only active:false", doc)
			}
		})
	}
}

func TestIntrospectRetiredKeyWithinGraceIsActive(t *testing.T) {
	ring, err := keyring.New(time.Hour, []keyring.Algorithm{keyring.AlgRS256})
	if err != nil {
		t.Fatalf("keyring.New() error = %v", err)
	}
	factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
	srv := New(ring, factory, testIssuer, "test-version", 100, 200)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() {
		ts.Close()
		srv.Close()
	})

	oldKey, err := ring.Signer(keyring.AlgRS256)
	if err != nil {
		t.Fatalf("Signer() error = %v", err)
	}
	if err := ring.Rotate(); err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	now := time.Now().UTC()
	tok := jwt5.NewWithClaims(jwt5.SigningMethodRS256, jwt5.MapClaims{
		"iss": testIssuer,
		"sub": "retired-client",
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = oldKey.Kid()
	signed, err := tok.SignedString(oldKey.Private)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	resp, data := postForm(t, ts.Client(), ts.URL+"/introspect", url.Values{"token": {signed}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, data)
	}
	doc := decodeBody(t, data)
	if doc["active"] != true {
		t.Fatalf("active = %v, want true (body %#v)", doc["active"], doc)
	}
}

func TestIntrospectRequestErrors(t *testing.T) {
	ts, _, _ := newOptionTestServer(t, nil)

	resp, data := postForm(t, ts.Client(), ts.URL+"/introspect", url.Values{})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing token status = %d, want 400 (body %s)", resp.StatusCode, data)
	}
	if doc := decodeBody(t, data); doc["error"] != "invalid_request" || doc["error_description"] == nil {
		t.Errorf("missing token body = %#v", doc)
	}

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/introspect", strings.NewReader(`{"token":"x"}`))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	jsonResp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("non-form request: %v", err)
	}
	defer func() { _ = jsonResp.Body.Close() }()
	jsonData, _ := io.ReadAll(jsonResp.Body)
	if jsonResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("non-form status = %d, want 400 (body %s)", jsonResp.StatusCode, jsonData)
	}
	if doc := decodeBody(t, jsonData); doc["error"] != "invalid_request" {
		t.Errorf("non-form error = %v", doc["error"])
	}

	resp, data = postForm(t, ts.Client(), ts.URL+"/introspect", url.Values{"token": {strings.Repeat("a", maxRequestBody)}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized status = %d, want 400 (body %s)", resp.StatusCode, data)
	}

	getResp, err := http.Get(ts.URL + "/introspect")
	if err != nil {
		t.Fatalf("GET /introspect: %v", err)
	}
	defer func() { _ = getResp.Body.Close() }()
	if getResp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /introspect status = %d, want 405", getResp.StatusCode)
	}
}

func TestIntrospectInternalError(t *testing.T) {
	realRing, err := keyring.New(time.Hour, []keyring.Algorithm{keyring.AlgRS256})
	if err != nil {
		t.Fatalf("keyring.New() error = %v", err)
	}
	token := mintVerifyToken(t, realRing, map[string]any{"sub": "user-1"})

	ring := &internalErrRing{}
	factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
	srv := New(ring, factory, testIssuer, "test-version", 100, 200)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() {
		ts.Close()
		srv.Close()
	})

	resp, data := postForm(t, ts.Client(), ts.URL+"/introspect", url.Values{"token": {token}})
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (body %s)", resp.StatusCode, data)
	}
	if doc := decodeBody(t, data); doc["error"] != "server_error" {
		t.Errorf("error = %v, want server_error", doc["error"])
	}
}

func TestIntrospectAuditing(t *testing.T) {
	ring, err := keyring.New(time.Hour, []keyring.Algorithm{keyring.AlgRS256})
	if err != nil {
		t.Fatalf("keyring.New() error = %v", err)
	}
	factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
	var buf bytes.Buffer
	srv := New(ring, factory, testIssuer, "test-version", 100, 200,
		WithLogger(slog.New(slog.NewJSONHandler(&buf, nil))),
	)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() {
		ts.Close()
		srv.Close()
	})

	activeToken := mintVerifyToken(t, ring, map[string]any{"sub": "user-1"})
	resp, data := postForm(t, ts.Client(), ts.URL+"/introspect", url.Values{"token": {activeToken}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, data)
	}
	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("decode audit log: %v (%s)", err, buf.String())
	}
	if entry["event"] != "token_introspected" || entry["active"] != true {
		t.Errorf("audit fields = %#v", entry)
	}
	if entry["path"] != "/introspect" || entry["method"] != http.MethodPost || entry["request_id"] == "" {
		t.Errorf("audit request fields = %#v", entry)
	}
	if strings.Contains(buf.String(), activeToken) || strings.Contains(buf.String(), "user-1") {
		t.Fatalf("audit log leaked token or claims: %s", buf.String())
	}

	buf.Reset()
	expired := mintVerifyToken(t, ring, map[string]any{"sub": "user-1", "exp": "-5m"})
	resp, data = postForm(t, ts.Client(), ts.URL+"/introspect", url.Values{"token": {expired}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, data)
	}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("decode audit log: %v (%s)", err, buf.String())
	}
	if entry["active"] != false || entry["reason"] != "expired" {
		t.Errorf("inactive audit fields = %#v", entry)
	}
	if strings.Contains(buf.String(), expired) {
		t.Fatalf("audit log leaked token: %s", buf.String())
	}
}

func TestLegacyOAuthTokenEndpointAlgorithmAndTTL(t *testing.T) {
	newLegacyRequest := func(t *testing.T, ts *httptest.Server, query string) (*http.Response, []byte) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/v2/oauth/token?"+query, nil)
		if err != nil {
			t.Fatalf("create request: %v", err)
		}
		req.Header.Set("X-Client-Id", "client")
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		data, _ := io.ReadAll(resp.Body)
		return resp, data
	}

	t.Run("explicit algorithm honored", func(t *testing.T) {
		ts, _, _ := newOptionTestServer(t, nil, keyring.AlgRS256, keyring.AlgES256)
		resp, data := newLegacyRequest(t, ts, "Scope=read&alg=ES256")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, body = %s", resp.StatusCode, data)
		}
		token := decodeBody(t, data)["access_token"].(string)
		if got := tokenAlgorithm(t, token); got != "ES256" {
			t.Errorf("token alg = %q, want ES256", got)
		}
	})

	t.Run("falls back to first enabled", func(t *testing.T) {
		ts, _, _ := newOptionTestServer(t, nil, keyring.AlgES256)
		resp, data := newLegacyRequest(t, ts, "Scope=read")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, body = %s", resp.StatusCode, data)
		}
		token := decodeBody(t, data)["access_token"].(string)
		if got := tokenAlgorithm(t, token); got != "ES256" {
			t.Errorf("token alg = %q, want ES256", got)
		}
	})

	t.Run("ttl honored", func(t *testing.T) {
		ts, _, _ := newOptionTestServer(t, nil)
		resp, data := newLegacyRequest(t, ts, "Scope=read&ttl=5m")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, body = %s", resp.StatusCode, data)
		}
		if got := decodeBody(t, data)["expires_in"].(float64); got != 300 {
			t.Errorf("expires_in = %v, want 300", got)
		}
	})

	for _, tc := range []struct{ name, query string }{
		{name: "ttl cap", query: "Scope=read&ttl=25h"},
		{name: "invalid ttl", query: "Scope=read&ttl=soon"},
		{name: "negative ttl", query: "Scope=read&ttl=-1s"},
		{name: "unknown algorithm", query: "Scope=read&alg=HS256"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts, _, _ := newOptionTestServer(t, nil)
			resp, data := newLegacyRequest(t, ts, tc.query)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s)", resp.StatusCode, data)
			}
		})
	}
}

func TestLegacyOAuthTokenEndpointAuditsSelectedAlgorithm(t *testing.T) {
	ring, err := keyring.New(time.Hour, []keyring.Algorithm{keyring.AlgRS256, keyring.AlgES256})
	if err != nil {
		t.Fatalf("keyring.New() error = %v", err)
	}
	factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
	var buf bytes.Buffer
	srv := New(ring, factory, testIssuer, "test-version", 100, 200,
		WithLogger(slog.New(slog.NewJSONHandler(&buf, nil))),
	)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() {
		ts.Close()
		srv.Close()
	})

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v2/oauth/token?Scope=read&alg=ES256", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("X-Client-Id", "client")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, data)
	}

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("decode audit log: %v (%s)", err, buf.String())
	}
	if entry["event"] != "token_minted" || entry["alg"] != "ES256" {
		t.Fatalf("audit fields = %#v", entry)
	}
}

func TestOAuthDiscoveryTokenVerifyIntrospectEndToEnd(t *testing.T) {
	ring, err := keyring.New(time.Hour, []keyring.Algorithm{keyring.AlgRS256, keyring.AlgES256})
	if err != nil {
		t.Fatalf("keyring.New() error = %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	issuer := "http://" + listener.Addr().String()
	factory := tokenfactory.NewFactory(ring, issuer, time.Hour, 24*time.Hour)
	srv := New(ring, factory, issuer, "test-version", 100, 200,
		WithAudience("my-api"),
		WithScopes([]string{"read", "write"}),
	)
	ts := httptest.NewUnstartedServer(nil)
	ts.Listener = listener
	ts.Config.Handler = srv.Handler()
	ts.Start()
	t.Cleanup(func() {
		ts.Close()
		srv.Close()
	})

	resp, err := http.Get(ts.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	discoveryData, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status = %d", resp.StatusCode)
	}
	discovery := decodeBody(t, discoveryData)
	tokenEndpoint, _ := discovery["token_endpoint"].(string)
	if tokenEndpoint != ts.URL+"/oauth/token" {
		t.Fatalf("token_endpoint = %q, want %q", tokenEndpoint, ts.URL+"/oauth/token")
	}

	tokenResp, tokenData := postForm(t, ts.Client(), tokenEndpoint, url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {"e2e-client"},
		"scope":      {"read write"},
	})
	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("token status = %d, body = %s", tokenResp.StatusCode, tokenData)
	}
	tokenDoc := decodeBody(t, tokenData)
	token, _ := tokenDoc["access_token"].(string)
	if token == "" {
		t.Fatal("access_token missing")
	}

	verifyResp, verifyData := postJSON(t, ts.URL+"/verify", `{"token":"`+token+`"}`)
	if verifyResp.StatusCode != http.StatusOK {
		t.Fatalf("verify status = %d, body = %s", verifyResp.StatusCode, verifyData)
	}
	verdict := decodeVerdict(t, verifyData)
	if verdict["valid"] != true {
		t.Fatalf("verdict = %#v", verdict)
	}
	claims, _ := verdict["claims"].(map[string]any)
	if claims["sub"] != "e2e-client" || !strings.Contains(fmt.Sprint(claims["aud"]), "my-api") || claims["scope"] != "read write" {
		t.Fatalf("claims = %#v", claims)
	}

	introspectResp, introspectData := postForm(t, ts.Client(), ts.URL+"/introspect", url.Values{"token": {token}})
	if introspectResp.StatusCode != http.StatusOK {
		t.Fatalf("introspect status = %d, body = %s", introspectResp.StatusCode, introspectData)
	}
	introspection := decodeBody(t, introspectData)
	if introspection["active"] != true || introspection["token_type"] != "Bearer" || introspection["sub"] != "e2e-client" {
		t.Fatalf("introspection = %#v", introspection)
	}
}
