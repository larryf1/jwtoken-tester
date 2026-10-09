package tester

// Demo scenarios for the embeddable issuer (pkg/tester).
//
// Run with:
//
//	go test ./pkg/tester -run TestUseCaseSimulation -v
//
// Each subtest narrates a small end-to-end scenario against an in-memory
// jwtoken-tester instance, the way a real JWT-aware service would use it.

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	jwt5 "github.com/golang-jwt/jwt/v5"

	"github.com/larryf1/jwtoken-tester/internal/keyring"
	"github.com/larryf1/jwtoken-tester/internal/tokenfactory"
)

func TestUseCaseSimulation(t *testing.T) {
	t.Run("01 bootstrap and discovery", func(t *testing.T) {
		s, url := NewServer(t)

		t.Log("Booted an ephemeral issuer: keys live in memory and vanish on shutdown.")
		t.Logf("    playground URL: %s", url)
		t.Logf("    issuer:         %s", s.Issuer())

		_, body := httpGet(t, url+"/")
		showJSON(t, "GET /", body)

		_, body = httpGet(t, url+"/healthz")
		showJSON(t, "GET /healthz", body)

		_, body = httpGet(t, url+"/.well-known/openid-configuration")
		showJSON(t, "GET /.well-known/openid-configuration", body)

		_, body = httpGet(t, url+"/.well-known/jwks.json")
		showJSON(t, "GET /.well-known/jwks.json", body)

		set := fetchJWKS(t, url+"/.well-known/jwks.json")
		for i := 0; i < set.Len(); i++ {
			k, present := set.Key(i)
			if !present {
				t.Fatalf("set.Key(%d) missing", i)
			}
			kid, _ := k.KeyID()
			alg, _ := k.Algorithm()
			kty := k.KeyType()
			t.Logf("    published key #%d: kid=%s alg=%v kty=%v", i, kid, alg, kty)
		}
		t.Log("That discovery doc + JWKS is everything real JWT middleware needs to configure itself.")
	})

	t.Run("02 mint a token and verify it", func(t *testing.T) {
		s, _ := NewServer(t, WithAlgorithms(keyring.AlgRS256))

		resp, err := s.TokenFactory().Mint(&tokenfactory.Request{
			Claims: map[string]any{
				"sub":   "user-123",
				"aud":   []string{"my-service"},
				"roles": []any{"admin"},
			},
		})
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}

		t.Log("Minted a token straight through TokenFactory().Mint(...).")
		t.Logf("    response envelope: token_type=%s expires_in=%ds", resp.TokenType, resp.ExpiresIn)
		showToken(t, resp.AccessToken)

		t.Log("Now a 'protected service' downloads the JWKS and verifies the signature + issuer + expiry.")
		tok, err := demoVerify(t, s, resp.AccessToken, string(keyring.AlgRS256))
		if err != nil {
			t.Fatalf("protected service rejected a valid token: %v", err)
		}
		claims := tok.Claims.(jwt5.MapClaims)
		t.Logf("    ACCEPTED — validated claims: sub=%v aud=%v roles=%v", claims["sub"], claims["aud"], claims["roles"])
		t.Logf("    iss=%v", claims["iss"])
	})

	t.Run("03 mint via the HTTP /token endpoint", func(t *testing.T) {
		s, url := NewServer(t)

		body := `{"claims":{"sub":"user-999","aud":["api-gateway"],"tenant":"acme"},"alg":"EdDSA"}`
		t.Logf("POSTing the same request a curl user would: %s", body)
		resp, err := s.Client().Post(url+"/token", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("POST /token: %v", err)
		}
		rbody, err := readAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatalf("read /token response: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("POST /token -> %d: %s", resp.StatusCode, string(rbody))
		}

		var envelope struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			ExpiresIn   int64  `json:"expires_in"`
		}
		if err := json.Unmarshal(rbody, &envelope); err != nil {
			t.Fatalf("decode envelope: %v", err)
		}
		showJSON(t, "POST /token", rbody)
		showToken(t, envelope.AccessToken)
		t.Log("This token is EdDSA-signed; the demo service below accepts it without special-casing.")

		if _, err := demoVerify(t, s, envelope.AccessToken, "EdDSA"); err != nil {
			t.Fatalf("protected service rejected an EdDSA token: %v", err)
		}
		t.Log("    ACCEPTED.")
	})

	t.Run("04 already-expired token is rejected", func(t *testing.T) {
		s, _ := NewServer(t, WithAlgorithms(keyring.AlgRS256))

		resp, err := s.TokenFactory().Mint(&tokenfactory.Request{
			Claims: map[string]any{"sub": "ghost", "exp": "-5m"},
		})
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		t.Log("Minted an ALREADY-EXPIRED token (exp \"-5m\"). The issuer happily mints it —")
		t.Log("you need nonexpiring negatives to test your middleware's expiry handling.")
		showToken(t, resp.AccessToken)

		t.Log("The protected service checks exp and turns it away:")
		if _, err := demoVerify(t, s, resp.AccessToken, string(keyring.AlgRS256)); err == nil {
			t.Fatal("expected the expired token to be rejected")
		} else {
			t.Logf("    rejected: %v", err)
		}
	})

	t.Run("05 token for the wrong issuer is rejected", func(t *testing.T) {
		s, _ := NewServer(t, WithAlgorithms(keyring.AlgRS256))

		resp, err := s.TokenFactory().Mint(&tokenfactory.Request{
			Claims: map[string]any{"iss": "https://attacker.example", "sub": "admin"},
		})
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		t.Log("An attacker-style token overrides the issuer claim to \"https://attacker.example\".")
		showToken(t, resp.AccessToken)

		t.Log("The demo service pins its issuer expectation and rejects the mismatch:")
		if _, err := demoVerify(t, s, resp.AccessToken, string(keyring.AlgRS256)); err == nil {
			t.Fatal("expected the wrong-issuer token to be rejected")
		} else {
			t.Logf("    rejected: %v", err)
		}
	})

	t.Run("06 tampered token is rejected", func(t *testing.T) {
		s, _ := NewServer(t, WithAlgorithms(keyring.AlgRS256))

		valid, err := s.TokenFactory().Mint(&tokenfactory.Request{})
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}

		dot := strings.LastIndex(valid.AccessToken, ".")
		sig := valid.AccessToken[dot+1:]
		mid := len(sig) / 2
		alt := "A"
		if string(sig[mid]) == "A" {
			alt = "B"
		}
		mutated := valid.AccessToken[:dot+1] + sig[:mid] + alt + sig[mid+1:]

		t.Log("Took a valid token and flipped one character inside its signature payload.")
		showToken(t, valid.AccessToken)
		t.Log("Mutated token (signature region rewritten):")
		t.Logf("    %.80s…", mutated)

		t.Log("Signature verification now fails:")
		if _, err := demoVerify(t, s, mutated, string(keyring.AlgRS256)); err == nil {
			t.Fatal("expected the tampered token to be rejected")
		} else {
			t.Logf("    rejected: %v", err)
		}
	})

	t.Run("07 fetch a single key by kid", func(t *testing.T) {
		_, url := NewServer(t, WithAlgorithms(keyring.AlgES256))

		set := fetchJWKS(t, url+"/.well-known/jwks.json")
		k, present := set.Key(0)
		if !present {
			t.Fatalf("set.Key(0) missing")
		}
		kid, _ := k.KeyID()

		t.Log("A consumer that knows exactly which key signed a token can fetch it alone:")
		code, body := httpGet(t, url+"/.well-known/jwks.json/"+kid)
		if code != http.StatusOK {
			t.Fatalf("key-by-kid GET -> %d", code)
		}
		showJSON(t, "GET /.well-known/jwks.json/{kid}", body)

		t.Log("An unknown kid gets a 404 rather than an empty set:")
		code, body = httpGet(t, url+"/.well-known/jwks.json/does-not-exist")
		t.Logf("    unknown kid -> %d: %s", code, strings.TrimSpace(string(body)))
		if code != http.StatusNotFound {
			t.Fatalf("unknown kid GET -> %d, want 404", code)
		}
	})

	t.Run("08 single-algorithm issuer", func(t *testing.T) {
		s, url := NewServer(t, WithAlgorithms(keyring.AlgES256))

		t.Log("Started the issuer with only ES256 enabled (WithAlgorithms).")
		_, body := httpGet(t, url+"/.well-known/openid-configuration")
		var disc map[string]any
		if err := json.Unmarshal(body, &disc); err != nil {
			t.Fatalf("decode discovery: %v", err)
		}
		t.Logf("    id_token_signing_alg_values_supported = %v", disc["id_token_signing_alg_values_supported"])

		if _, err := s.TokenFactory().Mint(&tokenfactory.Request{Alg: string(keyring.AlgES256)}); err != nil {
			t.Fatalf("ES256 mint: %v", err)
		}
		t.Log("ES256 minted fine.")

		if _, err := s.TokenFactory().Mint(&tokenfactory.Request{Alg: string(keyring.AlgEdDSA)}); err == nil {
			t.Fatal("expected EdDSA to be refused")
		} else {
			t.Logf("    factory request for EdDSA -> %v", err)
		}

		req, _ := http.NewRequest(http.MethodPost, url+"/token", strings.NewReader(`{"alg":"EdDSA"}`))
		req.Header.Set("Content-Type", "application/json")
		resp, err := s.Client().Do(req)
		if err != nil {
			t.Fatalf("POST /token (EdDSA): %v", err)
		}
		rbody, _ := readAll(resp.Body)
		_ = resp.Body.Close()
		t.Logf("    HTTP /token with EdDSA -> %d: %s", resp.StatusCode, strings.TrimSpace(string(rbody)))
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("POST /token (EdDSA) -> %d, want 400", resp.StatusCode)
		}
	})

	t.Run("09 key rotation and the grace window", func(t *testing.T) {
		s, _ := NewServer(t, WithAlgorithms(keyring.AlgRS256), WithGracePeriod(200*time.Millisecond))
		ring := s.KeyRing()

		t.Log("Key lifecycle demo: rotate -> old key stays published for GRACE_PERIOD -> then pruned.")
		first, err := s.TokenFactory().Mint(&tokenfactory.Request{Claims: map[string]any{"sub": "user-1"}})
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		kidA := kidOf(t, first.AccessToken)
		t.Logf("    token#1 signed with kid=%s", kidA)

		t.Log("Rotating now (the StartRotation ticker calls exactly this on ROTATION_INTERVAL)...")
		if err := ring.Rotate(); err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		set := fetchJWKS(t, s.URL()+"/.well-known/jwks.json")
		if _, ok := set.LookupKeyID(kidA); !ok {
			t.Fatalf("old kid %s missing from JWKS during grace", kidA)
		}
		t.Logf("    JWKS now holds %d keys; the retired kid=%s is still published.", set.Len(), kidA)

		if _, err := demoVerify(t, s, first.AccessToken, string(keyring.AlgRS256)); err != nil {
			t.Fatalf("token signed by the retired key failed during grace: %v", err)
		}
		t.Log("    outstanding tokens signed by the retired key STILL validate during the grace window.")

		t.Log("Simulating the end of GRACE_PERIOD (PruneAt drops + zeroizes over-age keys):")
		ring.PruneAt(time.Now().Add(500 * time.Millisecond))
		set = fetchJWKS(t, s.URL()+"/.well-known/jwks.json")
		if _, ok := set.LookupKeyID(kidA); ok {
			t.Fatal("old kid still present after grace expired")
		}
		t.Logf("    JWKS back to %d key(s); the retired key is gone.", set.Len())

		if _, err := demoVerify(t, s, first.AccessToken, string(keyring.AlgRS256)); err == nil {
			t.Fatal("expected the pre-rotation token to be rejected after grace")
		} else {
			t.Logf("    token#1 now rejected: %v", err)
		}

		second, err := s.TokenFactory().Mint(&tokenfactory.Request{Claims: map[string]any{"sub": "user-2"}})
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		t.Logf("    token#2 signed with kid=%s", kidOf(t, second.AccessToken))
		if _, err := demoVerify(t, s, second.AccessToken, string(keyring.AlgRS256)); err != nil {
			t.Fatalf("token signed by the new active key rejected: %v", err)
		}
		t.Log("    tokens from the brand-new active key validate as expected.")
	})

	t.Run("10 per-IP rate limiting", func(t *testing.T) {
		s, url := NewServer(t, WithRateLimit(1, 2))
		client := s.Client()

		t.Log("WithRateLimit(rps=1, burst=2): each client gets a token bucket seeded with 2 tokens.")
		statuses := make(map[int]int)
		for i := 1; i <= 4; i++ {
			req, _ := http.NewRequest(http.MethodGet, url+"/healthz", nil)
			// Pin the client identity so the limiter is shared across all 4 requests.
			req.Header.Set("X-Forwarded-For", "203.0.113.7")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request #%d: %v", i, err)
			}
			_ = resp.Body.Close()
			statuses[resp.StatusCode]++
			t.Logf("    request #%d -> %d %s", i, resp.StatusCode, http.StatusText(resp.StatusCode))
		}
		if statuses[http.StatusOK] == 0 || statuses[http.StatusTooManyRequests] == 0 {
			t.Fatalf("expected a mix of 200 and 429, got %v", statuses)
		}
		t.Log("Burst consumed the 2 tokens, then the limiter returned 429 until tokens refill (1/sec).")
	})
}

// demoVerify mimics a JWT-aware protected service: it fetches the issuer JWKS
// over HTTP, pins the allowed signing algorithm and the issuer, requires an
// expiry, and returns the parsed token or the verification error.
func demoVerify(t *testing.T, s *Server, raw, allowedAlg string) (*jwt5.Token, error) {
	t.Helper()
	set := fetchJWKS(t, s.URL()+"/.well-known/jwks.json")
	parser := jwt5.NewParser(
		jwt5.WithValidMethods([]string{allowedAlg}),
		jwt5.WithIssuer(s.Issuer()),
		jwt5.WithExpirationRequired(),
	)
	return parser.Parse(raw, func(tk *jwt5.Token) (any, error) {
		kid, _ := tk.Header["kid"].(string)
		key, ok := set.LookupKeyID(kid)
		if !ok {
			return nil, jwt5.ErrSignatureInvalid
		}
		return exportPublicKey(t, key)
	})
}

func httpGet(t *testing.T, url string) (int, []byte) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := readAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	t.Logf("    GET %s -> %d", url, resp.StatusCode)
	return resp.StatusCode, body
}

func showToken(t *testing.T, raw string) {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Logf("    token: %s (not a 3-segment compact JWS)", raw)
		return
	}
	t.Logf("    header:    %s", string(mustB64(t, parts[0])))
	t.Logf("    payload:   %s", string(mustB64(t, parts[1])))
	t.Logf("    signature: %.24s…", parts[2])
}

func kidOf(t *testing.T, raw string) string {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("not a 3-segment compact JWS: %q", raw)
	}
	var hdr struct {
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(mustB64(t, parts[0]), &hdr); err != nil {
		t.Fatalf("decode header: %v", err)
	}
	if hdr.Kid == "" {
		t.Fatalf("no kid in header: %s", string(mustB64(t, parts[0])))
	}
	return hdr.Kid
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64url decode %q: %v", s, err)
	}
	return b
}

func showJSON(t *testing.T, label string, body []byte) {
	t.Helper()
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		t.Logf("%s: %s", label, string(body))
		return
	}
	pretty, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Logf("%s: %s", label, string(body))
		return
	}
	t.Logf("%s: %s", label, string(pretty))
}
