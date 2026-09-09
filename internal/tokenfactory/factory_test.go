package tokenfactory

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	jwt5 "github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v4/jwk"

	"github.com/larryf1/jwtoken-tester/internal/keyring"
)

const testIssuer = "https://issuer.test.example"

func newTestFactory(t *testing.T, algs ...keyring.Algorithm) (*Factory, *keyring.KeyRing) {
	t.Helper()
	if len(algs) == 0 {
		algs = []keyring.Algorithm{keyring.AlgRS256}
	}
	ring, err := keyring.New(time.Hour, algs)
	if err != nil {
		t.Fatalf("keyring.New() error = %v", err)
	}
	return NewFactory(ring, testIssuer, time.Hour, 24*time.Hour), ring
}

func mustParseRS256(t *testing.T, ring *keyring.KeyRing, token string) jwt5.MapClaims {
	t.Helper()
	parser := jwt5.NewParser(jwt5.WithValidMethods([]string{"RS256"}))
	parsed, err := parser.Parse(token, func(tk *jwt5.Token) (any, error) {
		signer, err := ring.Signer(keyring.AlgRS256)
		if err != nil {
			return nil, err
		}
		return getPublicKey(t, signer.Private)
	})
	if parsed == nil {
		t.Fatalf("golang-jwt could not parse token: %v", err)
	}
	return parsed.Claims.(jwt5.MapClaims)
}

func mustParseES256(t *testing.T, ring *keyring.KeyRing, token string) jwt5.MapClaims {
	t.Helper()
	parser := jwt5.NewParser(jwt5.WithValidMethods([]string{"ES256"}))
	parsed, err := parser.Parse(token, func(tk *jwt5.Token) (any, error) {
		signer, err := ring.Signer(keyring.AlgES256)
		if err != nil {
			return nil, err
		}
		return getPublicKey(t, signer.Private)
	})
	if parsed == nil {
		t.Fatalf("golang-jwt could not parse token: %v", err)
	}
	return parsed.Claims.(jwt5.MapClaims)
}

func mustParseEdDSA(t *testing.T, ring *keyring.KeyRing, token string) jwt5.MapClaims {
	t.Helper()
	parser := jwt5.NewParser(jwt5.WithValidMethods([]string{"EdDSA"}))
	parsed, err := parser.Parse(token, func(tk *jwt5.Token) (any, error) {
		signer, err := ring.Signer(keyring.AlgEdDSA)
		if err != nil {
			return nil, err
		}
		return getPublicKey(t, signer.Private)
	})
	if parsed == nil {
		t.Fatalf("golang-jwt could not parse token: %v", err)
	}
	return parsed.Claims.(jwt5.MapClaims)
}

func getPublicKey(t *testing.T, priv interface{}) (any, error) {
	t.Helper()
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return k.Public(), nil
	case *ecdsa.PrivateKey:
		return k.Public(), nil
	case ed25519.PrivateKey:
		return k.Public(), nil
	default:
		return nil, fmt.Errorf("unknown private key type: %T", priv)
	}
}

func TestParseTimeValue(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		value   any
		want    time.Time
		wantErr bool
	}{
		{name: "epoch float", value: float64(1800000000), want: time.Unix(1800000000, 0).UTC()},
		{name: "epoch int", value: 1800000000, want: time.Unix(1800000000, 0).UTC()},
		{name: "duration", value: "90m", want: now.Add(90 * time.Minute)},
		{name: "in-prefixed duration", value: "in 1h30m", want: now.Add(90 * time.Minute)},
		{name: "rfc3339", value: "2027-01-01T00:00:00Z", want: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)},
		{name: "epoch string", value: "1800000000", want: time.Unix(1800000000, 0).UTC()},
		{name: "negative duration", value: "-5m", want: now.Add(-5 * time.Minute)},
		{name: "garbage", value: "soon-ish", wantErr: true},
		{name: "unsupported type", value: true, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTimeValue(tt.value, now)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseTimeValue(%v) succeeded, want error", tt.value)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTimeValue(%v) error = %v", tt.value, err)
			}
			if d := got.Sub(tt.want); d > time.Second || d < -time.Second {
				t.Fatalf("ParseTimeValue(%v) = %v, want ~%v", tt.value, got, tt.want)
			}
		})
	}
}

func TestMintDefaultsInjectStandardClaims(t *testing.T) {
	for _, alg := range []keyring.Algorithm{keyring.AlgRS256, keyring.AlgES256, keyring.AlgEdDSA} {
		t.Run(string(alg), func(t *testing.T) {
			f, ring := newTestFactory(t, alg)

			resp, err := f.Mint(&Request{Alg: string(alg)})
			if err != nil {
				t.Fatalf("Mint() error = %v", err)
			}
			if resp.TokenType != "Bearer" {
				t.Fatalf("token_type = %q, want Bearer", resp.TokenType)
			}
			if resp.ExpiresIn != 3600 {
				t.Fatalf("expires_in = %d, want 3600", resp.ExpiresIn)
			}

			var claims jwt5.MapClaims
			switch alg {
			case keyring.AlgRS256:
				claims = mustParseRS256(t, ring, resp.AccessToken)
			case keyring.AlgES256:
				claims = mustParseES256(t, ring, resp.AccessToken)
			case keyring.AlgEdDSA:
				claims = mustParseEdDSA(t, ring, resp.AccessToken)
			}

			if claims["iss"] != testIssuer {
				t.Fatalf("iss = %v, want %q", claims["iss"], testIssuer)
			}
			iat, err := claims.GetIssuedAt()
			if err != nil {
				t.Fatalf("GetIssuedAt() error = %v", err)
			}
			exp, err := claims.GetExpirationTime()
			if err != nil {
				t.Fatalf("GetExpirationTime() error = %v", err)
			}
			nbf, err := claims.GetNotBefore()
			if err != nil {
				t.Fatalf("GetNotBefore() error = %v", err)
			}
			if lifetime := exp.Sub(iat.Time); lifetime != time.Hour {
				t.Fatalf("exp-iat = %v, want 1h", lifetime)
			}
			if !nbf.Equal(iat.Time) {
				t.Fatalf("nbf = %v, want iat %v", nbf.Time, iat.Time)
			}
		})
	}
}

func TestMintExplicitClaimsOverrideDefaults(t *testing.T) {
	f, ring := newTestFactory(t, keyring.AlgRS256)

	req := &Request{Claims: map[string]any{
		"iss": "https://attacker.example",
		"sub": "user-42",
		"aud": []any{"svc-a", "svc-b"},
		"exp": "in 12h",
	}}
	resp, err := f.Mint(req)
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}

	claims := mustParseRS256(t, ring, resp.AccessToken)
	if claims["iss"] != "https://attacker.example" {
		t.Fatalf("iss = %v, explicit override lost", claims["iss"])
	}
	if claims["sub"] != "user-42" {
		t.Fatalf("sub = %v, want user-42", claims["sub"])
	}
	aud, ok := claims["aud"].([]any)
	if !ok || len(aud) != 2 || aud[0] != "svc-a" || aud[1] != "svc-b" {
		t.Fatalf("aud = %#v, want [svc-a svc-b]", claims["aud"])
	}
}

func TestMintRejectsUnsupportedAlg(t *testing.T) {
	f, _ := newTestFactory(t, keyring.AlgRS256)
	_, err := f.Mint(&Request{Alg: "ES256"})
	if !errors.Is(err, ErrUnsupportedAlg) {
		t.Fatalf("error = %v, want ErrUnsupportedAlg", err)
	}
}

func TestMintAcceptsEnabledAlg(t *testing.T) {
	f, _ := newTestFactory(t, keyring.AlgRS256, keyring.AlgES256, keyring.AlgEdDSA)

	for _, alg := range []keyring.Algorithm{keyring.AlgRS256, keyring.AlgES256, keyring.AlgEdDSA} {
		t.Run(string(alg), func(t *testing.T) {
			resp, err := f.Mint(&Request{Alg: string(alg)})
			if err != nil {
				t.Fatalf("Mint(%s) error = %v", alg, err)
			}
			if resp.AccessToken == "" {
				t.Fatalf("empty access token for %s", alg)
			}

			// Verify the algorithm in the header
			segments := strings.Split(resp.AccessToken, ".")
			headerJSON, err := base64.RawURLEncoding.DecodeString(segments[0])
			if err != nil {
				t.Fatalf("decode JOSE header: %v", err)
			}
			var header map[string]any
			if err := json.Unmarshal(headerJSON, &header); err != nil {
				t.Fatalf("unmarshal JOSE header: %v", err)
			}
			if header["alg"] != string(alg) {
				t.Fatalf("alg = %v, want %s", header["alg"], alg)
			}
		})
	}
}

func TestMintRejectsLifetimeOverCap(t *testing.T) {
	f, _ := newTestFactory(t)
	_, err := f.Mint(&Request{Claims: map[string]any{"exp": "72h"}})
	if !errors.Is(err, ErrTTLTooLong) {
		t.Fatalf("error = %v, want ErrTTLTooLong", err)
	}
}

func TestMintAllowsAlreadyExpiredTokens(t *testing.T) {
	f, ring := newTestFactory(t, keyring.AlgRS256)

	resp, err := f.Mint(&Request{Claims: map[string]any{"exp": "-5m"}})
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	if resp.ExpiresIn >= 0 {
		t.Fatalf("expires_in = %d, want negative", resp.ExpiresIn)
	}

	parser := jwt5.NewParser(jwt5.WithValidMethods([]string{"RS256"}))
	_, err = parser.Parse(resp.AccessToken, func(tk *jwt5.Token) (any, error) {
		s, err := ring.Signer(keyring.AlgRS256)
		if err != nil {
			return nil, err
		}
		return getPublicKey(t, s.Private)
	})
	if !errors.Is(err, jwt5.ErrTokenExpired) {
		t.Fatalf("validation error = %v, want ErrTokenExpired", err)
	}
}

func TestJOSEHeaderCarriesAlgKidTyp(t *testing.T) {
	for _, alg := range []keyring.Algorithm{keyring.AlgRS256, keyring.AlgES256, keyring.AlgEdDSA} {
		t.Run(string(alg), func(t *testing.T) {
			f, ring := newTestFactory(t, alg)

			resp, err := f.Mint(&Request{Alg: string(alg)})
			if err != nil {
				t.Fatalf("Mint() error = %v", err)
			}

			segments := strings.Split(resp.AccessToken, ".")
			if len(segments) != 3 {
				t.Fatalf("compact token has %d segments, want 3", len(segments))
			}
			headerJSON, err := base64.RawURLEncoding.DecodeString(segments[0])
			if err != nil {
				t.Fatalf("decode JOSE header: %v", err)
			}
			var header map[string]any
			if err := json.Unmarshal(headerJSON, &header); err != nil {
				t.Fatalf("unmarshal JOSE header: %v", err)
			}

			if header["alg"] != string(alg) {
				t.Fatalf("alg = %v, want %s", header["alg"], alg)
			}
			if header["typ"] != "JWT" {
				t.Fatalf("typ = %v, want JWT", header["typ"])
			}
			active, err := ring.Signer(alg)
			if err != nil {
				t.Fatalf("Signer() error = %v", err)
			}
			if header["kid"] != active.Kid() {
				t.Fatalf("kid = %v, want %q", header["kid"], active.Kid())
			}
		})
	}
}

func TestCustomProtectedHeadersAreEmbedded(t *testing.T) {
	f, _ := newTestFactory(t, keyring.AlgRS256)

	resp, err := f.Mint(&Request{Headers: map[string]any{"x-test-harness": "run-7"}})
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	segments := strings.Split(resp.AccessToken, ".")
	headerJSON, err := base64.RawURLEncoding.DecodeString(segments[0])
	if err != nil {
		t.Fatalf("decode JOSE header: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("unmarshal JOSE header: %v", err)
	}
	if header["x-test-harness"] != "run-7" {
		t.Fatalf("custom header missing: %#v", header)
	}
}

type failingSignerRing struct {
	err error
}

func (f *failingSignerRing) Signer(keyring.Algorithm) (*keyring.Key, error)             { return nil, f.err }
func (f *failingSignerRing) ActiveKid(keyring.Algorithm) (string, error)                { return "", f.err }
func (f *failingSignerRing) JWKS() (jwk.Set, error)                                     { return jwk.NewSet(), nil }
func (f *failingSignerRing) JWKByKID(string) (jwk.Key, error)                           { return nil, f.err }
func (f *failingSignerRing) Rotate() error                                              { return nil }
func (f *failingSignerRing) RotateAt(time.Time) error                                   { return nil }
func (f *failingSignerRing) Prune()                                                     {}
func (f *failingSignerRing) PruneAt(time.Time)                                          {}
func (f *failingSignerRing) StartRotation(context.Context, time.Duration, *slog.Logger) {}
func (f *failingSignerRing) EnabledAlgorithms() []keyring.Algorithm {
	return []keyring.Algorithm{keyring.AlgRS256}
}

func TestMintReturnsErrNoActiveKey(t *testing.T) {
	ring := &failingSignerRing{err: keyring.ErrNoActiveKey}
	f := NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)

	_, err := f.Mint(&Request{})
	if !errors.Is(err, keyring.ErrNoActiveKey) {
		t.Fatalf("error = %v, want ErrNoActiveKey", err)
	}
}

func TestMintRejectsUnsupportedTimeValueType(t *testing.T) {
	f, _ := newTestFactory(t, keyring.AlgRS256)
	req := &Request{Claims: map[string]any{"exp": true}}
	_, err := f.Mint(req)
	if err == nil {
		t.Fatal("expected error for unsupported time value type")
	}
	if !strings.Contains(err.Error(), "unsupported time value type") {
		t.Fatalf("error = %v, want unsupported time value type error", err)
	}
}

func TestMintRejectsInvalidDuration(t *testing.T) {
	f, _ := newTestFactory(t, keyring.AlgRS256)
	req := &Request{Claims: map[string]any{"exp": "not-a-duration"}}
	_, err := f.Mint(req)
	if err == nil {
		t.Fatal("expected error for invalid duration")
	}
	if !strings.Contains(err.Error(), "cannot parse") {
		t.Fatalf("error = %v, want parse error", err)
	}
}

func TestMintWithCustomHeaders(t *testing.T) {
	f, _ := newTestFactory(t, keyring.AlgRS256)
	req := &Request{Headers: map[string]any{"x-custom": "value"}}
	resp, err := f.Mint(req)
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("empty access token")
	}
}

func TestMintRejectsInvalidHeader(t *testing.T) {
	f, _ := newTestFactory(t, keyring.AlgRS256)
	req := &Request{Headers: map[string]any{"invalid": make(chan int)}}
	_, err := f.Mint(req)
	if err == nil {
		t.Fatal("expected error for invalid header value")
	}
	if !strings.Contains(err.Error(), "header") {
		t.Fatalf("error = %v, want header error", err)
	}
}

func TestParseTimeValueEdgeCases(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		value   any
		want    time.Time
		wantErr bool
	}{
		{name: "int64 epoch", value: int64(1800000000), want: time.Unix(1800000000, 0).UTC()},
		{name: "string epoch with spaces", value: "  1800000000  ", want: time.Unix(1800000000, 0).UTC()},
		{name: "duration with in prefix and spaces", value: "  in 1h  ", want: now.Add(time.Hour)},
		{name: "rfc3339 with timezone", value: "2027-01-01T00:00:00+05:00", want: time.Date(2026, 12, 31, 19, 0, 0, 0, time.UTC)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTimeValue(tt.value, now)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseTimeValue(%v) succeeded, want error", tt.value)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTimeValue(%v) error = %v", tt.value, err)
			}
			if d := got.Sub(tt.want); d > time.Second || d < -time.Second {
				t.Fatalf("ParseTimeValue(%v) = %v, want ~%v", tt.value, got, tt.want)
			}
		})
	}
}

func TestMintUsesDefaultAlgorithmWhenNotSpecified(t *testing.T) {
	f, _ := newTestFactory(t, keyring.AlgRS256)
	resp, err := f.Mint(&Request{})
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("empty access token")
	}
	segments := strings.Split(resp.AccessToken, ".")
	headerJSON, err := base64.RawURLEncoding.DecodeString(segments[0])
	if err != nil {
		t.Fatalf("decode JOSE header: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("unmarshal JOSE header: %v", err)
	}
	if header["alg"] != string(keyring.AlgRS256) {
		t.Fatalf("alg = %v, want %s", header["alg"], keyring.AlgRS256)
	}
}

func TestMintWithEmptyIssuer(t *testing.T) {
	ring, _ := keyring.New(time.Hour, []keyring.Algorithm{keyring.AlgRS256})
	f := NewFactory(ring, "", time.Hour, 24*time.Hour)
	resp, err := f.Mint(&Request{})
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("empty access token")
	}
}

func TestMintRejectsInvalidIatClaim(t *testing.T) {
	f, _ := newTestFactory(t, keyring.AlgRS256)
	req := &Request{Claims: map[string]any{"iat": "invalid"}}
	_, err := f.Mint(req)
	if err == nil {
		t.Fatal("expected error for invalid iat claim")
	}
	if !strings.Contains(err.Error(), "claim \"iat\"") {
		t.Fatalf("error = %v, want claim iat error", err)
	}
}

func TestMintRejectsInvalidNbfClaim(t *testing.T) {
	f, _ := newTestFactory(t, keyring.AlgRS256)
	req := &Request{Claims: map[string]any{"nbf": "invalid"}}
	_, err := f.Mint(req)
	if err == nil {
		t.Fatal("expected error for invalid nbf claim")
	}
	if !strings.Contains(err.Error(), "claim \"nbf\"") {
		t.Fatalf("error = %v, want claim nbf error", err)
	}
}

func TestMintRejectsInvalidExpClaim(t *testing.T) {
	f, _ := newTestFactory(t, keyring.AlgRS256)
	req := &Request{Claims: map[string]any{"exp": "invalid"}}
	_, err := f.Mint(req)
	if err == nil {
		t.Fatal("expected error for invalid exp claim")
	}
	if !strings.Contains(err.Error(), "claim \"exp\"") {
		t.Fatalf("error = %v, want claim exp error", err)
	}
}

type failingSignRing struct {
	err error
}

func (f *failingSignRing) Signer(keyring.Algorithm) (*keyring.Key, error)             { return nil, f.err }
func (f *failingSignRing) ActiveKid(keyring.Algorithm) (string, error)                { return "", f.err }
func (f *failingSignRing) JWKS() (jwk.Set, error)                                     { return jwk.NewSet(), nil }
func (f *failingSignRing) JWKByKID(string) (jwk.Key, error)                           { return nil, f.err }
func (f *failingSignRing) Rotate() error                                              { return nil }
func (f *failingSignRing) RotateAt(time.Time) error                                   { return nil }
func (f *failingSignRing) Prune()                                                     {}
func (f *failingSignRing) PruneAt(time.Time)                                          {}
func (f *failingSignRing) StartRotation(context.Context, time.Duration, *slog.Logger) {}
func (f *failingSignRing) EnabledAlgorithms() []keyring.Algorithm {
	return []keyring.Algorithm{keyring.AlgRS256}
}

func TestMintHandlesSignError(t *testing.T) {
	ring := &failingSignRing{err: errors.New("sign failed")}
	f := NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
	_, err := f.Mint(&Request{})
	if err == nil {
		t.Fatal("expected error for sign failure")
	}
	if !strings.Contains(err.Error(), "sign failed") {
		t.Fatalf("error = %v, want sign failed error", err)
	}
}

func TestMintWithNilRequest(t *testing.T) {
	f, _ := newTestFactory(t, keyring.AlgRS256)
	resp, err := f.Mint(nil)
	if err != nil {
		t.Fatalf("Mint(nil) error = %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("empty access token")
	}
}
