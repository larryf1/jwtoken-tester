package tokenfactory

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	jwt5 "github.com/golang-jwt/jwt/v5"

	"jwtoken-tester/internal/keyring"
)

const testIssuer = "https://issuer.test.example"

func newTestFactory(t *testing.T) (*Factory, *keyring.KeyRing) {
	t.Helper()
	ring, err := keyring.New(time.Hour)
	if err != nil {
		t.Fatalf("keyring.New() error = %v", err)
	}
	return NewFactory(ring, testIssuer, time.Hour, 24*time.Hour), ring
}

func mustParse(t *testing.T, ring *keyring.KeyRing, token string) jwt5.MapClaims {
	t.Helper()
	parser := jwt5.NewParser(jwt5.WithValidMethods([]string{"RS256"}))
	parsed, err := parser.Parse(token, func(tk *jwt5.Token) (any, error) {
		signer, err := ring.Signer()
		if err != nil {
			return nil, err
		}
		return signer.Private.Public(), nil
	})
	if parsed == nil {
		t.Fatalf("golang-jwt could not parse token: %v", err)
	}
	return parsed.Claims.(jwt5.MapClaims)
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
	f, ring := newTestFactory(t)

	resp, err := f.Mint(&Request{})
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	if resp.TokenType != "Bearer" {
		t.Fatalf("token_type = %q, want Bearer", resp.TokenType)
	}
	if resp.ExpiresIn != 3600 {
		t.Fatalf("expires_in = %d, want 3600", resp.ExpiresIn)
	}

	claims := mustParse(t, ring, resp.AccessToken)
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
}

func TestMintExplicitClaimsOverrideDefaults(t *testing.T) {
	f, ring := newTestFactory(t)

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

	claims := mustParse(t, ring, resp.AccessToken)
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
	f, _ := newTestFactory(t)
	_, err := f.Mint(&Request{Alg: "ES256"})
	if !errors.Is(err, ErrUnsupportedAlg) {
		t.Fatalf("error = %v, want ErrUnsupportedAlg", err)
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
	f, ring := newTestFactory(t)

	resp, err := f.Mint(&Request{Claims: map[string]any{"exp": "-5m"}})
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	if resp.ExpiresIn >= 0 {
		t.Fatalf("expires_in = %d, want negative", resp.ExpiresIn)
	}

	parser := jwt5.NewParser(jwt5.WithValidMethods([]string{"RS256"}))
	_, err = parser.Parse(resp.AccessToken, func(tk *jwt5.Token) (any, error) {
		s, _ := ring.Signer()
		return s.Private.Public(), nil
	})
	if !errors.Is(err, jwt5.ErrTokenExpired) {
		t.Fatalf("validation error = %v, want ErrTokenExpired", err)
	}
}

func TestJOSEHeaderCarriesAlgKidTyp(t *testing.T) {
	f, ring := newTestFactory(t)

	resp, err := f.Mint(&Request{})
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

	if header["alg"] != "RS256" {
		t.Fatalf("alg = %v, want RS256", header["alg"])
	}
	if header["typ"] != "JWT" {
		t.Fatalf("typ = %v, want JWT", header["typ"])
	}
	active, _ := ring.Signer()
	if header["kid"] != active.Kid() {
		t.Fatalf("kid = %v, want %q", header["kid"], active.Kid())
	}
}

func TestCustomProtectedHeadersAreEmbedded(t *testing.T) {
	f, _ := newTestFactory(t)

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
