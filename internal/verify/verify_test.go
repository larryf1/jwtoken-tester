package verify

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	jwt5 "github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/larryf1/jwtoken-tester/v2/internal/keyring"
	"github.com/larryf1/jwtoken-tester/v2/internal/tokenfactory"
)

const testIssuer = "http://127.0.0.1:8080"

func newRing(t *testing.T, algs ...keyring.Algorithm) *keyring.KeyRing {
	t.Helper()
	if len(algs) == 0 {
		algs = []keyring.Algorithm{keyring.AlgRS256}
	}
	ring, err := keyring.New(time.Hour, algs)
	if err != nil {
		t.Fatalf("keyring.New() error = %v", err)
	}
	return ring
}

func mustSigner(t *testing.T, ring keyring.Ring, alg keyring.Algorithm) *keyring.Key {
	t.Helper()
	key, err := ring.Signer(alg)
	if err != nil {
		t.Fatalf("Signer(%s) error = %v", alg, err)
	}
	return key
}

func signingMethod(alg keyring.Algorithm) jwt5.SigningMethod {
	switch alg {
	case keyring.AlgES256:
		return jwt5.SigningMethodES256
	case keyring.AlgEdDSA:
		return jwt5.SigningMethodEdDSA
	default:
		return jwt5.SigningMethodRS256
	}
}

func kidHeader(key *keyring.Key) map[string]any {
	return map[string]any{"kid": key.Kid()}
}

func signClaims(t *testing.T, key *keyring.Key, claims map[string]any, header map[string]any) string {
	t.Helper()
	tok := jwt5.NewWithClaims(signingMethod(key.Algorithm), jwt5.MapClaims(claims))
	for name, value := range header {
		tok.Header[name] = value
	}
	signed, err := tok.SignedString(key.Private)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func compactToken(header, claims map[string]any, signature string) string {
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	b64 := base64.RawURLEncoding.EncodeToString
	return b64(headerJSON) + "." + b64(claimsJSON) + "." + signature
}

func tamperSignature(token string) string {
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

func claimsAt(now time.Time) map[string]any {
	return map[string]any{
		"iss": testIssuer,
		"sub": "user-123",
		"aud": "my-service",
		"iat": now.Add(-time.Minute).Unix(),
		"nbf": now.Add(-time.Minute).Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
}

func verifyWith(ring keyring.Ring, token string, now time.Time) (Verdict, error) {
	return Verify(Input{
		Token:          token,
		Keys:           RingKeySource{Ring: ring},
		ExpectedIssuer: testIssuer,
		Now:            now,
	})
}

func TestVerifyValidReportsAuthenticatedClaims(t *testing.T) {
	ring := newRing(t, keyring.AlgRS256)
	key := mustSigner(t, ring, keyring.AlgRS256)
	now := time.Unix(1700000000, 0).UTC()
	token := signClaims(t, key, claimsAt(now), kidHeader(key))

	verdict, err := verifyWith(ring, token, now)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !verdict.Valid {
		t.Fatalf("Valid = false, reason = %q, error = %q", verdict.Reason, verdict.Error)
	}
	if verdict.Reason != "" || verdict.Error != "" {
		t.Fatalf("valid verdict has reason/error: %#v", verdict)
	}
	if verdict.Header["alg"] != "RS256" || verdict.Header["kid"] != key.Kid() {
		t.Fatalf("header = %#v", verdict.Header)
	}
	if verdict.Kid != key.Kid() || verdict.KidStatus != keyring.KeyStatusActive || verdict.Alg != "RS256" {
		t.Fatalf("kid/status/alg = %q/%q/%q", verdict.Kid, verdict.KidStatus, verdict.Alg)
	}
	if verdict.Claims == nil || verdict.UnverifiedClaims != nil {
		t.Fatalf("claims labeling = %#v / %#v", verdict.Claims, verdict.UnverifiedClaims)
	}
	if got := verdict.Claims["sub"]; got != "user-123" {
		t.Fatalf("claims[sub] = %v", got)
	}
}

func TestVerifyMalformed(t *testing.T) {
	ring := newRing(t)
	key := mustSigner(t, ring, keyring.AlgRS256)
	now := time.Unix(1700000000, 0).UTC()
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": key.Kid()})
	goodHeader := base64.RawURLEncoding.EncodeToString(header)

	cases := map[string]string{
		"not a compact jws": "not-a-token",
		"two segments":      "a.b",
		"bad base64":        "!!!.!!!=.!!!",
		"payload not json":  goodHeader + "." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".c2ln",
		"wrong exp shape":   signClaims(t, key, map[string]any{"iss": testIssuer, "exp": "soon"}, kidHeader(key)),
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			verdict, err := verifyWith(ring, token, now)
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if verdict.Valid || verdict.Reason != ReasonMalformed {
				t.Fatalf("verdict = %#v, want malformed", verdict)
			}
			if verdict.Error == "" {
				t.Fatal("malformed verdict has empty error")
			}
			if verdict.Claims != nil || verdict.UnverifiedClaims != nil || verdict.Header != nil {
				t.Fatalf("malformed verdict exposed diagnostic data: %#v", verdict)
			}
		})
	}
}

func TestVerifyAlgorithm(t *testing.T) {
	ring := newRing(t)
	key := mustSigner(t, ring, keyring.AlgRS256)
	now := time.Unix(1700000000, 0).UTC()
	claims := claimsAt(now)
	valid := signClaims(t, key, claims, kidHeader(key))

	cases := []struct {
		name    string
		token   string
		allowed []string
	}{
		{
			name:  "alg none",
			token: compactToken(map[string]any{"alg": "none", "typ": "JWT", "kid": key.Kid()}, claims, ""),
		},
		{
			name:  "HS256 over real payload",
			token: compactToken(map[string]any{"alg": "HS256", "typ": "JWT", "kid": key.Kid()}, claims, "c2ln"),
		},
		{
			name:  "disabled asymmetric algorithm",
			token: compactToken(map[string]any{"alg": "PS256", "typ": "JWT", "kid": key.Kid()}, claims, "c2ln"),
		},
		{
			name:  "missing alg",
			token: compactToken(map[string]any{"typ": "JWT", "kid": key.Kid()}, claims, "c2ln"),
		},
		{
			name:    "narrowed allowlist excludes token algorithm",
			token:   valid,
			allowed: []string{"ES256"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verdict, err := Verify(Input{
				Token:          tc.token,
				Keys:           RingKeySource{Ring: ring},
				ExpectedIssuer: testIssuer,
				AllowedAlgs:    tc.allowed,
				Now:            now,
			})
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if verdict.Valid || verdict.Reason != ReasonAlg {
				t.Fatalf("verdict = %#v, want alg", verdict)
			}
			if verdict.UnverifiedClaims == nil || verdict.Claims != nil {
				t.Fatalf("claims labeling = %#v / %#v", verdict.Claims, verdict.UnverifiedClaims)
			}
		})
	}
}

func TestVerifyKid(t *testing.T) {
	ring := newRing(t)
	key := mustSigner(t, ring, keyring.AlgRS256)
	now := time.Unix(1700000000, 0).UTC()
	claims := claimsAt(now)

	t.Run("unknown kid", func(t *testing.T) {
		token := signClaims(t, key, claims, map[string]any{"kid": "not-a-real-kid"})
		verdict, err := verifyWith(ring, token, now)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if verdict.Valid || verdict.Reason != ReasonKid {
			t.Fatalf("verdict = %#v, want kid", verdict)
		}
		if verdict.KidStatus != KeyStatusUnknown || verdict.Kid != "not-a-real-kid" {
			t.Fatalf("kid/status = %q/%q", verdict.Kid, verdict.KidStatus)
		}
		if verdict.UnverifiedClaims == nil || verdict.Claims != nil {
			t.Fatalf("claims labeling = %#v / %#v", verdict.Claims, verdict.UnverifiedClaims)
		}
	})

	t.Run("missing kid", func(t *testing.T) {
		token := signClaims(t, key, claims, nil)
		verdict, err := verifyWith(ring, token, now)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if verdict.Valid || verdict.Reason != ReasonKid {
			t.Fatalf("verdict = %#v, want kid", verdict)
		}
		if verdict.KidStatus != "" {
			t.Fatalf("kid_status = %q, want omitted", verdict.KidStatus)
		}
	})

	t.Run("non-string kid", func(t *testing.T) {
		token := signClaims(t, key, claims, map[string]any{"kid": 123})
		verdict, err := verifyWith(ring, token, now)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if verdict.Valid || verdict.Reason != ReasonKid {
			t.Fatalf("verdict = %#v, want kid", verdict)
		}
	})

	t.Run("pruned kid", func(t *testing.T) {
		token := signClaims(t, key, claims, kidHeader(key))
		if err := ring.Rotate(); err != nil {
			t.Fatalf("Rotate() error = %v", err)
		}
		ring.PruneAt(time.Now().Add(2 * time.Hour))
		verdict, err := verifyWith(ring, token, now)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if verdict.Valid || verdict.Reason != ReasonKid || verdict.KidStatus != KeyStatusUnknown {
			t.Fatalf("verdict = %#v, want kid/unknown", verdict)
		}
	})
}

func TestVerifySignature(t *testing.T) {
	ring := newRing(t)
	key := mustSigner(t, ring, keyring.AlgRS256)
	now := time.Unix(1700000000, 0).UTC()

	t.Run("tampered signature", func(t *testing.T) {
		token := tamperSignature(signClaims(t, key, claimsAt(now), kidHeader(key)))
		verdict, err := verifyWith(ring, token, now)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if verdict.Valid || verdict.Reason != ReasonSignature {
			t.Fatalf("verdict = %#v, want signature", verdict)
		}
		if verdict.KidStatus != keyring.KeyStatusActive {
			t.Fatalf("kid_status = %q", verdict.KidStatus)
		}
		if verdict.UnverifiedClaims == nil || verdict.Claims != nil {
			t.Fatalf("claims labeling = %#v / %#v", verdict.Claims, verdict.UnverifiedClaims)
		}
	})

	t.Run("key from another ring", func(t *testing.T) {
		other := newRing(t)
		otherKey := mustSigner(t, other, keyring.AlgRS256)
		token := signClaims(t, otherKey, claimsAt(now), kidHeader(key))
		verdict, err := verifyWith(ring, token, now)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if verdict.Valid || verdict.Reason != ReasonSignature {
			t.Fatalf("verdict = %#v, want signature", verdict)
		}
	})

	t.Run("algorithm and key type mismatch", func(t *testing.T) {
		mixed := newRing(t, keyring.AlgRS256, keyring.AlgES256)
		rsaKey := mustSigner(t, mixed, keyring.AlgRS256)
		token := compactToken(map[string]any{"alg": "ES256", "typ": "JWT", "kid": rsaKey.Kid()}, claimsAt(now), "c2ln")
		verdict, err := verifyWith(mixed, token, now)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if verdict.Valid || verdict.Reason != ReasonSignature {
			t.Fatalf("verdict = %#v, want signature", verdict)
		}
	})
}

func TestVerifyTime(t *testing.T) {
	ring := newRing(t)
	key := mustSigner(t, ring, keyring.AlgRS256)
	now := time.Unix(1700000000, 0).UTC()

	expired := claimsAt(now)
	expired["exp"] = now.Add(-time.Hour).Unix()
	future := claimsAt(now)
	future["nbf"] = now.Add(time.Hour).Unix()
	future["exp"] = now.Add(2 * time.Hour).Unix()
	usedBeforeIssued := claimsAt(now)
	usedBeforeIssued["iat"] = now.Add(time.Hour).Unix()
	usedBeforeIssued["exp"] = now.Add(2 * time.Hour).Unix()
	recentlyExpired := claimsAt(now)
	recentlyExpired["exp"] = now.Add(-30 * time.Second).Unix()
	longExpired := claimsAt(now)
	longExpired["exp"] = now.Add(-2 * time.Minute).Unix()
	expiredAndFuture := claimsAt(now)
	expiredAndFuture["exp"] = now.Add(-time.Hour).Unix()
	expiredAndFuture["nbf"] = now.Add(time.Hour).Unix()
	noExp := claimsAt(now)
	delete(noExp, "exp")

	cases := []struct {
		name   string
		claims map[string]any
		leeway time.Duration
		valid  bool
		reason Reason
	}{
		{name: "expired", claims: expired, reason: ReasonExpired},
		{name: "leeway admits recently expired", claims: recentlyExpired, leeway: time.Minute, valid: true},
		{name: "leeway is not enough", claims: longExpired, leeway: time.Minute, reason: ReasonExpired},
		{name: "not yet valid", claims: future, reason: ReasonNotYetValid},
		{name: "used before issued", claims: usedBeforeIssued, reason: ReasonNotYetValid},
		{name: "expired wins over not yet valid", claims: expiredAndFuture, reason: ReasonExpired},
		{name: "missing exp is optional", claims: noExp, valid: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token := signClaims(t, key, tc.claims, kidHeader(key))
			verdict, err := Verify(Input{
				Token:          token,
				Keys:           RingKeySource{Ring: ring},
				ExpectedIssuer: testIssuer,
				Leeway:         tc.leeway,
				Now:            now,
			})
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if verdict.Valid != tc.valid {
				t.Fatalf("Valid = %v, want %v (reason %q, error %q)", verdict.Valid, tc.valid, verdict.Reason, verdict.Error)
			}
			if !tc.valid && verdict.Reason != tc.reason {
				t.Fatalf("Reason = %q, want %q", verdict.Reason, tc.reason)
			}
			if verdict.Claims == nil {
				t.Fatal("signature-verified verdict must carry claims")
			}
			if verdict.UnverifiedClaims != nil {
				t.Fatalf("authenticated verdict carries unverified_claims: %#v", verdict.UnverifiedClaims)
			}
		})
	}
}

func TestVerifyIssuerAudience(t *testing.T) {
	ring := newRing(t)
	key := mustSigner(t, ring, keyring.AlgRS256)
	now := time.Unix(1700000000, 0).UTC()

	wrongIssuer := claimsAt(now)
	wrongIssuer["iss"] = "https://attacker.example"
	noIssuer := claimsAt(now)
	delete(noIssuer, "iss")
	wrongAudience := claimsAt(now)
	wrongAudience["aud"] = []string{"other-service"}

	cases := []struct {
		name           string
		claims         map[string]any
		expectedIssuer string
		audience       []string
		valid          bool
		reason         Reason
	}{
		{name: "matching issuer", claims: claimsAt(now), expectedIssuer: testIssuer, valid: true},
		{name: "wrong issuer", claims: wrongIssuer, expectedIssuer: testIssuer, reason: ReasonIssuer},
		{name: "missing issuer", claims: noIssuer, expectedIssuer: testIssuer, reason: ReasonIssuer},
		{name: "issuer check disabled", claims: wrongIssuer, valid: true},
		{name: "matching string audience", claims: claimsAt(now), expectedIssuer: testIssuer, audience: []string{"my-service"}, valid: true},
		{name: "matching array member", claims: func() map[string]any {
			c := claimsAt(now)
			c["aud"] = []string{"other-service", "my-service"}
			return c
		}(), expectedIssuer: testIssuer, audience: []string{"my-service"}, valid: true},
		{name: "wrong audience", claims: wrongAudience, expectedIssuer: testIssuer, audience: []string{"my-service"}, reason: ReasonAudience},
		{name: "audience check disabled", claims: wrongAudience, expectedIssuer: testIssuer, valid: true},
		{name: "issuer wins over audience", claims: wrongIssuer, expectedIssuer: testIssuer, audience: []string{"my-service"}, reason: ReasonIssuer},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token := signClaims(t, key, tc.claims, kidHeader(key))
			verdict, err := Verify(Input{
				Token:          token,
				Keys:           RingKeySource{Ring: ring},
				ExpectedIssuer: tc.expectedIssuer,
				Audience:       tc.audience,
				Now:            now,
			})
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if verdict.Valid != tc.valid {
				t.Fatalf("Valid = %v, want %v (reason %q, error %q)", verdict.Valid, tc.valid, verdict.Reason, verdict.Error)
			}
			if !tc.valid && verdict.Reason != tc.reason {
				t.Fatalf("Reason = %q, want %q", verdict.Reason, tc.reason)
			}
		})
	}
}

func TestVerifyKidStatus(t *testing.T) {
	ring := newRing(t)
	key := mustSigner(t, ring, keyring.AlgRS256)
	now := time.Unix(1700000000, 0).UTC()
	token := signClaims(t, key, claimsAt(now), kidHeader(key))

	active, err := verifyWith(ring, token, now)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !active.Valid || active.KidStatus != keyring.KeyStatusActive {
		t.Fatalf("active verdict = %#v", active)
	}

	if err := ring.Rotate(); err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	retired, err := verifyWith(ring, token, now)
	if err != nil {
		t.Fatalf("Verify() after rotate error = %v", err)
	}
	if !retired.Valid {
		t.Fatalf("retired verdict = %#v, want valid", retired)
	}
	if retired.KidStatus != keyring.KeyStatusRetired {
		t.Fatalf("kid_status = %q, want retired", retired.KidStatus)
	}
}

func TestVerifyPrecedence(t *testing.T) {
	ring := newRing(t)
	key := mustSigner(t, ring, keyring.AlgRS256)
	now := time.Unix(1700000000, 0).UTC()

	expiredClaims := claimsAt(now)
	expiredClaims["exp"] = now.Add(-time.Hour).Unix()
	expiredWrongAudience := claimsAt(now)
	expiredWrongAudience["exp"] = now.Add(-time.Hour).Unix()
	expiredWrongAudience["aud"] = "other-service"

	t.Run("expired plus unknown kid yields kid", func(t *testing.T) {
		token := signClaims(t, key, expiredClaims, map[string]any{"kid": "missing"})
		verdict, err := verifyWith(ring, token, now)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if verdict.Reason != ReasonKid {
			t.Fatalf("Reason = %q, want kid", verdict.Reason)
		}
	})

	t.Run("expired plus bad signature yields signature", func(t *testing.T) {
		token := tamperSignature(signClaims(t, key, expiredClaims, kidHeader(key)))
		verdict, err := verifyWith(ring, token, now)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if verdict.Reason != ReasonSignature {
			t.Fatalf("Reason = %q, want signature", verdict.Reason)
		}
	})

	t.Run("audience plus expired yields expired", func(t *testing.T) {
		token := signClaims(t, key, expiredWrongAudience, kidHeader(key))
		verdict, err := Verify(Input{
			Token:          token,
			Keys:           RingKeySource{Ring: ring},
			ExpectedIssuer: testIssuer,
			Audience:       []string{"my-service"},
			Now:            now,
		})
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if verdict.Reason != ReasonExpired {
			t.Fatalf("Reason = %q, want expired", verdict.Reason)
		}
	})
}

func TestVerifyEchoesNumericDates(t *testing.T) {
	ring := newRing(t)
	key := mustSigner(t, ring, keyring.AlgRS256)
	now := time.Unix(1700000000, 0).UTC()
	claims := map[string]any{
		"iss": testIssuer,
		"iat": int64(1699999400),
		"nbf": int64(1699999400),
		"exp": int64(1700003600),
	}
	token := signClaims(t, key, claims, kidHeader(key))
	verdict, err := verifyWith(ring, token, now)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !verdict.Valid {
		t.Fatalf("verdict = %#v", verdict)
	}
	for _, name := range []string{"iat", "nbf", "exp"} {
		if _, ok := verdict.Claims[name].(float64); !ok {
			t.Fatalf("claims[%s] type = %T, want float64", name, verdict.Claims[name])
		}
	}
	data, err := json.Marshal(verdict)
	if err != nil {
		t.Fatalf("marshal verdict: %v", err)
	}
	for _, want := range []string{`"exp":1700003600`, `"iat":1699999400`, `"nbf":1699999400`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("verdict JSON %s does not contain %s", data, want)
		}
	}
}

type failingSource struct {
	err error
}

func (f failingSource) Lookup(string) (crypto.PublicKey, keyring.KeyStatus, error) {
	return nil, "", f.err
}

func (f failingSource) Algorithms() []string {
	return []string{"RS256"}
}

func TestVerifyUnclassifiableLookupError(t *testing.T) {
	key := mustSigner(t, newRing(t), keyring.AlgRS256)
	now := time.Unix(1700000000, 0).UTC()
	token := signClaims(t, key, claimsAt(now), kidHeader(key))

	_, err := Verify(Input{
		Token: token,
		Keys:  failingSource{err: errors.New("backend unavailable")},
		Now:   now,
	})
	if err == nil {
		t.Fatal("Verify() error = nil, want an operational error")
	}
}

func TestParityWithJwx(t *testing.T) {
	algorithms := []keyring.Algorithm{keyring.AlgRS256, keyring.AlgES256, keyring.AlgEdDSA}
	for _, alg := range algorithms {
		t.Run(string(alg), func(t *testing.T) {
			ring := newRing(t, alg)
			factory := tokenfactory.NewFactory(ring, testIssuer, time.Hour, 24*time.Hour)
			key := mustSigner(t, ring, alg)

			fresh, err := factory.Mint(&tokenfactory.Request{Alg: string(alg)})
			if err != nil {
				t.Fatalf("Mint(fresh) error = %v", err)
			}
			verdict, err := verifyWith(ring, fresh.AccessToken, time.Now().UTC())
			if err != nil {
				t.Fatalf("Verify(fresh) error = %v", err)
			}
			if !verdict.Valid {
				t.Fatalf("Verify(fresh) = %#v", verdict)
			}
			if _, err := jwt.Parse([]byte(fresh.AccessToken),
				jwt.WithKey(keyring.JWAAlgorithms()[alg], key.PubJWK),
				jwt.WithIssuer(testIssuer),
			); err != nil {
				t.Fatalf("jwx rejected fresh token: %v", err)
			}

			tampered := tamperSignature(fresh.AccessToken)
			verdict, err = verifyWith(ring, tampered, time.Now().UTC())
			if err != nil {
				t.Fatalf("Verify(tampered) error = %v", err)
			}
			if verdict.Valid || verdict.Reason != ReasonSignature {
				t.Fatalf("Verify(tampered) = %#v", verdict)
			}
			if _, err := jwt.Parse([]byte(tampered),
				jwt.WithKey(keyring.JWAAlgorithms()[alg], key.PubJWK),
				jwt.WithIssuer(testIssuer),
			); err == nil {
				t.Fatal("jwx accepted tampered token")
			}

			expired, err := factory.Mint(&tokenfactory.Request{
				Alg:    string(alg),
				Claims: map[string]any{"exp": "-1h"},
			})
			if err != nil {
				t.Fatalf("Mint(expired) error = %v", err)
			}
			verdict, err = verifyWith(ring, expired.AccessToken, time.Now().UTC())
			if err != nil {
				t.Fatalf("Verify(expired) error = %v", err)
			}
			if verdict.Valid || verdict.Reason != ReasonExpired {
				t.Fatalf("Verify(expired) = %#v", verdict)
			}
			if _, err := jwt.Parse([]byte(expired.AccessToken),
				jwt.WithKey(keyring.JWAAlgorithms()[alg], key.PubJWK),
			); err == nil {
				t.Fatal("jwx accepted expired token")
			}

			wrongIssuer, err := factory.Mint(&tokenfactory.Request{
				Alg:    string(alg),
				Claims: map[string]any{"iss": "https://attacker.example"},
			})
			if err != nil {
				t.Fatalf("Mint(wrong issuer) error = %v", err)
			}
			verdict, err = verifyWith(ring, wrongIssuer.AccessToken, time.Now().UTC())
			if err != nil {
				t.Fatalf("Verify(wrong issuer) error = %v", err)
			}
			if verdict.Valid || verdict.Reason != ReasonIssuer {
				t.Fatalf("Verify(wrong issuer) = %#v", verdict)
			}
			if _, err := jwt.Parse([]byte(wrongIssuer.AccessToken),
				jwt.WithKey(keyring.JWAAlgorithms()[alg], key.PubJWK),
				jwt.WithIssuer(testIssuer),
			); err == nil {
				t.Fatal("jwx accepted wrong-issuer token")
			}
		})
	}
}
