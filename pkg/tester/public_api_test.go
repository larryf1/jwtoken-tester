package tester_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"runtime"
	"sync"
	"testing"
	"time"

	jwt5 "github.com/golang-jwt/jwt/v5"

	"github.com/larryf1/jwtoken-tester/v2/pkg/tester"
)

// TestPublicAPIMintVerifiesAgainstJWKS proves that a consumer can use the
// exported surface alone to mint a token and verify it with the public keys
// published by JWKSJSON.
func TestPublicAPIMintVerifiesAgainstJWKS(t *testing.T) {
	srv, err := tester.Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer srv.Close()

	if srv.URL() != srv.Issuer() {
		t.Fatalf("URL() = %q, Issuer() = %q, want identical", srv.URL(), srv.Issuer())
	}

	jwks, err := srv.JWKSJSON()
	if err != nil {
		t.Fatalf("JWKSJSON() error = %v", err)
	}
	keys := publicKeysFromJWKS(t, jwks)

	for _, alg := range []tester.Algorithm{tester.RS256, tester.ES256, tester.EdDSA} {
		alg := alg
		t.Run(string(alg), func(t *testing.T) {
			tok, err := srv.Mint(tester.MintRequest{
				Algorithm: alg,
				Claims:    map[string]any{"sub": "public-api", "scope": "read"},
			})
			if err != nil {
				t.Fatalf("Mint(%s) error = %v", alg, err)
			}
			if tok.TokenType != "Bearer" {
				t.Fatalf("TokenType = %q, want Bearer", tok.TokenType)
			}
			if tok.ExpiresIn != time.Hour {
				t.Fatalf("ExpiresIn = %v, want %v", tok.ExpiresIn, time.Hour)
			}

			parsed, err := jwt5.NewParser(
				jwt5.WithValidMethods([]string{string(alg)}),
				jwt5.WithIssuer(srv.Issuer()),
			).Parse(tok.AccessToken, func(tk *jwt5.Token) (any, error) {
				kid, _ := tk.Header["kid"].(string)
				key, ok := keys[kid]
				if !ok {
					return nil, fmt.Errorf("kid %q is absent from JWKS", kid)
				}
				return key, nil
			})
			if err != nil {
				t.Fatalf("verify %s token with JWKS key: %v", alg, err)
			}
			claims, ok := parsed.Claims.(jwt5.MapClaims)
			if !ok {
				t.Fatalf("claims type = %T, want jwt.MapClaims", parsed.Claims)
			}
			if got, _ := claims["sub"].(string); got != "public-api" {
				t.Fatalf("sub = %v, want public-api", claims["sub"])
			}
			if got, _ := claims["iss"].(string); got != srv.Issuer() {
				t.Fatalf("iss = %v, want %s", claims["iss"], srv.Issuer())
			}
		})
	}
}

// TestConcurrentStartupAdvertisesBoundIssuer starts several issuers at once and
// asserts each one's tokens and discovery document use its own bound URL. The
// old post-start mutation made this racy and could expose a stale issuer.
func TestConcurrentStartupAdvertisesBoundIssuer(t *testing.T) {
	const servers = 8

	var wg sync.WaitGroup
	failures := make(chan error, servers)
	for i := 0; i < servers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := checkBoundIssuer(); err != nil {
				failures <- err
			}
		}()
	}
	wg.Wait()
	close(failures)

	for err := range failures {
		t.Error(err)
	}
}

func checkBoundIssuer() error {
	srv, err := tester.Start(tester.WithAlgorithms(tester.RS256))
	if err != nil {
		return fmt.Errorf("Start() error = %w", err)
	}
	defer srv.Close()

	if srv.Issuer() != srv.URL() {
		return fmt.Errorf("Issuer() = %q, URL() = %q, want identical", srv.Issuer(), srv.URL())
	}

	resp, err := srv.Client().Get(srv.URL() + "/.well-known/openid-configuration")
	if err != nil {
		return fmt.Errorf("GET discovery: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("discovery status = %d, want 200", resp.StatusCode)
	}
	var discovery struct {
		Issuer string `json:"issuer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return fmt.Errorf("decode discovery: %w", err)
	}
	if discovery.Issuer != srv.Issuer() {
		return fmt.Errorf("discovery issuer = %q, want %q", discovery.Issuer, srv.Issuer())
	}

	tok, err := srv.Mint(tester.MintRequest{Claims: map[string]any{"sub": "concurrent"}})
	if err != nil {
		return fmt.Errorf("Mint() error = %w", err)
	}
	parsed, _, err := jwt5.NewParser().ParseUnverified(tok.AccessToken, jwt5.MapClaims{})
	if err != nil {
		return fmt.Errorf("parse minted token: %w", err)
	}
	claims, ok := parsed.Claims.(jwt5.MapClaims)
	if !ok {
		return fmt.Errorf("claims type = %T, want jwt.MapClaims", parsed.Claims)
	}
	if got, _ := claims["iss"].(string); got != srv.Issuer() {
		return fmt.Errorf("token iss = %v, want %q", claims["iss"], srv.Issuer())
	}
	return nil
}

// TestNoLeakAcrossStartCloseCycles asserts that repeated start/close cycles do
// not accumulate the rotation and visitor-cleanup goroutines. Goroutine counts
// are noisy, so the check allows a small tolerance and retries with a deadline.
func TestNoLeakAcrossStartCloseCycles(t *testing.T) {
	cycle := func() error {
		srv, err := tester.Start(
			tester.WithAlgorithms(tester.RS256, tester.ES256),
			tester.WithRotationInterval(time.Millisecond),
		)
		if err != nil {
			return fmt.Errorf("Start() error = %w", err)
		}
		defer srv.Close()

		if _, err := srv.Mint(tester.MintRequest{}); err != nil {
			return fmt.Errorf("Mint() error = %w", err)
		}
		resp, err := srv.Client().Get(srv.URL() + "/healthz")
		if err != nil {
			return fmt.Errorf("GET healthz: %w", err)
		}
		_ = resp.Body.Close()
		srv.Close()
		return nil
	}

	// Warm up transports and any lazily started runtime goroutines.
	if err := cycle(); err != nil {
		t.Fatalf("warm-up cycle: %v", err)
	}

	const tolerance = 2
	baseline := runtime.NumGoroutine()

	for i := 0; i < 12; i++ {
		if err := cycle(); err != nil {
			t.Fatalf("cycle %d: %v", i, err)
		}
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		got := runtime.NumGoroutine()
		if got <= baseline+tolerance {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutines after 12 cycles = %d, baseline = %d (leak)", got, baseline)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

type jwksDocument struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	KTY string `json:"kty"`
	KID string `json:"kid"`
	ALG string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	CRV string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func publicKeysFromJWKS(t *testing.T, data []byte) map[string]crypto.PublicKey {
	t.Helper()
	var doc jwksDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("decode JWKS: %v", err)
	}
	if len(doc.Keys) == 0 {
		t.Fatal("JWKS contains no keys")
	}
	keys := make(map[string]crypto.PublicKey, len(doc.Keys))
	for _, key := range doc.Keys {
		public, err := key.publicKey()
		if err != nil {
			t.Fatalf("decode JWK %q: %v", key.KID, err)
		}
		keys[key.KID] = public
	}
	return keys
}

func (k jwkKey) publicKey() (crypto.PublicKey, error) {
	switch k.KTY {
	case "RSA":
		n, err := decodeBigInt(k.N)
		if err != nil {
			return nil, fmt.Errorf("modulus: %w", err)
		}
		e, err := decodeBigInt(k.E)
		if err != nil {
			return nil, fmt.Errorf("exponent: %w", err)
		}
		if !e.IsInt64() {
			return nil, fmt.Errorf("exponent does not fit in int64")
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		curves := map[string]elliptic.Curve{
			"P-256": elliptic.P256(),
			"P-384": elliptic.P384(),
			"P-521": elliptic.P521(),
		}
		curve, ok := curves[k.CRV]
		if !ok {
			return nil, fmt.Errorf("unsupported curve %q", k.CRV)
		}
		point, err := encodeUncompressedPoint(curve, k.X, k.Y)
		if err != nil {
			return nil, err
		}
		return ecdsa.ParseUncompressedPublicKey(curve, point)
	case "OKP":
		if k.CRV != "Ed25519" {
			return nil, fmt.Errorf("unsupported OKP curve %q", k.CRV)
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("public key: %w", err)
		}
		if len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("public key length = %d, want %d", len(x), ed25519.PublicKeySize)
		}
		return ed25519.PublicKey(x), nil
	default:
		return nil, fmt.Errorf("unsupported key type %q", k.KTY)
	}
}

// encodeUncompressedPoint encodes JWK x and y coordinates as a SEC 1
// uncompressed point, left-padding each coordinate to the curve size.
func encodeUncompressedPoint(curve elliptic.Curve, x, y string) ([]byte, error) {
	size := (curve.Params().BitSize + 7) / 8
	point := make([]byte, 1+2*size)
	point[0] = 4 // Uncompressed point form.
	for i, coord := range []string{x, y} {
		raw, err := base64.RawURLEncoding.DecodeString(coord)
		if err != nil {
			return nil, fmt.Errorf("coordinate: %w", err)
		}
		if len(raw) > size {
			return nil, fmt.Errorf("coordinate length = %d, want at most %d", len(raw), size)
		}
		copy(point[1+i*size:1+(i+1)*size], raw)
	}
	return point, nil
}

func decodeBigInt(value string) (*big.Int, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(raw), nil
}
