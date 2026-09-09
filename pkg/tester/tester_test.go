package tester

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	jwt5 "github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"

	"github.com/larryf1/jwtoken-tester/internal/keyring"
	"github.com/larryf1/jwtoken-tester/internal/tokenfactory"
)

func TestNewServerReturnsURLAndFactory(t *testing.T) {
	s, url := NewServer(t)
	defer s.Close()

	if url == "" {
		t.Fatal("URL is empty")
	}
	if s.TokenFactory() == nil {
		t.Fatal("TokenFactory is nil")
	}
	if s.KeyRing() == nil {
		t.Fatal("KeyRing is nil")
	}
	if s.Issuer() == "" {
		t.Fatal("Issuer is empty")
	}
	if s.Client() == nil {
		t.Fatal("Client is nil")
	}
}

func TestNewServerWithCustomIssuer(t *testing.T) {
	customIssuer := "https://custom-issuer.example"
	s, _ := NewServer(t, WithIssuer(customIssuer))
	defer s.Close()

	if s.Issuer() != customIssuer {
		t.Fatalf("issuer = %q, want %q", s.Issuer(), customIssuer)
	}
}

func TestNewServerWithCustomAlgorithms(t *testing.T) {
	s, _ := NewServer(t, WithAlgorithms(keyring.AlgRS256))
	defer s.Close()

	algs := s.KeyRing().EnabledAlgorithms()
	if len(algs) != 1 || algs[0] != keyring.AlgRS256 {
		t.Fatalf("algorithms = %v, want [RS256]", algs)
	}
}

func TestNewServerMintTokenAndValidate(t *testing.T) {
	s, url := NewServer(t, WithAlgorithms(keyring.AlgRS256, keyring.AlgES256, keyring.AlgEdDSA))
	defer s.Close()

	for _, alg := range []keyring.Algorithm{keyring.AlgRS256, keyring.AlgES256, keyring.AlgEdDSA} {
		t.Run(string(alg), func(t *testing.T) {
			resp, err := s.TokenFactory().Mint(&tokenfactory.Request{
				Claims: map[string]any{
					"sub":  "user-123",
					"aud":  []string{"svc-a"},
					"role": "admin",
				},
				Alg: string(alg),
			})
			if err != nil {
				t.Fatalf("Mint() error = %v", err)
			}
			if resp.AccessToken == "" {
				t.Fatal("empty access token")
			}

			set := fetchJWKS(t, url+"/.well-known/jwks.json")
			parser := jwt5.NewParser(jwt5.WithValidMethods([]string{string(alg)}), jwt5.WithIssuer(s.Issuer()))
			_, err = parser.Parse(resp.AccessToken, func(tk *jwt5.Token) (any, error) {
				kid, _ := tk.Header["kid"].(string)
				key, ok := set.LookupKeyID(kid)
				if !ok {
					return nil, jwt5.ErrSignatureInvalid
				}
				return exportPublicKey(t, key)
			})
			if err != nil {
				t.Fatalf("golang-jwt rejected minted token: %v", err)
			}
		})
	}
}

func TestNewServerHealthEndpoint(t *testing.T) {
	s, url := NewServer(t)
	defer s.Close()

	resp, err := http.Get(url + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestNewServerDiscoveryEndpoint(t *testing.T) {
	s, _ := NewServer(t)
	defer s.Close()

	resp, err := http.Get(s.URL() + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	if doc["issuer"] != s.Issuer() {
		t.Fatalf("issuer = %v, want %q", doc["issuer"], s.Issuer())
	}
	expectedJWKS := s.URL() + "/.well-known/jwks.json"
	if doc["jwks_uri"] != expectedJWKS {
		t.Fatalf("jwks_uri = %v, want %s", doc["jwks_uri"], expectedJWKS)
	}
}

func TestNewServerTokenEndpoint(t *testing.T) {
	s, url := NewServer(t)
	defer s.Close()

	resp, err := http.Post(url+"/token", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestNewServerJWKSEndpoint(t *testing.T) {
	s, url := NewServer(t)
	defer s.Close()

	set := fetchJWKS(t, url+"/.well-known/jwks.json")
	if set.Len() < 1 {
		t.Fatal("JWKS is empty")
	}
}

func fetchJWKS(t *testing.T, url string) jwk.Set {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := readAll(resp.Body)
	if err != nil {
		t.Fatalf("read jwks response: %v", err)
	}
	set, err := jwk.Parse(data)
	if err != nil {
		t.Fatalf("jwk.Parse: %v", err)
	}
	return set
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
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return pub, nil
}

func readAll(r interface{ Read([]byte) (int, error) }) ([]byte, error) {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			if err.Error() == "EOF" {
				return buf, nil
			}
			return buf, err
		}
	}
}

func TestNewServerWithRotation(t *testing.T) {
	s, _ := NewServer(t, WithRotationInterval(10*time.Millisecond), WithGracePeriod(50*time.Millisecond))
	defer s.Close()

	time.Sleep(50 * time.Millisecond)

	set := fetchJWKS(t, s.URL()+"/.well-known/jwks.json")
	if set.Len() < 1 {
		t.Fatal("JWKS is empty after rotation")
	}
}

func TestNewServerWithCustomTTL(t *testing.T) {
	customTTL := 30 * time.Minute
	s, _ := NewServer(t, WithDefaultTTL(customTTL), WithMaxTTL(2*customTTL))
	defer s.Close()

	resp, err := s.TokenFactory().Mint(&tokenfactory.Request{})
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}

	set := fetchJWKS(t, s.URL()+"/.well-known/jwks.json")
	parser := jwt5.NewParser()
	token, err := parser.Parse(resp.AccessToken, func(tk *jwt5.Token) (interface{}, error) {
		kid, _ := tk.Header["kid"].(string)
		key, ok := set.LookupKeyID(kid)
		if !ok {
			return nil, jwt5.ErrSignatureInvalid
		}
		return exportPublicKey(t, key)
	})
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}

	claims := token.Claims.(jwt5.MapClaims)
	exp, err := claims.GetExpirationTime()
	if err != nil {
		t.Fatalf("GetExpirationTime: %v", err)
	}
	iat, err := claims.GetIssuedAt()
	if err != nil {
		t.Fatalf("GetIssuedAt: %v", err)
	}
	expTime := (*exp).Time
	iatTime := (*iat).Time
	lifetime := expTime.Sub(iatTime)
	expectedLifetime := customTTL
	if lifetime < expectedLifetime-time.Second || lifetime > expectedLifetime+time.Second {
		t.Fatalf("lifetime = %v, want ~%v", lifetime, expectedLifetime)
	}
}
