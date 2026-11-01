package tester

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	jwt5 "github.com/golang-jwt/jwt/v5"
)

func TestStartDefaultIssuerIsBoundURL(t *testing.T) {
	s, err := Start(WithIssuer(""))
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer s.Close()

	if s.URL() == "" {
		t.Fatal("URL() is empty")
	}
	if s.Issuer() != s.URL() {
		t.Fatalf("Issuer() = %q, want bound URL %q", s.Issuer(), s.URL())
	}

	_, body := get(t, s.URL()+"/.well-known/openid-configuration")
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	if doc["issuer"] != s.URL() {
		t.Fatalf("discovery issuer = %v, want %q", doc["issuer"], s.URL())
	}
}

func TestStartExplicitIssuer(t *testing.T) {
	const issuer = "https://idp.example.com"
	s, err := Start(WithIssuer(issuer))
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer s.Close()

	if s.Issuer() != issuer {
		t.Fatalf("Issuer() = %q, want %q", s.Issuer(), issuer)
	}
	tok, err := s.Mint(MintRequest{Claims: map[string]any{"sub": "u"}})
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	claims := mustVerify(t, s, tok.AccessToken, RS256)
	if claims["iss"] != issuer {
		t.Fatalf("iss = %v, want %q", claims["iss"], issuer)
	}
}

func TestStartRejectsEmptyAlgorithms(t *testing.T) {
	_, err := Start(WithAlgorithms())
	if !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("Start() error = %v, want ErrUnsupportedAlgorithm", err)
	}
}

func TestStartRejectsUnsupportedAlgorithm(t *testing.T) {
	_, err := Start(WithAlgorithms(Algorithm("HS256")))
	if !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("Start() error = %v, want ErrUnsupportedAlgorithm", err)
	}
}

func TestFailedStartLeavesNoGoroutines(t *testing.T) {
	before := runtime.NumGoroutine()
	for i := 0; i < 10; i++ {
		if _, err := Start(WithAlgorithms()); err == nil {
			t.Fatal("Start() with no algorithms unexpectedly succeeded")
		}
	}
	after := runtime.NumGoroutine()
	if after > before+2 {
		t.Fatalf("goroutines grew from %d to %d after failed starts", before, after)
	}
}

func TestNewServerReturnsOnlyHandle(t *testing.T) {
	s := NewServer(t)
	if s.URL() == "" || s.Issuer() == "" || s.Client() == nil || s.Handler() == nil {
		t.Fatalf("NewServer() returned incomplete handle: %#v", s)
	}
}

func TestMintDefaultAlgorithmIsRS256(t *testing.T) {
	s := NewServer(t, WithAlgorithms(RS256))
	tok, err := s.Mint(MintRequest{Claims: map[string]any{"sub": "user-1"}})
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	if tok.TokenType != "Bearer" {
		t.Fatalf("TokenType = %q, want Bearer", tok.TokenType)
	}
	if tok.ExpiresIn < 59*time.Minute || tok.ExpiresIn > 61*time.Minute {
		t.Fatalf("ExpiresIn = %v, want about 1h", tok.ExpiresIn)
	}
	if alg := headerString(t, tok.AccessToken, "alg"); alg != string(RS256) {
		t.Fatalf("alg = %q, want RS256", alg)
	}
	claims := mustVerify(t, s, tok.AccessToken, RS256)
	if claims["sub"] != "user-1" {
		t.Fatalf("sub = %v, want user-1", claims["sub"])
	}
}

func TestMintHonorsRequestedAlgorithm(t *testing.T) {
	s := NewServer(t, WithAlgorithms(RS256, ES256, EdDSA))
	for _, alg := range []Algorithm{ES256, EdDSA} {
		t.Run(string(alg), func(t *testing.T) {
			tok, err := s.Mint(MintRequest{
				Claims:    map[string]any{"sub": "user-1"},
				Algorithm: alg,
			})
			if err != nil {
				t.Fatalf("Mint() error = %v", err)
			}
			if got := headerString(t, tok.AccessToken, "alg"); got != string(alg) {
				t.Fatalf("alg = %q, want %q", got, alg)
			}
			claims := mustVerify(t, s, tok.AccessToken, alg)
			if claims["sub"] != "user-1" {
				t.Fatalf("sub = %v, want user-1", claims["sub"])
			}
		})
	}
}

func TestMintRejectsTTLAboveMaximum(t *testing.T) {
	s := NewServer(t, WithMaxTTL(time.Hour))
	_, err := s.Mint(MintRequest{Claims: map[string]any{"exp": "2h"}})
	if !errors.Is(err, ErrTTLTooLong) {
		t.Fatalf("Mint() error = %v, want ErrTTLTooLong", err)
	}
}

func TestMintRejectsUnsupportedAlgorithm(t *testing.T) {
	s := NewServer(t, WithAlgorithms(RS256))
	if _, err := s.Mint(MintRequest{Algorithm: ES256}); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("Mint(ES256) error = %v, want ErrUnsupportedAlgorithm", err)
	}
	if _, err := s.Mint(MintRequest{Algorithm: Algorithm("HS256")}); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("Mint(HS256) error = %v, want ErrUnsupportedAlgorithm", err)
	}
}

func TestMintRejectsMalformedClaims(t *testing.T) {
	s := NewServer(t)
	_, err := s.Mint(MintRequest{Claims: map[string]any{"exp": "not-a-time"}})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Mint() error = %v, want ErrInvalidRequest", err)
	}
}

func TestKeysAreOrderedByKeyID(t *testing.T) {
	s := NewServer(t)
	first := s.Keys()
	second := s.Keys()
	if len(first) != 3 {
		t.Fatalf("Keys() length = %d, want 3", len(first))
	}
	if !sort.SliceIsSorted(first, func(i, j int) bool { return first[i].KID < first[j].KID }) {
		t.Fatalf("Keys() is not ordered by KID: %v", first)
	}
	for i := range first {
		if first[i].KID != second[i].KID {
			t.Fatalf("Keys() order changed: %v vs %v", first, second)
		}
		if first[i].Retired {
			t.Fatalf("fresh key %s is marked retired", first[i].KID)
		}
		kid, err := s.ActiveKeyID(first[i].Algorithm)
		if err != nil {
			t.Fatalf("ActiveKeyID(%s) error = %v", first[i].Algorithm, err)
		}
		if kid != first[i].KID {
			t.Fatalf("ActiveKeyID(%s) = %q, want %q", first[i].Algorithm, kid, first[i].KID)
		}
	}
}

func TestRotateKeepsRetiredKeysUntilPruned(t *testing.T) {
	s := NewServer(t, WithAlgorithms(RS256), WithGracePeriod(time.Hour))
	oldKID, err := s.ActiveKeyID(RS256)
	if err != nil {
		t.Fatalf("ActiveKeyID() error = %v", err)
	}

	if err := s.Rotate(); err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	newKID, err := s.ActiveKeyID(RS256)
	if err != nil {
		t.Fatalf("ActiveKeyID() error = %v", err)
	}
	if newKID == oldKID {
		t.Fatal("Rotate() did not change the active key")
	}

	if len(s.Keys()) != 2 {
		t.Fatalf("Keys() length = %d, want 2 during grace", len(s.Keys()))
	}
	keys := s.Keys()
	var retired *KeyInfo
	for i := range keys {
		if keys[i].KID == oldKID {
			retired = &keys[i]
		}
	}
	if retired == nil || !retired.Retired || retired.RetiredAt.IsZero() {
		t.Fatalf("retired key %s not reported with Retired/RetiredAt: %#v", oldKID, retired)
	}
	if _, err := s.PublicKey(oldKID); err != nil {
		t.Fatalf("PublicKey(retired) error = %v", err)
	}
	kids := jwksKIDs(t, s)
	if !contains(kids, oldKID) || !contains(kids, newKID) {
		t.Fatalf("JWKS kids = %v, want both %q and %q during grace", kids, oldKID, newKID)
	}

	s.PruneAt(time.Now().Add(2 * time.Hour))

	if _, err := s.PublicKey(oldKID); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("PublicKey(pruned) error = %v, want ErrKeyNotFound", err)
	}
	if got := s.Keys(); len(got) != 1 || got[0].KID != newKID {
		t.Fatalf("Keys() after prune = %#v, want only %q", got, newKID)
	}
	if kids := jwksKIDs(t, s); contains(kids, oldKID) {
		t.Fatalf("JWKS still contains pruned kid %q: %v", oldKID, kids)
	}
}

func TestPublicKeyPEMRoundTrip(t *testing.T) {
	s := NewServer(t, WithAlgorithms(RS256))
	kid, err := s.ActiveKeyID(RS256)
	if err != nil {
		t.Fatalf("ActiveKeyID() error = %v", err)
	}

	pemBytes, err := s.PublicKeyPEM(kid)
	if err != nil {
		t.Fatalf("PublicKeyPEM() error = %v", err)
	}
	block, rest := pem.Decode(pemBytes)
	if block == nil || len(rest) != 0 {
		t.Fatalf("PublicKeyPEM() did not return one PEM block: %q", pemBytes)
	}
	if block.Type != "PUBLIC KEY" {
		t.Fatalf("PEM type = %q, want PUBLIC KEY", block.Type)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey() error = %v", err)
	}
	public, err := s.PublicKey(kid)
	if err != nil {
		t.Fatalf("PublicKey() error = %v", err)
	}
	wantDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}
	gotDER, err := x509.MarshalPKIXPublicKey(parsed)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey(parsed) error = %v", err)
	}
	if !bytes.Equal(gotDER, wantDER) {
		t.Fatal("PEM public key does not match PublicKey()")
	}
}

func TestKeyAccessorsReportUnknownKID(t *testing.T) {
	s := NewServer(t)
	if _, err := s.PublicKey("missing"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("PublicKey(missing) error = %v, want ErrKeyNotFound", err)
	}
	if _, err := s.PublicKeyPEM("missing"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("PublicKeyPEM(missing) error = %v, want ErrKeyNotFound", err)
	}
}

func TestActiveKeyIDRejectsDisabledAlgorithm(t *testing.T) {
	s := NewServer(t, WithAlgorithms(RS256))
	if _, err := s.ActiveKeyID(ES256); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("ActiveKeyID(ES256) error = %v, want ErrUnsupportedAlgorithm", err)
	}
}

func TestCloseIsIdempotentAndConcurrentSafe(t *testing.T) {
	s, err := Start(WithRotationInterval(time.Millisecond))
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Close()
		}()
	}
	wg.Wait()
	s.Close()

	select {
	case <-s.rotationDone:
	default:
		t.Fatal("rotation goroutine still running after Close")
	}

	if resp, err := s.Client().Get(s.URL() + "/healthz"); err == nil {
		_ = resp.Body.Close()
		t.Fatal("listener still accepting requests after Close")
	}

	tok, err := s.Mint(MintRequest{Claims: map[string]any{"sub": "after-close"}})
	if err != nil {
		t.Fatalf("Mint() after Close error = %v", err)
	}
	if tok.AccessToken == "" {
		t.Fatal("Mint() after Close returned an empty token")
	}
	if len(s.Keys()) == 0 {
		t.Fatal("Keys() after Close returned no keys")
	}
	if _, err := s.JWKSJSON(); err != nil {
		t.Fatalf("JWKSJSON() after Close error = %v", err)
	}
}

func TestCloseStopsRotation(t *testing.T) {
	s, err := Start(WithRotationInterval(5 * time.Millisecond))
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	s.Close()
	select {
	case <-s.rotationDone:
	default:
		t.Fatal("rotation goroutine still running after Close")
	}
}

func TestRotationDisabledWhenIntervalNotSet(t *testing.T) {
	s, err := Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer s.Close()
	select {
	case <-s.rotationDone:
	default:
		t.Fatal("rotation goroutine started without a positive interval")
	}
}

func TestHandlerServesEndpointsForIssuer(t *testing.T) {
	s := NewServer(t, WithIssuer("https://issuer.example.com"))

	for _, path := range []string{"/.well-known/openid-configuration", "/.well-known/jwks.json"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s via Handler() = %d, want 200", path, w.Code)
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(`{"claims":{"sub":"handler"}}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /token via Handler() = %d, want 200: %s", w.Code, w.Body.String())
	}

	resp, err := s.Client().Get(s.URL() + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET discovery via Client(): %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	if doc["issuer"] != s.Issuer() {
		t.Fatalf("discovery issuer = %v, want %q", doc["issuer"], s.Issuer())
	}
}

func TestLoggingIsOptIn(t *testing.T) {
	var buf bytes.Buffer
	original := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(original) })

	s := NewServer(t)
	if err := postToken(t, s); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Fatalf("default embedded issuer logged to slog.Default(): %s", buf.String())
	}
}

func TestWithLoggerRoutesEvents(t *testing.T) {
	var buf bytes.Buffer
	s := NewServer(t, WithLogger(slog.New(slog.NewJSONHandler(&buf, nil))))
	if err := postToken(t, s); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "token_audit") {
		t.Fatalf("configured logger did not receive audit events: %s", buf.String())
	}
}

func TestOptionsShapeServerBehavior(t *testing.T) {
	const ttl = 30 * time.Minute
	s := NewServer(t, WithAlgorithms(RS256), WithDefaultTTL(ttl), WithMaxTTL(2*ttl))

	keys := s.Keys()
	if len(keys) != 1 || keys[0].Algorithm != RS256 {
		t.Fatalf("Keys() = %#v, want only RS256", keys)
	}
	select {
	case <-s.rotationDone:
	default:
		t.Fatal("rotation started without a positive interval")
	}

	tok, err := s.Mint(MintRequest{})
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	if tok.ExpiresIn < ttl-time.Second || tok.ExpiresIn > ttl+time.Second {
		t.Fatalf("default lifetime = %v, want ~%v", tok.ExpiresIn, ttl)
	}
}

func mustVerify(t *testing.T, s *Server, raw string, alg Algorithm) jwt5.MapClaims {
	t.Helper()
	tok, err := jwt5.NewParser(
		jwt5.WithValidMethods([]string{string(alg)}),
		jwt5.WithIssuer(s.Issuer()),
	).Parse(raw, func(tk *jwt5.Token) (any, error) {
		kid, _ := tk.Header["kid"].(string)
		return s.PublicKey(kid)
	})
	if err != nil {
		t.Fatalf("token verification failed: %v", err)
	}
	return tok.Claims.(jwt5.MapClaims)
}

func headerString(t *testing.T, raw, name string) string {
	t.Helper()
	tok, _, err := jwt5.NewParser().ParseUnverified(raw, jwt5.MapClaims{})
	if err != nil {
		t.Fatalf("parse token header: %v", err)
	}
	value, _ := tok.Header[name].(string)
	return value
}

func jwksKIDs(t *testing.T, s *Server) []string {
	t.Helper()
	data, err := s.JWKSJSON()
	if err != nil {
		t.Fatalf("JWKSJSON() error = %v", err)
	}
	var doc struct {
		Keys []struct {
			KID string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("decode JWKS: %v", err)
	}
	kids := make([]string, len(doc.Keys))
	for i, key := range doc.Keys {
		kids[i] = key.KID
	}
	return kids
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func get(t *testing.T, url string) (int, []byte) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body bytes.Buffer
	if _, err := body.ReadFrom(resp.Body); err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	return resp.StatusCode, body.Bytes()
}

func postToken(t *testing.T, s *Server) error {
	t.Helper()
	resp, err := s.Client().Post(s.URL()+"/token", "application/json", strings.NewReader(`{"claims":{"sub":"log-check"}}`))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return errors.New("unexpected status: " + resp.Status)
	}
	return nil
}
