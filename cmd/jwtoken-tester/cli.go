package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	jwt5 "github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v4/jwk"

	"github.com/larryf1/jwtoken-tester/v2/internal/keyring"
	"github.com/larryf1/jwtoken-tester/v2/internal/verify"
)

const (
	maxKeySourceBytes = 1 << 20
	keySourceTimeout  = 5 * time.Second
	maxRedirects      = 5
)

// runDecodeCommand implements `jwtoken-tester decode`. It only checks that the
// value is a three-segment compact JWS with JSON header and payload; it never
// validates the signature or any claim.
func runDecodeCommand(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("decode", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: jwtoken-tester decode [token]")
	}
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() > 1 {
		fmt.Fprintln(stderr, "decode: at most one token argument is accepted")
		return 1
	}

	token, err := tokenFromArgsOrStdin(fs.Args(), stdin)
	if err != nil {
		fmt.Fprintf(stderr, "decode: %v\n", err)
		return 1
	}

	header, claims, err := decodeCompactJWS(token)
	if err != nil {
		fmt.Fprintf(stderr, "decode: %v\n", err)
		return 1
	}

	out := struct {
		Header map[string]any `json:"header"`
		Claims map[string]any `json:"claims"`
	}{Header: header, Claims: claims}

	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(stderr, "decode: writing output: %v\n", err)
		return 1
	}
	return 0
}

func decodeCompactJWS(token string) (map[string]any, map[string]any, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("value is not a three-segment compact JWS")
	}

	header, err := decodeJWSPart(parts[0], "header")
	if err != nil {
		return nil, nil, err
	}
	claims, err := decodeJWSPart(parts[1], "payload")
	if err != nil {
		return nil, nil, err
	}
	return header, claims, nil
}

func decodeJWSPart(part, name string) (map[string]any, error) {
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return nil, fmt.Errorf("decoding %s: %w", name, err)
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, fmt.Errorf("decoding %s JSON: %w", name, err)
	}
	return value, nil
}

func tokenFromArgsOrStdin(args []string, stdin io.Reader) (string, error) {
	if len(args) > 1 {
		return "", errors.New("at most one token argument is accepted")
	}
	if len(args) == 1 {
		token := strings.TrimSpace(args[0])
		if token == "" {
			return "", errors.New("token is empty")
		}
		return token, nil
	}

	raw, err := io.ReadAll(stdin)
	if err != nil {
		return "", fmt.Errorf("reading stdin: %w", err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", errors.New("no token argument or piped input")
	}
	return token, nil
}

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

type verifyConfig struct {
	JWKS     string
	Issuer   string
	Audience string
	Algs     stringList
	Leeway   time.Duration
	JSON     bool
}

// runVerifyCommand implements `jwtoken-tester verify`. Exit codes are the
// documented contract: 0 valid, 1 invalid verdict, 2 operational/usage failure.
func runVerifyCommand(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var cfg verifyConfig
	fs.StringVar(&cfg.JWKS, "jwks", "", "JWKS URL or file path")
	fs.StringVar(&cfg.Issuer, "issuer", "", "issuer URL; keys and expected iss come from discovery")
	fs.StringVar(&cfg.Audience, "aud", "", "expected audience")
	fs.Var(&cfg.Algs, "alg", "accepted algorithm (repeatable)")
	fs.DurationVar(&cfg.Leeway, "leeway", 0, "clock skew allowance for exp/nbf/iat")
	fs.BoolVar(&cfg.JSON, "json", false, "print the verdict envelope as JSON")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: jwtoken-tester verify (--jwks <url|file> | --issuer <url>) [--aud <aud>] [--alg <alg>]... [--leeway <duration>] [--json] [token]")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if (cfg.JWKS == "") == (cfg.Issuer == "") {
		fmt.Fprintln(stderr, "verify: exactly one of --jwks or --issuer is required")
		fs.Usage()
		return 2
	}

	algs, err := normalizeAlgorithms(cfg.Algs)
	if err != nil {
		fmt.Fprintf(stderr, "verify: %v\n", err)
		return 2
	}

	token, err := tokenFromArgsOrStdin(fs.Args(), stdin)
	if err != nil {
		fmt.Fprintf(stderr, "verify: %v\n", err)
		return 2
	}

	keys, expectedIssuer, err := loadKeySource(cfg.JWKS, cfg.Issuer)
	if err != nil {
		fmt.Fprintf(stderr, "verify: %v\n", err)
		return 2
	}

	var audience []string
	if cfg.Audience != "" {
		audience = []string{cfg.Audience}
	}

	verdict, err := verify.Verify(verify.Input{
		Token:          token,
		Keys:           keys,
		ExpectedIssuer: expectedIssuer,
		AllowedAlgs:    algs,
		Audience:       audience,
		Leeway:         cfg.Leeway,
		Now:            time.Now().UTC(),
	})
	if err != nil {
		fmt.Fprintf(stderr, "verify: %v\n", err)
		return 2
	}

	if cfg.JSON {
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(verdict); err != nil {
			fmt.Fprintf(stderr, "verify: writing output: %v\n", err)
			return 2
		}
	} else {
		printVerdict(stdout, verdict)
	}

	if !verdict.Valid {
		if verdict.Reason == verify.ReasonKid && verdict.KidStatus == verify.KeyStatusUnknown {
			fmt.Fprintln(stderr, "hint: the token's kid was not found in the key source. Tokens minted by `jwtoken-tester print-token` use a throwaway in-memory keyring and cannot verify against a running server; restarting `serve` also discards its keys.")
		}
		return 1
	}
	return 0
}

func normalizeAlgorithms(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(values))
	var out []string
	for _, value := range values {
		alg := strings.TrimSpace(value)
		if alg == "" {
			return nil, errors.New("--alg requires a non-empty algorithm")
		}
		if strings.EqualFold(alg, "none") || jwt5.GetSigningMethod(alg) == nil {
			return nil, fmt.Errorf("unsupported algorithm %q", alg)
		}
		if _, ok := seen[alg]; ok {
			continue
		}
		seen[alg] = struct{}{}
		out = append(out, alg)
	}
	return out, nil
}

func printVerdict(w io.Writer, verdict verify.Verdict) {
	if verdict.Valid {
		fmt.Fprint(w, "valid: token verified")
		var details []string
		if verdict.Alg != "" {
			details = append(details, "alg="+verdict.Alg)
		}
		if verdict.Kid != "" {
			details = append(details, "kid="+verdict.Kid)
		}
		if len(details) > 0 {
			fmt.Fprintf(w, " (%s)", strings.Join(details, " "))
		}
		fmt.Fprintln(w)
		return
	}

	fmt.Fprintf(w, "invalid: %s", verdict.Reason)
	if verdict.Error != "" {
		fmt.Fprintf(w, ": %s", verdict.Error)
	}
	fmt.Fprintln(w)
}

func loadKeySource(jwksValue, issuerValue string) (*jwksKeySource, string, error) {
	if issuerValue != "" {
		return loadDiscoveryKeySource(issuerValue)
	}
	raw, err := loadKeySourceBytes(jwksValue)
	if err != nil {
		return nil, "", err
	}
	keys, err := parseJWKS(raw)
	if err != nil {
		return nil, "", err
	}
	return keys, "", nil
}

func loadDiscoveryKeySource(issuer string) (*jwksKeySource, string, error) {
	discoveryURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	raw, err := fetchBytes(discoveryURL)
	if err != nil {
		return nil, "", err
	}

	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, "", fmt.Errorf("parsing discovery document %s: %w", discoveryURL, err)
	}
	if strings.TrimSpace(doc.JWKSURI) == "" {
		return nil, "", fmt.Errorf("discovery document %s has no jwks_uri", discoveryURL)
	}

	jwksURL, err := resolveReference(discoveryURL, doc.JWKSURI)
	if err != nil {
		return nil, "", fmt.Errorf("resolving jwks_uri %q: %w", doc.JWKSURI, err)
	}
	raw, err = fetchBytes(jwksURL)
	if err != nil {
		return nil, "", err
	}
	keys, err := parseJWKS(raw)
	if err != nil {
		return nil, "", err
	}

	expectedIssuer := doc.Issuer
	if expectedIssuer == "" {
		expectedIssuer = issuer
	}
	return keys, expectedIssuer, nil
}

func resolveReference(base, ref string) (string, error) {
	baseURL, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	refURL, err := url.Parse(ref)
	if err != nil {
		return "", err
	}
	return baseURL.ResolveReference(refURL).String(), nil
}

func loadKeySourceBytes(value string) ([]byte, error) {
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		return fetchBytes(value)
	}
	raw, err := os.ReadFile(value)
	if err != nil {
		return nil, fmt.Errorf("reading key source %s: %w", value, err)
	}
	if len(raw) > maxKeySourceBytes {
		return nil, fmt.Errorf("key source %s exceeds %d bytes", value, maxKeySourceBytes)
	}
	return raw, nil
}

func fetchBytes(rawURL string) ([]byte, error) {
	client := &http.Client{
		Timeout: keySourceTimeout,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) > maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			return nil
		},
	}

	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building request for %s: %w", rawURL, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", rawURL, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: %s", rawURL, resp.Status)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxKeySourceBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", rawURL, err)
	}
	if len(raw) > maxKeySourceBytes {
		return nil, fmt.Errorf("response from %s exceeds %d bytes", rawURL, maxKeySourceBytes)
	}
	return raw, nil
}

type jwksKeySource struct {
	keys       map[string]crypto.PublicKey
	algorithms []string
}

func (s *jwksKeySource) Lookup(kid string) (crypto.PublicKey, keyring.KeyStatus, error) {
	key, ok := s.keys[kid]
	if !ok {
		return nil, "", fmt.Errorf("%w: kid %q", keyring.ErrKeyNotFound, kid)
	}
	return key, keyring.KeyStatusActive, nil
}

func (s *jwksKeySource) Algorithms() []string { return s.algorithms }

func parseJWKS(raw []byte) (*jwksKeySource, error) {
	set, err := jwk.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing JWKS: %w", err)
	}

	keys := make(map[string]crypto.PublicKey)
	algSeen := make(map[string]struct{})
	for _, key := range set.All() {
		if key == nil {
			continue
		}
		if err := jwk.AssignKeyID(key); err != nil {
			continue
		}
		kid, ok := key.KeyID()
		if !ok || kid == "" {
			continue
		}
		pubJWK, err := key.PublicKey()
		if err != nil {
			continue
		}
		pub, err := jwk.Export[crypto.PublicKey](pubJWK)
		if err != nil {
			continue
		}
		keys[kid] = pub
		for _, alg := range keyAlgorithms(key, pub) {
			algSeen[alg] = struct{}{}
		}
	}

	if len(keys) == 0 {
		return nil, errors.New("JWKS contained no usable public keys")
	}

	algorithms := make([]string, 0, len(algSeen))
	for alg := range algSeen {
		algorithms = append(algorithms, alg)
	}
	sort.Strings(algorithms)

	return &jwksKeySource{keys: keys, algorithms: algorithms}, nil
}

func keyAlgorithms(key jwk.Key, pub crypto.PublicKey) []string {
	if alg, ok := key.Algorithm(); ok && alg.String() != "" {
		return []string{alg.String()}
	}

	switch typed := pub.(type) {
	case *rsa.PublicKey:
		return []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}
	case *ecdsa.PublicKey:
		switch typed.Curve {
		case elliptic.P256():
			return []string{"ES256"}
		case elliptic.P384():
			return []string{"ES384"}
		case elliptic.P521():
			return []string{"ES512"}
		default:
			return []string{"ES256", "ES384", "ES512"}
		}
	case ed25519.PublicKey:
		return []string{"EdDSA"}
	default:
		return nil
	}
}
