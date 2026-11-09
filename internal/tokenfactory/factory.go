package tokenfactory

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/larryf1/jwtoken-tester/v2/internal/keyring"
)

var (
	ErrUnsupportedAlg   = errors.New("unsupported algorithm")
	ErrTTLTooLong       = errors.New("requested lifetime exceeds maximum allowed")
	ErrInvalidRequest   = errors.New("invalid token request")
	ErrNegativeDisabled = errors.New("negative token controls are disabled")
)

type Request struct {
	Claims         map[string]any `json:"claims"`
	Alg            string         `json:"alg,omitempty"`
	Headers        map[string]any `json:"headers,omitempty"`
	KID            string         `json:"kid,omitempty"`
	Typ            string         `json:"typ,omitempty"`
	CTY            string         `json:"cty,omitempty"`
	Corrupt        string         `json:"corrupt,omitempty"`
	DuplicateClaim string         `json:"duplicate_claim,omitempty"`
	AllowNegative  bool           `json:"-"`
}

type Response struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

type Factory struct {
	ring       keyring.Ring
	issuer     string
	defaultTTL time.Duration
	maxTTL     time.Duration
	hmacSecret []byte
}

// SetHMACSecret configures HS256 signing. The secret must contain at least 32 bytes.
func (f *Factory) SetHMACSecret(secret []byte) { f.hmacSecret = append([]byte(nil), secret...) }

func NewFactory(ring keyring.Ring, issuer string, defaultTTL, maxTTL time.Duration) *Factory {
	return &Factory{ring: ring, issuer: issuer, defaultTTL: defaultTTL, maxTTL: maxTTL}
}

// MaxTTL reports the configured lifetime cap. Zero means no cap.
func (f *Factory) MaxTTL() time.Duration {
	return f.maxTTL
}

func (f *Factory) Mint(req *Request) (*Response, error) {
	if req == nil {
		req = &Request{}
	}

	alg := keyring.AlgRS256
	if req.Alg != "" {
		alg = keyring.Algorithm(req.Alg)
	}

	negative := alg == "none" || req.Corrupt != "" || req.DuplicateClaim != ""
	if req.Corrupt != "" && !contains([]string{"signature", "payload", "header", "truncate", "duplicate_claims"}, req.Corrupt) {
		return nil, fmt.Errorf("%w: corrupt mode %q", ErrInvalidRequest, req.Corrupt)
	}
	if negative && !req.AllowNegative {
		return nil, ErrNegativeDisabled
	}
	switch alg {
	case "HS256":
		if len(f.hmacSecret) < 32 {
			return nil, fmt.Errorf("%w: HS256 requires an HMAC secret of at least 32 bytes", ErrUnsupportedAlg)
		}
	case "none":
		// enabled through the negative-token gate
	default:
		_, ok := keyring.JWAAlgorithms()[alg]
		if !ok {
			supported := make([]string, 0, len(keyring.JWAAlgorithms()))
			for a := range keyring.JWAAlgorithms() {
				supported = append(supported, string(a))
			}
			return nil, fmt.Errorf("%w: %q (supported: %v)", ErrUnsupportedAlg, req.Alg, supported)
		}
	}

	now := time.Now().UTC().Truncate(time.Second)
	tok := jwt.New()

	var exp time.Time
	expSet := false
	for name, value := range req.Claims {
		switch name {
		case jwt.ExpirationKey:
			t, err := ParseTimeValue(value, now)
			if err != nil {
				return nil, fmt.Errorf("%w: claim %q: %v", ErrInvalidRequest, name, err)
			}
			exp = t
			expSet = true
		case jwt.IssuedAtKey, jwt.NotBeforeKey:
			t, err := ParseTimeValue(value, now)
			if err != nil {
				return nil, fmt.Errorf("%w: claim %q: %v", ErrInvalidRequest, name, err)
			}
			if err := tok.Set(name, t); err != nil {
				return nil, fmt.Errorf("%w: claim %q: %v", ErrInvalidRequest, name, err)
			}
		default:
			if err := tok.Set(name, value); err != nil {
				return nil, fmt.Errorf("%w: claim %q: %v", ErrInvalidRequest, name, err)
			}
		}
	}

	if !tok.Has(jwt.IssuerKey) && f.issuer != "" {
		_ = tok.Set(jwt.IssuerKey, f.issuer)
	}
	if !tok.Has(jwt.IssuedAtKey) {
		_ = tok.Set(jwt.IssuedAtKey, now)
	}
	if !tok.Has(jwt.NotBeforeKey) {
		_ = tok.Set(jwt.NotBeforeKey, now)
	}
	if !expSet {
		exp = now.Add(f.defaultTTL)
	}
	if err := tok.Set(jwt.ExpirationKey, exp); err != nil {
		return nil, err
	}

	lifetime := exp.Sub(now)
	if f.maxTTL > 0 && lifetime > f.maxTTL {
		return nil, ErrTTLTooLong
	}

	if alg == "none" {
		return f.rawToken(tok, "none", nil, req, lifetime)
	}
	if alg == "HS256" {
		return f.rawToken(tok, "HS256", f.hmacSecret, req, lifetime)
	}
	var signer *keyring.Key
	var err error
	if req.KID != "" {
		signer, err = f.ring.SignerByKID(req.KID, alg)
		if errors.Is(err, keyring.ErrKeyNotFound) {
			for _, candidate := range f.ring.EnabledAlgorithms() {
				if candidate != alg {
					if _, lookupErr := f.ring.SignerByKID(req.KID, candidate); lookupErr == nil {
						return nil, fmt.Errorf("%w: kid %q belongs to a different algorithm", ErrInvalidRequest, req.KID)
					}
				}
			}
		}
		if errors.Is(err, keyring.ErrKeyNotFound) && !req.AllowNegative {
			return nil, ErrNegativeDisabled
		}
	} else {
		signer, err = f.ring.Signer(alg)
	}
	if errors.Is(err, keyring.ErrKeyNotFound) && req.KID != "" && req.AllowNegative {
		signer, err = f.ring.Signer(alg)
	}
	if err != nil {
		if errors.Is(err, keyring.ErrUnsupportedAlg) {
			return nil, ErrUnsupportedAlg
		}
		return nil, err
	}

	jwaAlg := keyring.JWAAlgorithms()[alg]
	hdrs := jws.NewHeaders()
	_ = hdrs.Set("typ", defaultString(req.Typ, "JWT"))
	_ = hdrs.Set("kid", req.KID)
	if req.KID == "" {
		_ = hdrs.Set("kid", signer.Kid())
	}
	if req.CTY != "" {
		_ = hdrs.Set("cty", req.CTY)
	}
	if len(req.Headers) > 0 {
		for name, value := range req.Headers {
			switch strings.ToLower(name) {
			case "alg", "kid", "typ", "cty":
				return nil, fmt.Errorf("%w: reserved header %q", ErrInvalidRequest, name)
			}
			if err := hdrs.Set(name, value); err != nil {
				return nil, fmt.Errorf("%w: header %q: %v", ErrInvalidRequest, name, err)
			}
		}

	}
	signOpt := jwt.WithKey(jwaAlg, signer.Private, jws.WithProtectedHeaders(hdrs))
	if req.Corrupt == "duplicate_claims" || req.DuplicateClaim != "" {
		payload, marshalErr := json.Marshal(tok)
		if marshalErr != nil {
			return nil, fmt.Errorf("%w: claims: %v", ErrInvalidRequest, marshalErr)
		}
		claim := req.DuplicateClaim
		if claim == "" {
			claim = "sub"
		}
		value, has := tok.Field(claim)
		if !has {
			value = "duplicate"
		}
		encodedValue, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			return nil, fmt.Errorf("%w: duplicate claim: %v", ErrInvalidRequest, marshalErr)
		}
		if len(payload) < 2 || payload[len(payload)-1] != '}' {
			return nil, fmt.Errorf("%w: claims are not a JSON object", ErrInvalidRequest)
		}
		separator := ","
		if len(payload) == 2 {
			separator = ""
		}
		payload = append(payload[:len(payload)-1], []byte(fmt.Sprintf("%s%q:%s}", separator, claim, encodedValue))...)
		signed, signErr := jws.Sign(payload, jws.WithKey(jwaAlg, signer.Private, jws.WithProtectedHeaders(hdrs)))
		if signErr != nil {
			return nil, fmt.Errorf("sign token: %w", signErr)
		}
		return &Response{AccessToken: string(signed), TokenType: "Bearer", ExpiresIn: int64(math.Round(lifetime.Seconds()))}, nil
	}

	signed, err := jwt.Sign(tok, signOpt)
	if err != nil {
		return nil, fmt.Errorf("sign token: %w", err)
	}

	if req.Corrupt != "" {
		signed = corruptToken(signed, req.Corrupt)
	}
	return &Response{
		AccessToken: string(signed),
		TokenType:   "Bearer",
		ExpiresIn:   int64(math.Round(lifetime.Seconds())),
	}, nil
}

func contains(values []string, s string) bool {
	for _, v := range values {
		if v == s {
			return true
		}
	}
	return false
}
func defaultString(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func (f *Factory) rawToken(tok jwt.Token, alg string, secret []byte, req *Request, lifetime time.Duration) (*Response, error) {
	claims, err := json.Marshal(tok)
	if err != nil {
		return nil, fmt.Errorf("%w: claims: %v", ErrInvalidRequest, err)
	}
	header := map[string]any{"alg": alg, "typ": defaultString(req.Typ, "JWT")}
	if req.KID != "" {
		header["kid"] = req.KID
	}
	if req.CTY != "" {
		header["cty"] = req.CTY
	}
	for k, v := range req.Headers {
		switch strings.ToLower(k) {
		case "alg", "kid", "typ", "cty":
			return nil, fmt.Errorf("%w: reserved header %q", ErrInvalidRequest, k)
		}
		header[k] = v
	}
	h, _ := json.Marshal(header)
	enc := base64.RawURLEncoding
	input := enc.EncodeToString(h) + "." + enc.EncodeToString(claims)
	sig := ""
	if alg == "HS256" {
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write([]byte(input))
		sig = enc.EncodeToString(mac.Sum(nil))
	}
	return &Response{AccessToken: input + "." + sig, TokenType: "Bearer", ExpiresIn: int64(math.Round(lifetime.Seconds()))}, nil
}

func corruptToken(token []byte, mode string) []byte {
	parts := strings.Split(string(token), ".")
	switch mode {
	case "truncate":
		if len(token) > 1 {
			return token[:len(token)-1]
		}
	case "signature":
		if len(parts) == 3 && len(parts[2]) > 0 {
			b := []byte(parts[2])
			if b[0] == 'A' {
				b[0] = 'B'
			} else {
				b[0] = 'A'
			}
			parts[2] = string(b)
		}
	case "payload", "header":
		if len(parts) == 3 {
			i := 1
			if mode == "header" {
				i = 0
			}
			b, err := base64.RawURLEncoding.DecodeString(parts[i])
			if err == nil && len(b) > 0 {
				b[0] ^= 1
				parts[i] = base64.RawURLEncoding.EncodeToString(b)
			}
		}
	case "duplicate_claims":
		return token
	}
	return []byte(strings.Join(parts, "."))
}

func ParseTimeValue(value any, now time.Time) (time.Time, error) {
	switch v := value.(type) {
	case float64:
		return time.Unix(int64(v), 0).UTC(), nil
	case int:
		return time.Unix(int64(v), 0).UTC(), nil
	case int64:
		return time.Unix(v, 0).UTC(), nil
	case string:
		s := strings.TrimSpace(v)
		s = strings.TrimPrefix(s, "in ")
		s = strings.TrimSpace(s)
		if d, err := time.ParseDuration(s); err == nil {
			return now.Add(d), nil
		}
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t.UTC(), nil
		}
		if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
			return time.Unix(n, 0).UTC(), nil
		}
		return time.Time{}, fmt.Errorf("cannot parse %q as duration, RFC3339, or epoch seconds", v)
	default:
		return time.Time{}, fmt.Errorf("unsupported time value type %T", value)
	}
}
