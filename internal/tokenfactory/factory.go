package tokenfactory

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"

	"jwtoken-tester/internal/keyring"
)

var (
	ErrUnsupportedAlg = errors.New("unsupported algorithm")
	ErrTTLTooLong     = errors.New("requested lifetime exceeds maximum allowed")
	ErrInvalidRequest = errors.New("invalid token request")
)

type Request struct {
	Claims  map[string]any `json:"claims"`
	Alg     string         `json:"alg,omitempty"`
	Headers map[string]any `json:"headers,omitempty"`
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
}

func NewFactory(ring keyring.Ring, issuer string, defaultTTL, maxTTL time.Duration) *Factory {
	return &Factory{ring: ring, issuer: issuer, defaultTTL: defaultTTL, maxTTL: maxTTL}
}

func (f *Factory) Mint(req *Request) (*Response, error) {
	if req == nil {
		req = &Request{}
	}
	alg := jwa.RS256()
	if req.Alg != "" && req.Alg != alg.String() {
		return nil, fmt.Errorf("%w: %q (supported: %s)", ErrUnsupportedAlg, req.Alg, alg)
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

	signer, err := f.ring.Signer()
	if err != nil {
		return nil, err
	}

	signOpt := jwt.WithKey(alg, signer.PrivJWK)
	if len(req.Headers) > 0 {
		hdrs := jws.NewHeaders()
		for name, value := range req.Headers {
			if err := hdrs.Set(name, value); err != nil {
				return nil, fmt.Errorf("%w: header %q: %v", ErrInvalidRequest, name, err)
			}
		}
		signOpt = jwt.WithKey(alg, signer.PrivJWK, jws.WithProtectedHeaders(hdrs))
	}

	signed, err := jwt.Sign(tok, signOpt)
	if err != nil {
		return nil, fmt.Errorf("sign token: %w", err)
	}

	return &Response{
		AccessToken: string(signed),
		TokenType:   "Bearer",
		ExpiresIn:   int64(math.Round(lifetime.Seconds())),
	}, nil
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
