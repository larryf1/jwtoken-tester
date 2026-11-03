// Package verify implements the policy-free token verification classifier
// shared by the HTTP endpoint and the CLI. Callers supply the key source and
// every consumer expectation; the classifier owns the closed failure taxonomy
// and its deterministic precedence.
package verify

import (
	"crypto"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	jwt5 "github.com/golang-jwt/jwt/v5"

	"github.com/larryf1/jwtoken-tester/v2/internal/keyring"
)

// Reason is the closed set of verification failure reasons. Any failure that
// cannot be mapped to one of these is an operational error, not a verdict.
type Reason string

const (
	ReasonMalformed   Reason = "malformed"
	ReasonAlg         Reason = "alg"
	ReasonKid         Reason = "kid"
	ReasonSignature   Reason = "signature"
	ReasonExpired     Reason = "expired"
	ReasonNotYetValid Reason = "not_yet_valid"
	ReasonIssuer      Reason = "issuer"
	ReasonAudience    Reason = "audience"
)

// Reasons returns the closed reason set in precedence order.
func Reasons() []Reason {
	return []Reason{
		ReasonMalformed,
		ReasonAlg,
		ReasonKid,
		ReasonSignature,
		ReasonExpired,
		ReasonNotYetValid,
		ReasonIssuer,
		ReasonAudience,
	}
}

// KeyStatusUnknown reports a kid that is not present in the key source. The
// keyring itself never returns it; active and retired come from keyring.
const KeyStatusUnknown keyring.KeyStatus = "unknown"

// Input is everything the classifier needs. Policy is supplied entirely by the
// caller: an empty ExpectedIssuer or Audience disables that check, and an empty
// AllowedAlgs accepts every algorithm the key source advertises.
type Input struct {
	Token          string
	Keys           KeySource
	ExpectedIssuer string
	AllowedAlgs    []string
	Audience       []string
	Leeway         time.Duration
	Now            time.Time
}

// KeySource resolves a kid to a public key and its publication status.
type KeySource interface {
	Lookup(kid string) (crypto.PublicKey, keyring.KeyStatus, error)
	Algorithms() []string
}

// Verdict is the response envelope shared by POST /verify and the CLI --json
// output. Claims appear under Claims only after signature verification and
// under UnverifiedClaims before it; malformed input carries neither.
type Verdict struct {
	Valid            bool              `json:"valid"`
	Reason           Reason            `json:"reason,omitempty"`
	Error            string            `json:"error,omitempty"`
	Header           map[string]any    `json:"header,omitempty"`
	Claims           map[string]any    `json:"claims,omitempty"`
	UnverifiedClaims map[string]any    `json:"unverified_claims,omitempty"`
	Kid              string            `json:"kid,omitempty"`
	KidStatus        keyring.KeyStatus `json:"kid_status,omitempty"`
	Alg              string            `json:"alg,omitempty"`
}

// RingKeySource adapts a keyring to the classifier.
type RingKeySource struct {
	Ring keyring.Ring
}

// Lookup implements KeySource.
func (s RingKeySource) Lookup(kid string) (crypto.PublicKey, keyring.KeyStatus, error) {
	if s.Ring == nil {
		return nil, "", errors.New("verify: nil keyring")
	}
	return s.Ring.Lookup(kid)
}

// Algorithms implements KeySource.
func (s RingKeySource) Algorithms() []string {
	if s.Ring == nil {
		return nil
	}
	enabled := s.Ring.EnabledAlgorithms()
	out := make([]string, len(enabled))
	for i, alg := range enabled {
		out[i] = string(alg)
	}
	return out
}

// Verify classifies a token. A non-nil error means the failure could not be
// mapped to the closed reason set and must be surfaced as an operational
// failure (HTTP 500 or CLI exit 2) rather than a verdict.
func Verify(in Input) (Verdict, error) {
	now := in.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	leeway := in.Leeway
	if leeway < 0 {
		leeway = 0
	}

	// Pass 1: structural diagnostics. This is the only place malformed input is
	// classified; signature failures are classified by pass 2.
	claims := jwt5.MapClaims{}
	tok, _, err := jwt5.NewParser().ParseUnverified(strings.TrimSpace(in.Token), claims)
	if err != nil {
		// A missing or unknown "alg" makes the library call the token
		// unverifiable during the diagnostic pass. That is an algorithm
		// failure, not a structural one, so classify it as such while still
		// exposing whatever header and claims were readable.
		if errors.Is(err, jwt5.ErrTokenUnverifiable) && tok != nil {
			header := map[string]any{}
			for name, value := range tok.Header {
				header[name] = value
			}
			alg, _ := stringHeader(header, "alg")
			kid, _ := stringHeader(header, "kid")
			message := "token header has no usable alg"
			if alg != "" {
				message = fmt.Sprintf("algorithm %q is not accepted", alg)
			}
			return invalid(ReasonAlg, message, baseVerdict(header, claims, alg, kid)), nil
		}
		return invalid(ReasonMalformed, err.Error(), Verdict{}), nil
	}
	header := map[string]any{}
	for name, value := range tok.Header {
		header[name] = value
	}
	if err := validateClaimShapes(claims); err != nil {
		return invalid(ReasonMalformed, err.Error(), Verdict{}), nil
	}

	// Explicit algorithm check before any key work.
	alg, ok := stringHeader(header, "alg")
	if !ok || alg == "" {
		return invalid(ReasonAlg, "token header has no usable alg", baseVerdict(header, claims, "", "")), nil
	}
	allowed := in.AllowedAlgs
	if len(allowed) == 0 {
		if in.Keys == nil {
			return Verdict{}, errors.New("verify: no key source")
		}
		allowed = in.Keys.Algorithms()
	}
	if !slices.Contains(allowed, alg) {
		return invalid(ReasonAlg, fmt.Sprintf("algorithm %q is not accepted", alg), baseVerdict(header, claims, alg, "")), nil
	}

	// Explicit key check before the cryptographic pass.
	kid, kidPresent := stringHeader(header, "kid")
	if !kidPresent || kid == "" {
		return invalid(ReasonKid, "token header has no kid", baseVerdict(header, claims, alg, "")), nil
	}
	if in.Keys == nil {
		return Verdict{}, errors.New("verify: no key source")
	}
	key, status, lookupErr := in.Keys.Lookup(kid)
	base := baseVerdict(header, claims, alg, kid)
	if lookupErr != nil {
		if errors.Is(lookupErr, keyring.ErrKeyNotFound) {
			base.KidStatus = KeyStatusUnknown
			return invalid(ReasonKid, fmt.Sprintf("no key found for kid %q", kid), base), nil
		}
		return Verdict{}, fmt.Errorf("verify: lookup kid %q: %w", kid, lookupErr)
	}
	base.KidStatus = status

	// Pass 2: signature only. Time, issuer, and audience checks run afterwards
	// in the order the contract requires.
	verified := jwt5.MapClaims{}
	_, err = jwt5.NewParser(
		jwt5.WithValidMethods([]string{alg}),
		jwt5.WithoutClaimsValidation(),
	).ParseWithClaims(strings.TrimSpace(in.Token), verified, func(*jwt5.Token) (any, error) {
		return key, nil
	})
	if err != nil {
		if reason, ok := signatureReason(err); ok {
			return invalid(reason, "token signature does not verify", base), nil
		}
		return Verdict{}, fmt.Errorf("verify: signature pass: %w", err)
	}

	// The signature is valid from here on, so the claim set is authenticated.
	base = authenticatedVerdict(header, claims, alg, kid, status)

	validator := jwt5.NewValidator(
		jwt5.WithLeeway(leeway),
		jwt5.WithTimeFunc(func() time.Time { return now }),
		jwt5.WithIssuedAt(),
	)
	if err := validator.Validate(claims); err != nil {
		switch {
		case errors.Is(err, jwt5.ErrTokenExpired):
			return invalid(ReasonExpired, "token is expired", base), nil
		case errors.Is(err, jwt5.ErrTokenNotValidYet):
			return invalid(ReasonNotYetValid, "token is not valid yet", base), nil
		case errors.Is(err, jwt5.ErrTokenUsedBeforeIssued):
			return invalid(ReasonNotYetValid, "token was used before it was issued", base), nil
		default:
			return Verdict{}, fmt.Errorf("verify: time claims: %w", err)
		}
	}

	if in.ExpectedIssuer != "" {
		issuer, _ := claims.GetIssuer()
		if issuer != in.ExpectedIssuer {
			message := "token has no issuer"
			if issuer != "" {
				message = fmt.Sprintf("token issuer %q does not match %q", issuer, in.ExpectedIssuer)
			}
			return invalid(ReasonIssuer, message, base), nil
		}
	}

	if len(in.Audience) > 0 {
		aud, err := claims.GetAudience()
		if err != nil {
			return Verdict{}, fmt.Errorf("verify: audience claim: %w", err)
		}
		if !anyAudienceMatches(in.Audience, aud) {
			return invalid(ReasonAudience, "token audience does not match", base), nil
		}
	}

	base.Valid = true
	return base, nil
}

func validateClaimShapes(claims jwt5.MapClaims) error {
	if _, err := claims.GetExpirationTime(); err != nil {
		return err
	}
	if _, err := claims.GetNotBefore(); err != nil {
		return err
	}
	if _, err := claims.GetIssuedAt(); err != nil {
		return err
	}
	if _, err := claims.GetAudience(); err != nil {
		return err
	}
	if _, err := claims.GetIssuer(); err != nil {
		return err
	}
	if _, err := claims.GetSubject(); err != nil {
		return err
	}
	return nil
}

func stringHeader(header map[string]any, name string) (string, bool) {
	value, ok := header[name].(string)
	return value, ok
}

func baseVerdict(header map[string]any, claims jwt5.MapClaims, alg, kid string) Verdict {
	return Verdict{
		Header:           header,
		UnverifiedClaims: map[string]any(claims),
		Alg:              alg,
		Kid:              kid,
	}
}

func authenticatedVerdict(header map[string]any, claims jwt5.MapClaims, alg, kid string, status keyring.KeyStatus) Verdict {
	return Verdict{
		Header:    header,
		Claims:    map[string]any(claims),
		Alg:       alg,
		Kid:       kid,
		KidStatus: status,
	}
}

func invalid(reason Reason, message string, verdict Verdict) Verdict {
	verdict.Valid = false
	verdict.Reason = reason
	verdict.Error = message
	return verdict
}

func signatureReason(err error) (Reason, bool) {
	switch {
	case errors.Is(err, jwt5.ErrTokenSignatureInvalid),
		errors.Is(err, jwt5.ErrInvalidKey),
		errors.Is(err, jwt5.ErrInvalidKeyType),
		errors.Is(err, jwt5.ErrTokenUnverifiable):
		return ReasonSignature, true
	default:
		return "", false
	}
}

func anyAudienceMatches(expected []string, actual []string) bool {
	for _, want := range expected {
		if slices.Contains(actual, want) {
			return true
		}
	}
	return false
}
