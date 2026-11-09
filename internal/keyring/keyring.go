package keyring

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
)

const (
	defaultRSABits = 2048
	minRSABits     = 1024
)

// Option configures a KeyRing at construction time.
type Option func(*config) error

type config struct {
	rsaBits int
}

// WithRSABits sets the RSA modulus size used for RSA and RSA-PSS algorithms.
// Values below the minimum are rejected by New. Values are integers by
// construction; configuration layers are responsible for rejecting
// non-integer text before calling this option.
func WithRSABits(bits int) Option {
	return func(c *config) error {
		c.rsaBits = bits
		return nil
	}
}

var (
	ErrNoActiveKey    = errors.New("keyring: no active signing key")
	ErrUnsupportedAlg = errors.New("keyring: unsupported algorithm")
	ErrKeyNotFound    = errors.New("keyring: key not found")
)

// jwx refuses to import RSA keys below 2048 bits by default. This tool
// deliberately supports RSA_BITS values down to minRSABits for
// consumer-compatibility tests, so align the JWK validation floor with the
// keyring minimum.
func init() {
	if err := jwk.Settings(jwk.WithMinRSAModulusBits(minRSABits)); err != nil {
		panic(fmt.Sprintf("keyring: configure jwk minimum RSA modulus: %v", err))
	}
}

type Algorithm string

const (
	AlgRS256 Algorithm = "RS256"
	AlgRS384 Algorithm = "RS384"
	AlgRS512 Algorithm = "RS512"
	AlgPS256 Algorithm = "PS256"
	AlgPS384 Algorithm = "PS384"
	AlgPS512 Algorithm = "PS512"
	AlgES256 Algorithm = "ES256"
	AlgES384 Algorithm = "ES384"
	AlgES512 Algorithm = "ES512"
	AlgEdDSA Algorithm = "EdDSA"
)

// KeyStatus reports whether a key found by Lookup is still signing or has been
// retired and is being kept published for its grace window.
type KeyStatus string

const (
	KeyStatusActive  KeyStatus = "active"
	KeyStatusRetired KeyStatus = "retired"
)

var (
	allAlgorithms = []Algorithm{
		AlgRS256, AlgRS384, AlgRS512,
		AlgPS256, AlgPS384, AlgPS512,
		AlgES256, AlgES384, AlgES512,
		AlgEdDSA,
	}
	jwaAlgorithms = map[Algorithm]jwa.KeyAlgorithm{
		AlgRS256: jwa.RS256(),
		AlgRS384: jwa.RS384(),
		AlgRS512: jwa.RS512(),
		AlgPS256: jwa.PS256(),
		AlgPS384: jwa.PS384(),
		AlgPS512: jwa.PS512(),
		AlgES256: jwa.ES256(),
		AlgES384: jwa.ES384(),
		AlgES512: jwa.ES512(),
		AlgEdDSA: jwa.EdDSA(),
	}
)

func JWAAlgorithms() map[Algorithm]jwa.KeyAlgorithm {
	return jwaAlgorithms
}

type Key struct {
	Private   crypto.PrivateKey
	Public    crypto.PublicKey
	PrivJWK   jwk.Key
	PubJWK    jwk.Key
	Algorithm Algorithm
	CreatedAt time.Time
	RetiredAt time.Time
}

func (k *Key) Kid() string {
	s, ok := k.PubJWK.KeyID()
	if !ok {
		return ""
	}
	return s
}

type KeyRing struct {
	mu      sync.RWMutex
	active  map[Algorithm]*Key
	retired map[Algorithm][]*Key
	grace   time.Duration
	enabled map[Algorithm]bool
	rsaBits int
}

type Ring interface {
	Signer(alg Algorithm) (*Key, error)
	SignerByKID(kid string, alg Algorithm) (*Key, error)
	ActiveKid(alg Algorithm) (string, error)
	Lookup(kid string) (crypto.PublicKey, KeyStatus, error)
	JWKS() (jwk.Set, error)
	JWKByKID(kid string) (jwk.Key, error)
	Rotate() error
	RotateAt(now time.Time) error
	Prune()
	PruneAt(now time.Time)
	StartRotation(ctx context.Context, interval time.Duration, logger *slog.Logger) <-chan struct{}
	EnabledAlgorithms() []Algorithm
}

func New(grace time.Duration, enabledAlgs []Algorithm, opts ...Option) (*KeyRing, error) {
	cfg := config{rsaBits: defaultRSABits}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(&cfg); err != nil {
			return nil, err
		}
	}
	if cfg.rsaBits < minRSABits {
		return nil, fmt.Errorf("keyring: RSA bits %d is below minimum %d", cfg.rsaBits, minRSABits)
	}

	enabled := make(map[Algorithm]bool)
	for _, alg := range allAlgorithms {
		enabled[alg] = false
	}
	for _, alg := range enabledAlgs {
		if _, ok := jwaAlgorithms[alg]; !ok {
			return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlg, alg)
		}
		enabled[alg] = true
	}

	if len(enabledAlgs) == 0 {
		return nil, errors.New("keyring: at least one algorithm must be enabled")
	}

	r := &KeyRing{
		grace:   grace,
		active:  make(map[Algorithm]*Key),
		retired: make(map[Algorithm][]*Key),
		enabled: enabled,
		rsaBits: cfg.rsaBits,
	}

	for _, alg := range allAlgorithms {
		if enabled[alg] {
			k, err := r.generateKey(alg)
			if err != nil {
				return nil, err
			}
			r.active[alg] = k
		}
	}
	return r, nil
}

func (r *KeyRing) generateKey(alg Algorithm) (*Key, error) {
	jwaAlg, ok := jwaAlgorithms[alg]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlg, alg)
	}

	var priv crypto.PrivateKey
	var err error
	switch alg {
	case AlgRS256, AlgRS384, AlgRS512, AlgPS256, AlgPS384, AlgPS512:
		priv, err = rsa.GenerateKey(rand.Reader, r.rsaBits)
	case AlgES256:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case AlgES384:
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case AlgES512:
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case AlgEdDSA:
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlg, alg)
	}
	if err != nil {
		return nil, fmt.Errorf("generate %s key: %w", alg, err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("generate %s key: %T does not implement crypto.Signer", alg, priv)
	}
	pub := signer.Public()

	privJWK, err := jwk.Import[jwk.Key](priv)
	if err != nil {
		return nil, fmt.Errorf("build private jwk: %w", err)
	}
	pubJWK, err := privJWK.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("derive public jwk: %w", err)
	}
	thumbprint, err := pubJWK.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("compute rfc7638 thumbprint: %w", err)
	}
	kid := base64.RawURLEncoding.EncodeToString(thumbprint)
	for _, k := range []jwk.Key{privJWK, pubJWK} {
		if err := k.Set(jwk.KeyIDKey, kid); err != nil {
			return nil, err
		}
		if err := k.Set(jwk.KeyUsageKey, jwk.ForSignature); err != nil {
			return nil, err
		}
		if err := k.Set(jwk.AlgorithmKey, jwaAlg); err != nil {
			return nil, err
		}
	}
	return &Key{Private: priv, Public: pub, PrivJWK: privJWK, PubJWK: pubJWK, Algorithm: alg, CreatedAt: time.Now()}, nil
}

func (r *KeyRing) Signer(alg Algorithm) (*Key, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.enabled[alg] {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlg, alg)
	}
	k, ok := r.active[alg]
	if !ok || k == nil {
		return nil, ErrNoActiveKey
	}
	return k, nil
}

// SignerByKID returns the active or retired key with the given kid, provided
// it belongs to the requested algorithm. Unknown kids return ErrKeyNotFound.
// A key whose algorithm differs returns ErrUnsupportedAlg so callers can treat
// the selection as a malformed request rather than an unknown negative control.
func (r *KeyRing) SignerByKID(kid string, alg Algorithm) (*Key, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	found := func(k *Key) (*Key, error) {
		if k == nil || k.Kid() != kid {
			return nil, nil
		}
		if k.Algorithm != alg {
			return nil, fmt.Errorf("%w: kid %q uses %s, requested %s", ErrUnsupportedAlg, kid, k.Algorithm, alg)
		}
		return k, nil
	}

	for _, k := range r.active {
		if got, err := found(k); err != nil || got != nil {
			return got, err
		}
	}
	for _, keys := range r.retired {
		for _, k := range keys {
			if got, err := found(k); err != nil || got != nil {
				return got, err
			}
		}
	}
	return nil, fmt.Errorf("%w: kid %q", ErrKeyNotFound, kid)
}

func (r *KeyRing) ActiveKid(alg Algorithm) (string, error) {
	k, err := r.Signer(alg)
	if err != nil {
		return "", err
	}
	return k.Kid(), nil
}

func (r *KeyRing) Rotate() error {
	return r.RotateAt(time.Now())
}

func (r *KeyRing) RotateAt(now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, alg := range allAlgorithms {
		if !r.enabled[alg] {
			continue
		}
		k, err := r.generateKey(alg)
		if err != nil {
			return err
		}
		if old := r.active[alg]; old != nil {
			old.RetiredAt = now
			r.retired[alg] = append(r.retired[alg], old)
		}
		r.active[alg] = k
	}
	return nil
}

func (r *KeyRing) Prune() {
	r.PruneAt(time.Now())
}

func (r *KeyRing) PruneAt(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for alg, keys := range r.retired {
		kept := keys[:0]
		for _, k := range keys {
			if now.Sub(k.RetiredAt) < r.grace {
				kept = append(kept, k)
				continue
			}
			zeroizePrivate(k.Private)
		}
		for i := len(kept); i < len(keys); i++ {
			keys[i] = nil
		}
		r.retired[alg] = kept
	}
}

func (r *KeyRing) StartRotation(ctx context.Context, interval time.Duration, logger *slog.Logger) <-chan struct{} {
	done := make(chan struct{})
	if interval <= 0 {
		logger.Info("key rotation disabled")
		close(done)
		return done
	}
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				if err := r.RotateAt(now); err != nil {
					logger.Error("key rotation failed", "error", err)
					continue
				}
				r.PruneAt(now)
				var kids []string
				for _, alg := range allAlgorithms {
					if kid, err := r.ActiveKid(alg); err == nil {
						kids = append(kids, fmt.Sprintf("%s=%s", alg, kid))
					}
				}
				logger.Info("signing keys rotated", "active_kids", kids)
			}
		}
	}()
	return done
}

func (r *KeyRing) JWKByKID(kid string) (jwk.Key, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	set, err := r.jwksUnlocked()
	if err != nil {
		return nil, err
	}
	key, ok := set.LookupKeyID(kid)
	if !ok {
		return nil, fmt.Errorf("%w: kid %q", ErrKeyNotFound, kid)
	}
	return key, nil
}

// Snapshot returns a copy of the active and retired keys ordered by kid.
func (r *KeyRing) Snapshot() []*Key {
	r.mu.RLock()
	defer r.mu.RUnlock()
	keys := r.sortedKeysUnlocked()
	out := make([]*Key, len(keys))
	copy(out, keys)
	return out
}

// Lookup returns the cached public key and status for a kid. It takes the read
// lock once and searches the same active/retired snapshot that JWKS and
// Snapshot use, so a concurrent rotation cannot produce a torn answer.
func (r *KeyRing) Lookup(kid string) (crypto.PublicKey, KeyStatus, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, k := range r.active {
		if k != nil && k.Kid() == kid {
			return k.Public, KeyStatusActive, nil
		}
	}
	for _, retired := range r.retired {
		for _, k := range retired {
			if k != nil && k.Kid() == kid {
				return k.Public, KeyStatusRetired, nil
			}
		}
	}
	return nil, "", fmt.Errorf("%w: kid %q", ErrKeyNotFound, kid)
}

// PublicKeyByKID returns the cached public key for an active or retired kid.
func (r *KeyRing) PublicKeyByKID(kid string) (crypto.PublicKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, k := range r.sortedKeysUnlocked() {
		if k.Kid() == kid {
			return k.Public, nil
		}
	}
	return nil, fmt.Errorf("%w: kid %q", ErrKeyNotFound, kid)
}

func (r *KeyRing) jwksUnlocked() (jwk.Set, error) {
	set := jwk.NewSet()
	for _, k := range r.sortedKeysUnlocked() {
		if err := set.AddKey(k.PubJWK); err != nil {
			return nil, err
		}
	}
	return set, nil
}

// sortedKeysUnlocked returns active and retired keys ordered by kid. Callers
// must hold r.mu.
func (r *KeyRing) sortedKeysUnlocked() []*Key {
	keys := make([]*Key, 0, len(r.active))
	for _, k := range r.active {
		if k != nil {
			keys = append(keys, k)
		}
	}
	for _, retired := range r.retired {
		keys = append(keys, retired...)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].Kid() < keys[j].Kid()
	})
	return keys
}

func (r *KeyRing) JWKS() (jwk.Set, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.jwksUnlocked()
}

func (r *KeyRing) EnabledAlgorithms() []Algorithm {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var algs []Algorithm
	for _, alg := range allAlgorithms {
		if r.enabled[alg] {
			algs = append(algs, alg)
		}
	}
	return algs
}

func zeroizePrivate(priv crypto.PrivateKey) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		k.D.SetInt64(0)
		k.Precomputed.Dp.SetInt64(0)
		k.Precomputed.Dq.SetInt64(0)
		k.Precomputed.Qinv.SetInt64(0)
		for _, p := range k.Primes {
			p.SetInt64(0)
		}
	case *ecdsa.PrivateKey:
		// D.SetInt64(0) deprecated in Go 1.26+; not safe for cryptographic values.
		// ECDSA private keys are discarded on process exit; GC clears memory.
	case ed25519.PrivateKey:
		for i := range k {
			k[i] = 0
		}
	}
}
