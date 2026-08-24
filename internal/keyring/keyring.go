package keyring

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
)

const rsaBits = 2048

var ErrNoActiveKey = errors.New("keyring: no active signing key")

type Key struct {
	Private   *rsa.PrivateKey
	PrivJWK   jwk.Key
	PubJWK    jwk.Key
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
	active  *Key
	retired []*Key
	grace   time.Duration
	bits    int
}

func New(grace time.Duration) (*KeyRing, error) {
	r := &KeyRing{grace: grace, bits: rsaBits}
	k, err := r.generateKey()
	if err != nil {
		return nil, err
	}
	r.active = k
	return r, nil
}

func (r *KeyRing) generateKey() (*Key, error) {
	priv, err := rsa.GenerateKey(rand.Reader, r.bits)
	if err != nil {
		return nil, fmt.Errorf("generate rsa key: %w", err)
	}
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
		if err := k.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
			return nil, err
		}
	}
	return &Key{Private: priv, PrivJWK: privJWK, PubJWK: pubJWK, CreatedAt: time.Now()}, nil
}

func (r *KeyRing) Signer() (*Key, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.active == nil {
		return nil, ErrNoActiveKey
	}
	return r.active, nil
}

func (r *KeyRing) ActiveKid() (string, error) {
	k, err := r.Signer()
	if err != nil {
		return "", err
	}
	return k.Kid(), nil
}

func (r *KeyRing) JWKS() (jwk.Set, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	set := jwk.NewSet()
	if r.active != nil {
		if err := set.AddKey(r.active.PubJWK); err != nil {
			return nil, err
		}
	}
	for _, k := range r.retired {
		if err := set.AddKey(k.PubJWK); err != nil {
			return nil, err
		}
	}
	return set, nil
}

func (r *KeyRing) Rotate() error {
	return r.RotateAt(time.Now())
}

func (r *KeyRing) RotateAt(now time.Time) error {
	k, err := r.generateKey()
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active != nil {
		r.active.RetiredAt = now
		r.retired = append(r.retired, r.active)
	}
	r.active = k
	return nil
}

func (r *KeyRing) Prune() {
	r.PruneAt(time.Now())
}

func (r *KeyRing) PruneAt(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	kept := r.retired[:0]
	for _, k := range r.retired {
		if now.Sub(k.RetiredAt) < r.grace {
			kept = append(kept, k)
			continue
		}
		zeroizePrivate(k.Private)
	}
	for i := len(kept); i < len(r.retired); i++ {
		r.retired[i] = nil
	}
	r.retired = kept
}

func (r *KeyRing) StartRotation(ctx context.Context, interval time.Duration, logger *slog.Logger) {
	if interval <= 0 {
		logger.Info("key rotation disabled")
		return
	}
	go func() {
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
				kid, err := r.ActiveKid()
				if err != nil {
					logger.Error("post-rotation state invalid", "error", err)
					continue
				}
				logger.Info("signing key rotated", "active_kid", kid)
			}
		}
	}()
}

func zeroizePrivate(priv *rsa.PrivateKey) {
	priv.D.SetInt64(0)
	priv.Precomputed.Dp.SetInt64(0)
	priv.Precomputed.Dq.SetInt64(0)
	priv.Precomputed.Qinv.SetInt64(0)
	for _, p := range priv.Primes {
		p.SetInt64(0)
	}
}
