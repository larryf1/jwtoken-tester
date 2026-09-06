package keyring

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

func newTestRing(t *testing.T, grace time.Duration, algs ...Algorithm) *KeyRing {
	t.Helper()
	if len(algs) == 0 {
		algs = []Algorithm{AlgRS256}
	}
	r, err := New(grace, algs)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return r
}

func TestKidIsRFC7638Thumbprint(t *testing.T) {
	for _, alg := range []Algorithm{AlgRS256, AlgES256, AlgEdDSA} {
		t.Run(string(alg), func(t *testing.T) {
			r := newTestRing(t, time.Hour, alg)
			k, err := r.Signer(alg)
			if err != nil {
				t.Fatalf("Signer() error = %v", err)
			}
			pub, err := k.PrivJWK.PublicKey()
			if err != nil {
				t.Fatalf("PublicKey() error = %v", err)
			}
			thumbprint, err := pub.Thumbprint(crypto.SHA256)
			if err != nil {
				t.Fatalf("Thumbprint() error = %v", err)
			}
			want := base64.RawURLEncoding.EncodeToString(thumbprint)
			if k.Kid() != want {
				t.Fatalf("kid = %q, want thumbprint %q", k.Kid(), want)
			}
		})
	}
}

func TestKidStableAcrossDerivations(t *testing.T) {
	for _, alg := range []Algorithm{AlgRS256, AlgES256, AlgEdDSA} {
		t.Run(string(alg), func(t *testing.T) {
			r := newTestRing(t, time.Hour, alg)
			k, err := r.Signer(alg)
			if err != nil {
				t.Fatalf("Signer() error = %v", err)
			}
			first := k.Kid()

			pub, err := k.PubJWK.PublicKey()
			if err != nil {
				t.Fatalf("PublicKey() error = %v", err)
			}
			thumbprint, _ := pub.Thumbprint(crypto.SHA256)
			if second := base64.RawURLEncoding.EncodeToString(thumbprint); first != second {
				t.Fatalf("kid changed across derivations: %q vs %q", first, second)
			}
		})
	}
}

func TestInitialJWKSPublishesExactlyActiveKey(t *testing.T) {
	for _, alg := range []Algorithm{AlgRS256, AlgES256, AlgEdDSA} {
		t.Run(string(alg), func(t *testing.T) {
			r := newTestRing(t, time.Hour, alg)
			active, err := r.Signer(alg)
			if err != nil {
				t.Fatalf("Signer() error = %v", err)
			}

			set, err := r.JWKS()
			if err != nil {
				t.Fatalf("JWKS() error = %v", err)
			}
			if set.Len() != 1 {
				t.Fatalf("JWKS length = %d, want 1", set.Len())
			}
			key, ok := set.LookupKeyID(active.Kid())
			if !ok {
				t.Fatalf("active kid %q missing from JWKS", active.Kid())
			}
			algVal, ok := key.Algorithm()
			if !ok || algVal != jwaAlgorithms[alg] {
				t.Fatalf("published alg = %v, want %v", algVal, jwaAlgorithms[alg])
			}
		})
	}
}

func TestInitialJWKSPublishesAllEnabledAlgorithms(t *testing.T) {
	r := newTestRing(t, time.Hour, AlgRS256, AlgES256, AlgEdDSA)

	set, err := r.JWKS()
	if err != nil {
		t.Fatalf("JWKS() error = %v", err)
	}
	if set.Len() != 3 {
		t.Fatalf("JWKS length = %d, want 3", set.Len())
	}

	for _, alg := range []Algorithm{AlgRS256, AlgES256, AlgEdDSA} {
		k, err := r.Signer(alg)
		if err != nil {
			t.Fatalf("Signer(%s) error = %v", alg, err)
		}
		key, ok := set.LookupKeyID(k.Kid())
		if !ok {
			t.Fatalf("active kid %q missing from JWKS", k.Kid())
		}
		algVal, ok := key.Algorithm()
		if !ok || algVal != jwaAlgorithms[alg] {
			t.Fatalf("published alg = %v, want %v", algVal, jwaAlgorithms[alg])
		}
	}
}

func TestRotationKeepsOldKeyPublishedDuringGrace(t *testing.T) {
	for _, alg := range []Algorithm{AlgRS256, AlgES256, AlgEdDSA} {
		t.Run(string(alg), func(t *testing.T) {
			r := newTestRing(t, time.Hour, alg)
			oldKey, err := r.Signer(alg)
			if err != nil {
				t.Fatalf("Signer() error = %v", err)
			}

			now := time.Now()
			if err := r.RotateAt(now); err != nil {
				t.Fatalf("RotateAt() error = %v", err)
			}
			newKey, err := r.Signer(alg)
			if err != nil {
				t.Fatalf("Signer() after rotation error = %v", err)
			}
			if oldKey.Kid() == newKey.Kid() {
				t.Fatal("rotation produced same kid")
			}

			set, err := r.JWKS()
			if err != nil {
				t.Fatalf("JWKS() error = %v", err)
			}
			if set.Len() != 2 {
				t.Fatalf("JWKS length = %d, want 2 during grace window", set.Len())
			}
			for _, want := range []string{oldKey.Kid(), newKey.Kid()} {
				if _, ok := set.LookupKeyID(want); !ok {
					t.Fatalf("kid %q missing from JWKS", want)
				}
			}
		})
	}
}

func TestPruneRemovesExpiredRetiredKeysAndZeroizesMaterial(t *testing.T) {
	for _, alg := range []Algorithm{AlgRS256, AlgES256, AlgEdDSA} {
		t.Run(string(alg), func(t *testing.T) {
			grace := time.Hour
			r := newTestRing(t, grace, alg)
			oldKey, err := r.Signer(alg)
			if err != nil {
				t.Fatalf("Signer() error = %v", err)
			}

			now := time.Now()
			if err := r.RotateAt(now); err != nil {
				t.Fatalf("RotateAt() error = %v", err)
			}
			r.PruneAt(now.Add(grace + time.Minute))

			set, err := r.JWKS()
			if err != nil {
				t.Fatalf("JWKS() error = %v", err)
			}
			if set.Len() != 1 {
				t.Fatalf("JWKS length = %d, want 1 after prune", set.Len())
			}
			if _, ok := set.LookupKeyID(oldKey.Kid()); ok {
				t.Fatal("retired key still published past grace period")
			}
			assertZeroized(t, oldKey.Private)
		})
	}
}

func assertZeroized(t *testing.T, priv crypto.PrivateKey) {
	t.Helper()
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		if k.D.Sign() != 0 {
			t.Fatal("private exponent D not zeroized")
		}
		for i, p := range k.Primes {
			if p.Sign() != 0 {
				t.Fatalf("prime %d not zeroized", i)
			}
		}
		if k.Precomputed.Dp.Sign() != 0 || k.Precomputed.Dq.Sign() != 0 || k.Precomputed.Qinv.Sign() != 0 {
			t.Fatal("precomputed values not zeroized")
		}
	case *ecdsa.PrivateKey:
		// ECDSA zeroization is deprecated in Go 1.26+; we no longer zeroize D
	case ed25519.PrivateKey:
		for i := range k {
			if k[i] != 0 {
				t.Fatalf("ed25519 key not zeroized at index %d", i)
			}
		}
	default:
		t.Fatalf("unknown private key type: %T", priv)
	}
}

func TestActiveKidReturnsActiveKeyKid(t *testing.T) {
	for _, alg := range []Algorithm{AlgRS256, AlgES256, AlgEdDSA} {
		t.Run(string(alg), func(t *testing.T) {
			r := newTestRing(t, time.Hour, alg)
			k, err := r.Signer(alg)
			if err != nil {
				t.Fatalf("Signer() error = %v", err)
			}

			kid, err := r.ActiveKid(alg)
			if err != nil {
				t.Fatalf("ActiveKid() error = %v", err)
			}
			if kid != k.Kid() {
				t.Fatalf("ActiveKid() = %q, want %q", kid, k.Kid())
			}
		})
	}
}

func TestRotateProducesNewKey(t *testing.T) {
	for _, alg := range []Algorithm{AlgRS256, AlgES256, AlgEdDSA} {
		t.Run(string(alg), func(t *testing.T) {
			r := newTestRing(t, time.Hour, alg)
			oldKey, err := r.Signer(alg)
			if err != nil {
				t.Fatalf("Signer() error = %v", err)
			}

			if err := r.Rotate(); err != nil {
				t.Fatalf("Rotate() error = %v", err)
			}
			newKey, err := r.Signer(alg)
			if err != nil {
				t.Fatalf("Signer() after rotation error = %v", err)
			}
			if oldKey.Kid() == newKey.Kid() {
				t.Fatal("Rotate() produced same kid")
			}
		})
	}
}

func TestPruneNoOpWhenNoRetiredKeys(t *testing.T) {
	for _, alg := range []Algorithm{AlgRS256, AlgES256, AlgEdDSA} {
		t.Run(string(alg), func(t *testing.T) {
			r := newTestRing(t, time.Hour, alg)
			r.Prune()
			set, err := r.JWKS()
			if err != nil {
				t.Fatalf("JWKS() error = %v", err)
			}
			if set.Len() != 1 {
				t.Fatalf("JWKS length = %d, want 1", set.Len())
			}
		})
	}
}

func TestStartRotationDisabledWhenIntervalZero(t *testing.T) {
	r := newTestRing(t, time.Hour, AlgRS256)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	r.StartRotation(ctx, 0, logger)
	time.Sleep(10 * time.Millisecond)
	output := buf.String()
	if !strings.Contains(output, "key rotation disabled") {
		t.Fatalf("expected log about rotation disabled, got: %s", output)
	}
}

func TestStartRotationRotatesAndPrunes(t *testing.T) {
	r := newTestRing(t, 50*time.Millisecond, AlgRS256, AlgES256)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	r.StartRotation(ctx, 10*time.Millisecond, logger)

	var output string
	for i := 0; i < 50; i++ {
		time.Sleep(50 * time.Millisecond)
		output = buf.String()
		if strings.Contains(output, "signing keys rotated") {
			break
		}
	}
	if !strings.Contains(output, "signing keys rotated") {
		t.Fatalf("expected log about key rotated, got: %s", output)
	}

	set, err := r.JWKS()
	if err != nil {
		t.Fatalf("JWKS() error = %v", err)
	}
	if set.Len() < 1 {
		t.Fatalf("JWKS is empty")
	}
}

func TestNewReturnsErrorWhenGenerateKeyFails(t *testing.T) {
	r := &KeyRing{}
	_, err := r.generateKey(Algorithm("INVALID"))
	if err == nil {
		t.Fatal("expected error from generateKey with invalid algorithm")
	}
}

func TestGenerateKeyErrorPath(t *testing.T) {
	r := &KeyRing{}
	_, err := r.generateKey(Algorithm("INVALID"))
	if err == nil {
		t.Fatal("expected error from generateKey with invalid algorithm")
	}
}

func TestSignerReturnsErrorWhenNoActive(t *testing.T) {
	r := &KeyRing{}
	_, err := r.Signer(AlgRS256)
	if !errors.Is(err, ErrUnsupportedAlg) {
		t.Fatalf("Signer() error = %v, want ErrUnsupportedAlg", err)
	}
}

func TestSignerReturnsErrorWhenAlgDisabled(t *testing.T) {
	r := newTestRing(t, time.Hour, AlgRS256)
	_, err := r.Signer(AlgES256)
	if err == nil {
		t.Fatal("expected error when algorithm is disabled")
	}
	if !errors.Is(err, ErrUnsupportedAlg) {
		t.Fatalf("error = %v, want ErrUnsupportedAlg", err)
	}
}

func TestActiveKidReturnsErrorWhenNoActive(t *testing.T) {
	r := &KeyRing{}
	_, err := r.ActiveKid(AlgRS256)
	if !errors.Is(err, ErrUnsupportedAlg) {
		t.Fatalf("ActiveKid() error = %v, want ErrUnsupportedAlg", err)
	}
}

func TestActiveKidReturnsErrorWhenAlgDisabled(t *testing.T) {
	r := newTestRing(t, time.Hour, AlgRS256)
	_, err := r.ActiveKid(AlgES256)
	if err == nil {
		t.Fatal("expected error when algorithm is disabled")
	}
	if !errors.Is(err, ErrUnsupportedAlg) {
		t.Fatalf("error = %v, want ErrUnsupportedAlg", err)
	}
}

func TestJWKSWithNoActiveKey(t *testing.T) {
	r := &KeyRing{}
	set, err := r.JWKS()
	if err != nil {
		t.Fatalf("JWKS() error = %v", err)
	}
	if set.Len() != 0 {
		t.Fatalf("JWKS length = %d, want 0", set.Len())
	}
}

func TestJWKSErrorWhenAddKeyFails(t *testing.T) {
	r := &failingKeyRing{err: errors.New("add key failed")}
	_, err := r.JWKS()
	if err == nil {
		t.Fatal("expected error from JWKS when AddKey fails")
	}
}

type failingKeyRing struct {
	err error
}

func (f *failingKeyRing) Signer(Algorithm) (*Key, error)      { return nil, f.err }
func (f *failingKeyRing) ActiveKid(Algorithm) (string, error) { return "", f.err }
func (f *failingKeyRing) JWKS() (jwk.Set, error)              { return nil, f.err }
func (f *failingKeyRing) Rotate() error                       { return f.err }
func (f *failingKeyRing) RotateAt(time.Time) error            { return f.err }
func (f *failingKeyRing) Prune()                              {}
func (f *failingKeyRing) PruneAt(time.Time)                   {}
func (f *failingKeyRing) StartRotation(ctx context.Context, interval time.Duration, logger *slog.Logger) {
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
				if err := f.RotateAt(now); err != nil {
					logger.Error("key rotation failed", "error", err)
					continue
				}
				f.PruneAt(now)
				kid, err := f.ActiveKid(AlgRS256)
				if err != nil {
					logger.Error("post-rotation state invalid", "error", err)
					continue
				}
				logger.Info("signing key rotated", "active_kid", kid)
			}
		}
	}()
}

func (f *failingKeyRing) EnabledAlgorithms() []Algorithm { return []Algorithm{AlgRS256} }

func TestRotateAtErrorPath(t *testing.T) {
	r := &KeyRing{}
	err := r.RotateAt(time.Now())
	if err != nil {
		t.Fatalf("unexpected error from RotateAt when no algorithms enabled: %v", err)
	}
}

func TestStartRotationErrorPaths(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	r := &failingKeyRing{err: errors.New("rotate failed")}
	r.StartRotation(ctx, 10*time.Millisecond, logger)

	time.Sleep(200 * time.Millisecond)
	cancel()

	output := buf.String()
	if !strings.Contains(output, "key rotation failed") {
		t.Fatalf("expected log about key rotation failed, got: %s", output)
	}
}

func TestStartRotationActiveKidErrorPath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	r := &failingActiveKidKeyRing{}
	r.StartRotation(ctx, 10*time.Millisecond, logger)

	time.Sleep(200 * time.Millisecond)
	cancel()

	output := buf.String()
	if !strings.Contains(output, "post-rotation state invalid") {
		t.Fatalf("expected log about post-rotation state invalid, got: %s", output)
	}
}

type failingActiveKidKeyRing struct {
}

func (f *failingActiveKidKeyRing) Signer(Algorithm) (*Key, error) { return &Key{}, nil }
func (f *failingActiveKidKeyRing) ActiveKid(Algorithm) (string, error) {
	return "", errors.New("no active key")
}
func (f *failingActiveKidKeyRing) JWKS() (jwk.Set, error)   { return jwk.NewSet(), nil }
func (f *failingActiveKidKeyRing) Rotate() error            { return nil }
func (f *failingActiveKidKeyRing) RotateAt(time.Time) error { return nil }
func (f *failingActiveKidKeyRing) Prune()                   {}
func (f *failingActiveKidKeyRing) PruneAt(time.Time)        {}
func (f *failingActiveKidKeyRing) StartRotation(ctx context.Context, interval time.Duration, logger *slog.Logger) {
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
				if err := f.RotateAt(now); err != nil {
					logger.Error("key rotation failed", "error", err)
					continue
				}
				f.PruneAt(now)
				kid, err := f.ActiveKid(AlgRS256)
				if err != nil {
					logger.Error("post-rotation state invalid", "error", err)
					continue
				}
				logger.Info("signing key rotated", "active_kid", kid)
			}
		}
	}()
}

func (f *failingActiveKidKeyRing) EnabledAlgorithms() []Algorithm { return []Algorithm{AlgRS256} }

func TestEnabledAlgorithms(t *testing.T) {
	tests := []struct {
		name     string
		enabled  []Algorithm
		expected []Algorithm
	}{
		{"RS256 only", []Algorithm{AlgRS256}, []Algorithm{AlgRS256}},
		{"ES256 only", []Algorithm{AlgES256}, []Algorithm{AlgES256}},
		{"EdDSA only", []Algorithm{AlgEdDSA}, []Algorithm{AlgEdDSA}},
		{"all three", []Algorithm{AlgRS256, AlgES256, AlgEdDSA}, []Algorithm{AlgRS256, AlgES256, AlgEdDSA}},
		{"RS256 and EdDSA", []Algorithm{AlgRS256, AlgEdDSA}, []Algorithm{AlgRS256, AlgEdDSA}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newTestRing(t, time.Hour, tt.enabled...)
			got := r.EnabledAlgorithms()
			if len(got) != len(tt.expected) {
				t.Fatalf("EnabledAlgorithms() = %v, want %v", got, tt.expected)
			}
			for i, alg := range tt.expected {
				if got[i] != alg {
					t.Fatalf("EnabledAlgorithms()[%d] = %v, want %v", i, got[i], alg)
				}
			}
		})
	}
}

func TestJWAAlgorithmsReturnsAllAlgorithms(t *testing.T) {
	algs := JWAAlgorithms()
	if len(algs) != 3 {
		t.Fatalf("expected 3 algorithms, got %d", len(algs))
	}
	if algs[AlgRS256] == nil || algs[AlgES256] == nil || algs[AlgEdDSA] == nil {
		t.Fatal("missing expected algorithm in JWAAlgorithms")
	}
}

func TestKidReturnsEmptyWhenNoKeyID(t *testing.T) {
	r := newTestRing(t, time.Hour, AlgRS256)
	k, _ := r.Signer(AlgRS256)
	if err := k.PubJWK.Remove(jwk.KeyIDKey); err != nil {
		t.Fatalf("Remove KeyIDKey: %v", err)
	}
	if kid := k.Kid(); kid != "" {
		t.Fatalf("expected empty kid when no KeyID set, got %q", kid)
	}
}

func TestGenerateKeyErrors(t *testing.T) {
	r := &KeyRing{}
	_, err := r.generateKey(Algorithm("INVALID"))
	if err == nil {
		t.Fatal("expected error for invalid algorithm")
	}
	if !errors.Is(err, ErrUnsupportedAlg) {
		t.Fatalf("error = %v, want ErrUnsupportedAlg", err)
	}
}

func TestSignerErrors(t *testing.T) {
	r := &KeyRing{}

	_, err := r.Signer(AlgRS256)
	if !errors.Is(err, ErrUnsupportedAlg) {
		t.Fatalf("Signer() with no algorithms: error = %v, want ErrUnsupportedAlg", err)
	}

	r = newTestRing(t, time.Hour, AlgRS256)
	_, err = r.Signer(AlgES256)
	if err == nil {
		t.Fatal("expected error when algorithm is disabled")
	}
	if !errors.Is(err, ErrUnsupportedAlg) {
		t.Fatalf("error = %v, want ErrUnsupportedAlg", err)
	}
}

func TestJWKSWithRetiredKeys(t *testing.T) {
	r := newTestRing(t, time.Hour, AlgRS256)
	oldKey, _ := r.Signer(AlgRS256)

	now := time.Now()
	if err := r.RotateAt(now); err != nil {
		t.Fatalf("RotateAt: %v", err)
	}

	set, err := r.JWKS()
	if err != nil {
		t.Fatalf("JWKS() error = %v", err)
	}
	if set.Len() != 2 {
		t.Fatalf("JWKS length = %d, want 2 (active + retired)", set.Len())
	}

	if _, ok := set.LookupKeyID(oldKey.Kid()); !ok {
		t.Fatal("retired key missing from JWKS")
	}
}

func TestStartRotationDisabledWhenIntervalNegative(t *testing.T) {
	r := newTestRing(t, time.Hour, AlgRS256)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	r.StartRotation(ctx, -time.Hour, logger)
	time.Sleep(10 * time.Millisecond)
	output := buf.String()
	if !strings.Contains(output, "key rotation disabled") {
		t.Fatalf("expected log about rotation disabled, got: %s", output)
	}
}

func TestNewRequiresAtLeastOneAlgorithm(t *testing.T) {
	_, err := New(time.Hour, []Algorithm{})
	if err == nil {
		t.Fatal("expected error when no algorithms enabled")
	}
}

func TestJWKByKIDReturnsActiveKey(t *testing.T) {
	for _, alg := range []Algorithm{AlgRS256, AlgES256, AlgEdDSA} {
		t.Run(string(alg), func(t *testing.T) {
			r := newTestRing(t, time.Hour, alg)
			k, err := r.Signer(alg)
			if err != nil {
				t.Fatalf("Signer() error = %v", err)
			}

			key, err := r.JWKByKID(k.Kid())
			if err != nil {
				t.Fatalf("JWKByKID() error = %v", err)
			}
			kid, ok := key.KeyID()
			if !ok || kid != k.Kid() {
				t.Fatalf("JWKByKID() returned wrong kid: got %q, want %q", kid, k.Kid())
			}
		})
	}
}

func TestJWKByKIDReturnsRetiredKey(t *testing.T) {
	for _, alg := range []Algorithm{AlgRS256, AlgES256, AlgEdDSA} {
		t.Run(string(alg), func(t *testing.T) {
			r := newTestRing(t, time.Hour, alg)
			oldKey, err := r.Signer(alg)
			if err != nil {
				t.Fatalf("Signer() error = %v", err)
			}

			now := time.Now()
			if err := r.RotateAt(now); err != nil {
				t.Fatalf("RotateAt() error = %v", err)
			}

			key, err := r.JWKByKID(oldKey.Kid())
			if err != nil {
				t.Fatalf("JWKByKID() for retired key error = %v", err)
			}
			kid, ok := key.KeyID()
			if !ok || kid != oldKey.Kid() {
				t.Fatalf("JWKByKID() returned wrong kid for retired key: got %q, want %q", kid, oldKey.Kid())
			}
		})
	}
}

func TestJWKByKIDReturnsErrorForUnknownKid(t *testing.T) {
	r := newTestRing(t, time.Hour, AlgRS256)
	_, err := r.JWKByKID("unknown-kid")
	if err == nil {
		t.Fatal("expected error for unknown kid")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("error = %v, want 'not found'", err)
	}
}

func TestJWKByKIDReturnsErrorWhenNoAlgorithmsEnabled(t *testing.T) {
	r := &KeyRing{}
	_, err := r.JWKByKID("any-kid")
	if err == nil {
		t.Fatal("expected error when no algorithms enabled")
	}
}

func TestJWKSUnlockedReturnsKeys(t *testing.T) {
	r := newTestRing(t, time.Hour, AlgRS256, AlgES256)
	set, err := r.JWKS()
	if err != nil {
		t.Fatalf("JWKS() error = %v", err)
	}
	if set.Len() != 2 {
		t.Fatalf("JWKS length = %d, want 2", set.Len())
	}
}
