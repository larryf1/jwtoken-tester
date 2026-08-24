package keyring

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
)

func newTestRing(t *testing.T, grace time.Duration) *KeyRing {
	t.Helper()
	r, err := New(grace)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return r
}

func TestKidIsRFC7638Thumbprint(t *testing.T) {
	r := newTestRing(t, time.Hour)
	k, err := r.Signer()
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
}

func TestKidStableAcrossDerivations(t *testing.T) {
	r := newTestRing(t, time.Hour)
	k, _ := r.Signer()
	first := k.Kid()

	pub, err := k.PubJWK.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey() error = %v", err)
	}
	thumbprint, _ := pub.Thumbprint(crypto.SHA256)
	if second := base64.RawURLEncoding.EncodeToString(thumbprint); first != second {
		t.Fatalf("kid changed across derivations: %q vs %q", first, second)
	}
}

func TestInitialJWKSPublishesExactlyActiveKey(t *testing.T) {
	r := newTestRing(t, time.Hour)
	active, _ := r.Signer()

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
	alg, ok := key.Algorithm()
	if !ok || alg != jwa.RS256() {
		t.Fatalf("published alg = %v, want RS256", alg)
	}
}

func TestRotationKeepsOldKeyPublishedDuringGrace(t *testing.T) {
	r := newTestRing(t, time.Hour)
	oldKey, _ := r.Signer()

	now := time.Now()
	if err := r.RotateAt(now); err != nil {
		t.Fatalf("RotateAt() error = %v", err)
	}
	newKey, _ := r.Signer()
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
}

func TestPruneRemovesExpiredRetiredKeysAndZeroizesMaterial(t *testing.T) {
	grace := time.Hour
	r := newTestRing(t, grace)
	oldKey, _ := r.Signer()

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
}

func assertZeroized(t *testing.T, priv *rsa.PrivateKey) {
	t.Helper()
	if priv.D.Sign() != 0 {
		t.Fatal("private exponent D not zeroized")
	}
	for i, p := range priv.Primes {
		if p.Sign() != 0 {
			t.Fatalf("prime %d not zeroized", i)
		}
	}
	if priv.Precomputed.Dp.Sign() != 0 || priv.Precomputed.Dq.Sign() != 0 || priv.Precomputed.Qinv.Sign() != 0 {
		t.Fatal("precomputed values not zeroized")
	}
}

func TestActiveKidReturnsActiveKeyKid(t *testing.T) {
	r := newTestRing(t, time.Hour)
	k, _ := r.Signer()

	kid, err := r.ActiveKid()
	if err != nil {
		t.Fatalf("ActiveKid() error = %v", err)
	}
	if kid != k.Kid() {
		t.Fatalf("ActiveKid() = %q, want %q", kid, k.Kid())
	}
}

func TestRotateProducesNewKey(t *testing.T) {
	r := newTestRing(t, time.Hour)
	oldKey, _ := r.Signer()

	if err := r.Rotate(); err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	newKey, _ := r.Signer()
	if oldKey.Kid() == newKey.Kid() {
		t.Fatal("Rotate() produced same kid")
	}
}

func TestPruneNoOpWhenNoRetiredKeys(t *testing.T) {
	r := newTestRing(t, time.Hour)
	r.Prune()
	set, err := r.JWKS()
	if err != nil {
		t.Fatalf("JWKS() error = %v", err)
	}
	if set.Len() != 1 {
		t.Fatalf("JWKS length = %d, want 1", set.Len())
	}
}

func TestStartRotationDisabledWhenIntervalZero(t *testing.T) {
	r := newTestRing(t, time.Hour)
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
	r := newTestRing(t, 50*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	r.StartRotation(ctx, 10*time.Millisecond, logger)

	// Wait for at least one rotation to happen
	time.Sleep(200 * time.Millisecond)

	output := buf.String()
	if !strings.Contains(output, "signing key rotated") {
		t.Fatalf("expected log about key rotated, got: %s", output)
	}

	// Verify the active key changed
	set, err := r.JWKS()
	if err != nil {
		t.Fatalf("JWKS() error = %v", err)
	}
	if set.Len() < 1 {
		t.Fatalf("JWKS is empty")
	}
}

func TestNewReturnsErrorWhenGenerateKeyFails(t *testing.T) {
	// Test New error path by creating a KeyRing with invalid bits
	r := &KeyRing{bits: -1}
	_, err := r.generateKey()
	if err == nil {
		t.Fatal("expected error from generateKey with invalid bits")
	}
}

func TestGenerateKeyErrorPath(t *testing.T) {
	r := &KeyRing{bits: -1}
	_, err := r.generateKey()
	if err == nil {
		t.Fatal("expected error from generateKey with invalid bits")
	}
}

func TestSignerReturnsErrorWhenNoActive(t *testing.T) {
	r := &KeyRing{}
	_, err := r.Signer()
	if err != ErrNoActiveKey {
		t.Fatalf("Signer() error = %v, want ErrNoActiveKey", err)
	}
}

func TestActiveKidReturnsErrorWhenNoActive(t *testing.T) {
	r := &KeyRing{}
	_, err := r.ActiveKid()
	if err != ErrNoActiveKey {
		t.Fatalf("ActiveKid() error = %v, want ErrNoActiveKey", err)
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

func (f *failingKeyRing) Signer() (*Key, error)      { return nil, f.err }
func (f *failingKeyRing) ActiveKid() (string, error) { return "", f.err }
func (f *failingKeyRing) JWKS() (jwk.Set, error)     { return nil, f.err }
func (f *failingKeyRing) Rotate() error              { return f.err }
func (f *failingKeyRing) RotateAt(time.Time) error   { return f.err }
func (f *failingKeyRing) Prune()                     {}
func (f *failingKeyRing) PruneAt(time.Time)          {}
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
				kid, err := f.ActiveKid()
				if err != nil {
					logger.Error("post-rotation state invalid", "error", err)
					continue
				}
				logger.Info("signing key rotated", "active_kid", kid)
			}
		}
	}()
}

func TestRotateAtErrorPath(t *testing.T) {
	r := &KeyRing{bits: -1}
	err := r.RotateAt(time.Now())
	if err == nil {
		t.Fatal("expected error from RotateAt when generateKey fails")
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
	rotateCount int
}

func (f *failingActiveKidKeyRing) Signer() (*Key, error)      { return &Key{}, nil }
func (f *failingActiveKidKeyRing) ActiveKid() (string, error) { return "", errors.New("no active key") }
func (f *failingActiveKidKeyRing) JWKS() (jwk.Set, error)     { return jwk.NewSet(), nil }
func (f *failingActiveKidKeyRing) Rotate() error              { return nil }
func (f *failingActiveKidKeyRing) RotateAt(time.Time) error   { return nil }
func (f *failingActiveKidKeyRing) Prune()                     {}
func (f *failingActiveKidKeyRing) PruneAt(time.Time)          {}
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
				kid, err := f.ActiveKid()
				if err != nil {
					logger.Error("post-rotation state invalid", "error", err)
					continue
				}
				logger.Info("signing key rotated", "active_kid", kid)
			}
		}
	}()
}
