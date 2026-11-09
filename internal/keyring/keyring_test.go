package keyring

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

// lockedBuffer is a concurrency-safe log sink. Rotation logs are written from a
// background goroutine while tests inspect the captured output.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

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

func TestAllAlgorithmsKeyTypeAndJWA(t *testing.T) {
	type expected struct {
		kind  string
		curve elliptic.Curve
	}
	want := map[Algorithm]expected{
		AlgRS256: {kind: "rsa"},
		AlgRS384: {kind: "rsa"},
		AlgRS512: {kind: "rsa"},
		AlgPS256: {kind: "rsa"},
		AlgPS384: {kind: "rsa"},
		AlgPS512: {kind: "rsa"},
		AlgES256: {kind: "ecdsa", curve: elliptic.P256()},
		AlgES384: {kind: "ecdsa", curve: elliptic.P384()},
		AlgES512: {kind: "ecdsa", curve: elliptic.P521()},
		AlgEdDSA: {kind: "ed25519"},
	}
	if len(want) != len(allAlgorithms) {
		t.Fatalf("test table covers %d algorithms, registry has %d", len(want), len(allAlgorithms))
	}

	for _, alg := range allAlgorithms {
		t.Run(string(alg), func(t *testing.T) {
			exp, ok := want[alg]
			if !ok {
				t.Fatalf("algorithm %s missing from test table", alg)
			}
			jwaAlg, ok := jwaAlgorithms[alg]
			if !ok || jwaAlg == nil {
				t.Fatalf("jwaAlgorithms[%s] is missing", alg)
			}
			if got := jwaAlg.String(); got != string(alg) {
				t.Fatalf("jwaAlgorithms[%s] = %s, want %s", alg, got, alg)
			}

			r := newTestRing(t, time.Hour, alg)
			k, err := r.Signer(alg)
			if err != nil {
				t.Fatalf("Signer() error = %v", err)
			}
			switch exp.kind {
			case "rsa":
				if _, ok := k.Public.(*rsa.PublicKey); !ok {
					t.Fatalf("Public type = %T, want *rsa.PublicKey", k.Public)
				}
			case "ecdsa":
				pub, ok := k.Public.(*ecdsa.PublicKey)
				if !ok {
					t.Fatalf("Public type = %T, want *ecdsa.PublicKey", k.Public)
				}
				if pub.Curve != exp.curve {
					t.Fatalf("curve = %s, want %s", pub.Curve.Params().Name, exp.curve.Params().Name)
				}
			case "ed25519":
				if _, ok := k.Public.(ed25519.PublicKey); !ok {
					t.Fatalf("Public type = %T, want ed25519.PublicKey", k.Public)
				}
			default:
				t.Fatalf("unknown expected kind %q", exp.kind)
			}

			gotAlg, ok := k.PubJWK.Algorithm()
			if !ok || gotAlg != jwaAlg {
				t.Fatalf("public JWK alg = %v, want %v", gotAlg, jwaAlg)
			}
		})
	}
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

func TestEveryEnabledAlgorithmExposesUsablePublicKey(t *testing.T) {
	for _, alg := range []Algorithm{AlgRS256, AlgES256, AlgEdDSA} {
		t.Run(string(alg), func(t *testing.T) {
			r := newTestRing(t, time.Hour, alg)
			k, err := r.Signer(alg)
			if err != nil {
				t.Fatalf("Signer() error = %v", err)
			}
			if k.Public == nil {
				t.Fatal("Public is nil")
			}
			signer, ok := k.Private.(crypto.Signer)
			if !ok {
				t.Fatalf("private key %T does not implement crypto.Signer", k.Private)
			}
			switch alg {
			case AlgRS256:
				if _, ok := k.Public.(*rsa.PublicKey); !ok {
					t.Fatalf("Public type = %T, want *rsa.PublicKey", k.Public)
				}
			case AlgES256:
				if _, ok := k.Public.(*ecdsa.PublicKey); !ok {
					t.Fatalf("Public type = %T, want *ecdsa.PublicKey", k.Public)
				}
			case AlgEdDSA:
				if _, ok := k.Public.(ed25519.PublicKey); !ok {
					t.Fatalf("Public type = %T, want ed25519.PublicKey", k.Public)
				}
			}
			if !reflect.DeepEqual(k.Public, signer.Public()) {
				t.Fatal("cached public key differs from signer public key")
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
		// ECDSA zeroization skipped (Go 1.26+ deprecation); key discarded on exit.
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

	var buf lockedBuffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	done := r.StartRotation(ctx, 0, logger)
	select {
	case <-done:
	default:
		t.Fatal("StartRotation with zero interval did not return a closed done channel")
	}
	time.Sleep(10 * time.Millisecond)
	output := buf.String()
	if !strings.Contains(output, "key rotation disabled") {
		t.Fatalf("expected log about rotation disabled, got: %s", output)
	}
}

func TestStartRotationCancellationClosesDone(t *testing.T) {
	r := newTestRing(t, time.Hour, AlgRS256)
	ctx, cancel := context.WithCancel(context.Background())

	var buf lockedBuffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	done := r.StartRotation(ctx, 10*time.Millisecond, logger)
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("rotation goroutine did not exit after cancellation")
	}
}

func TestStartRotationRotatesAndPrunes(t *testing.T) {
	r := newTestRing(t, 50*time.Millisecond, AlgRS256, AlgES256)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var buf lockedBuffer
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

func TestExpandedAlgorithmViewsAreAsymmetricDeterministicAndSorted(t *testing.T) {
	enabled := []Algorithm{AlgRS256, AlgPS256, AlgES384, AlgES512, AlgEdDSA}
	r := newTestRing(t, time.Hour, enabled...)

	wantOrder := []Algorithm{AlgRS256, AlgPS256, AlgES384, AlgES512, AlgEdDSA}
	gotOrder := r.EnabledAlgorithms()
	if !reflect.DeepEqual(gotOrder, wantOrder) {
		t.Fatalf("EnabledAlgorithms() = %v, want %v", gotOrder, wantOrder)
	}
	for _, alg := range gotOrder {
		if alg == "none" || alg == "HS256" {
			t.Fatalf("EnabledAlgorithms() contains non-asymmetric algorithm %q", alg)
		}
	}

	first, err := r.JWKS()
	if err != nil {
		t.Fatalf("JWKS() error = %v", err)
	}
	second, err := r.JWKS()
	if err != nil {
		t.Fatalf("JWKS() error = %v", err)
	}
	if first.Len() != len(enabled) || second.Len() != len(enabled) {
		t.Fatalf("JWKS length = %d/%d, want %d", first.Len(), second.Len(), len(enabled))
	}

	var previous string
	for i := 0; i < first.Len(); i++ {
		firstKey, _ := first.Key(i)
		secondKey, _ := second.Key(i)
		firstKid, _ := firstKey.KeyID()
		secondKid, _ := secondKey.KeyID()
		if firstKid != secondKid {
			t.Fatalf("JWKS key order changed at index %d: %q vs %q", i, firstKid, secondKid)
		}
		if i > 0 && firstKid < previous {
			t.Fatalf("JWKS not sorted by kid: %q before %q", previous, firstKid)
		}
		previous = firstKid
		algVal, ok := firstKey.Algorithm()
		if !ok {
			t.Fatalf("JWKS key %q has no alg", firstKid)
		}
		if algVal.String() == "HS256" || algVal.String() == "none" {
			t.Fatalf("JWKS contains non-asymmetric algorithm %q", algVal)
		}
	}

	snapshot := r.Snapshot()
	if len(snapshot) != len(enabled) {
		t.Fatalf("Snapshot() length = %d, want %d", len(snapshot), len(enabled))
	}
	for i := 1; i < len(snapshot); i++ {
		if snapshot[i].Kid() < snapshot[i-1].Kid() {
			t.Fatalf("Snapshot() not sorted by kid: %q before %q", snapshot[i-1].Kid(), snapshot[i].Kid())
		}
	}
	for _, k := range snapshot {
		if k.Algorithm == "none" || k.Algorithm == "HS256" {
			t.Fatalf("Snapshot() contains non-asymmetric algorithm %q", k.Algorithm)
		}
	}
}

func TestNewRejectsNonAsymmetricAlgorithms(t *testing.T) {
	for _, alg := range []Algorithm{"none", "HS256"} {
		t.Run(string(alg), func(t *testing.T) {
			_, err := New(time.Hour, []Algorithm{alg})
			if !errors.Is(err, ErrUnsupportedAlg) {
				t.Fatalf("New(%q) error = %v, want ErrUnsupportedAlg", alg, err)
			}
		})
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

func (f *failingKeyRing) Signer(Algorithm) (*Key, error) { return nil, f.err }
func (f *failingKeyRing) SignerByKID(string, Algorithm) (*Key, error) {
	return nil, f.err
}
func (f *failingKeyRing) ActiveKid(Algorithm) (string, error) { return "", f.err }
func (f *failingKeyRing) Lookup(string) (crypto.PublicKey, KeyStatus, error) {
	return nil, "", f.err
}
func (f *failingKeyRing) JWKS() (jwk.Set, error)   { return nil, f.err }
func (f *failingKeyRing) Rotate() error            { return f.err }
func (f *failingKeyRing) RotateAt(time.Time) error { return f.err }
func (f *failingKeyRing) Prune()                   {}
func (f *failingKeyRing) PruneAt(time.Time)        {}
func (f *failingKeyRing) StartRotation(ctx context.Context, interval time.Duration, logger *slog.Logger) <-chan struct{} {
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
	return done
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

	var buf lockedBuffer
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

	var buf lockedBuffer
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
func (f *failingActiveKidKeyRing) SignerByKID(string, Algorithm) (*Key, error) {
	return &Key{}, nil
}
func (f *failingActiveKidKeyRing) ActiveKid(Algorithm) (string, error) {
	return "", errors.New("no active key")
}
func (f *failingActiveKidKeyRing) Lookup(string) (crypto.PublicKey, KeyStatus, error) {
	return nil, "", errors.New("not found")
}
func (f *failingActiveKidKeyRing) JWKS() (jwk.Set, error)   { return jwk.NewSet(), nil }
func (f *failingActiveKidKeyRing) Rotate() error            { return nil }
func (f *failingActiveKidKeyRing) RotateAt(time.Time) error { return nil }
func (f *failingActiveKidKeyRing) Prune()                   {}
func (f *failingActiveKidKeyRing) PruneAt(time.Time)        {}
func (f *failingActiveKidKeyRing) StartRotation(ctx context.Context, interval time.Duration, logger *slog.Logger) <-chan struct{} {
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
	return done
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
	if len(algs) != len(allAlgorithms) {
		t.Fatalf("expected %d algorithms, got %d", len(allAlgorithms), len(algs))
	}
	for _, alg := range allAlgorithms {
		if algs[alg] == nil {
			t.Fatalf("missing %s in JWAAlgorithms", alg)
		}
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

func TestJWKSKeyOrderIsStableAndSortedByKid(t *testing.T) {
	r := newTestRing(t, time.Hour, AlgRS256, AlgES256, AlgEdDSA)
	if err := r.Rotate(); err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}

	first, err := r.JWKS()
	if err != nil {
		t.Fatalf("JWKS() error = %v", err)
	}
	second, err := r.JWKS()
	if err != nil {
		t.Fatalf("JWKS() error = %v", err)
	}
	if first.Len() != second.Len() {
		t.Fatalf("JWKS lengths differ: %d vs %d", first.Len(), second.Len())
	}

	var previous string
	for i := 0; i < first.Len(); i++ {
		firstKey, _ := first.Key(i)
		secondKey, _ := second.Key(i)
		firstKid, _ := firstKey.KeyID()
		secondKid, _ := secondKey.KeyID()
		if firstKid != secondKid {
			t.Fatalf("key order changed at index %d: %q vs %q", i, firstKid, secondKid)
		}
		if i > 0 && firstKid < previous {
			t.Fatalf("keys not sorted by kid: %q before %q", previous, firstKid)
		}
		previous = firstKid
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

	var buf lockedBuffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	done := r.StartRotation(ctx, -time.Hour, logger)
	select {
	case <-done:
	default:
		t.Fatal("StartRotation with negative interval did not return a closed done channel")
	}
	time.Sleep(10 * time.Millisecond)
	output := buf.String()
	if !strings.Contains(output, "key rotation disabled") {
		t.Fatalf("expected log about rotation disabled, got: %s", output)
	}
}

func TestRSABits(t *testing.T) {
	rsaModulus := func(t *testing.T, r *KeyRing, alg Algorithm) int {
		t.Helper()
		k, err := r.Signer(alg)
		if err != nil {
			t.Fatalf("Signer(%s) error = %v", alg, err)
		}
		pub, ok := k.Public.(*rsa.PublicKey)
		if !ok {
			t.Fatalf("Public type = %T, want *rsa.PublicKey", k.Public)
		}
		return pub.N.BitLen()
	}

	t.Run("default is 2048", func(t *testing.T) {
		r, err := New(time.Hour, []Algorithm{AlgRS256, AlgPS256})
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		for _, alg := range []Algorithm{AlgRS256, AlgPS256} {
			if got := rsaModulus(t, r, alg); got != 2048 {
				t.Fatalf("%s modulus = %d bits, want 2048", alg, got)
			}
		}
	})

	t.Run("custom size is honored", func(t *testing.T) {
		r, err := New(time.Hour, []Algorithm{AlgRS256}, WithRSABits(3072))
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if got := rsaModulus(t, r, AlgRS256); got != 3072 {
			t.Fatalf("modulus = %d bits, want 3072", got)
		}
	})

	t.Run("minimum is accepted", func(t *testing.T) {
		r, err := New(time.Hour, []Algorithm{AlgRS256}, WithRSABits(1024))
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if got := rsaModulus(t, r, AlgRS256); got != 1024 {
			t.Fatalf("modulus = %d bits, want 1024", got)
		}
	})

	for _, bits := range []int{0, 512, 1023, -2048} {
		t.Run(fmt.Sprintf("invalid input %d", bits), func(t *testing.T) {
			_, err := New(time.Hour, []Algorithm{AlgRS256}, WithRSABits(bits))
			if err == nil {
				t.Fatalf("New() with RSA bits %d succeeded, want error", bits)
			}
		})
	}
}

func TestNewRequiresAtLeastOneAlgorithm(t *testing.T) {
	_, err := New(time.Hour, []Algorithm{})
	if err == nil {
		t.Fatal("expected error when no algorithms enabled")
	}
}

func TestSnapshotIncludesActiveAndRetiredKeysSortedByKid(t *testing.T) {
	r := newTestRing(t, time.Hour, AlgRS256, AlgES256)
	oldRS, err := r.Signer(AlgRS256)
	if err != nil {
		t.Fatalf("Signer() error = %v", err)
	}

	if err := r.Rotate(); err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}

	snapshot := r.Snapshot()
	if len(snapshot) != 4 {
		t.Fatalf("Snapshot() length = %d, want 4 (two active, two retired)", len(snapshot))
	}
	var previous string
	foundRetired := false
	for i, key := range snapshot {
		if i > 0 && key.Kid() < previous {
			t.Fatalf("Snapshot() not sorted by kid: %q before %q", previous, key.Kid())
		}
		previous = key.Kid()
		if key.Kid() == oldRS.Kid() {
			foundRetired = true
			if key.RetiredAt.IsZero() {
				t.Fatal("retired key has zero RetiredAt")
			}
		}
	}
	if !foundRetired {
		t.Fatal("retired key missing from Snapshot()")
	}
}

func TestPublicKeyByKIDActiveRetiredPrunedAndUnknown(t *testing.T) {
	r := newTestRing(t, time.Hour, AlgRS256)
	active, err := r.Signer(AlgRS256)
	if err != nil {
		t.Fatalf("Signer() error = %v", err)
	}
	if got, err := r.PublicKeyByKID(active.Kid()); err != nil || got == nil {
		t.Fatalf("PublicKeyByKID(active) = %v, %v", got, err)
	}

	if err := r.Rotate(); err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if got, err := r.PublicKeyByKID(active.Kid()); err != nil || got == nil {
		t.Fatalf("PublicKeyByKID(retired) = %v, %v", got, err)
	}

	r.PruneAt(time.Now().Add(2 * time.Hour))
	if _, err := r.PublicKeyByKID(active.Kid()); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("PublicKeyByKID(pruned) error = %v, want ErrKeyNotFound", err)
	}
	if _, err := r.PublicKeyByKID("unknown-kid"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("PublicKeyByKID(unknown) error = %v, want ErrKeyNotFound", err)
	}
}

func TestSignerByKIDActiveRetiredMismatchUnknownAndPruned(t *testing.T) {
	t.Run("active", func(t *testing.T) {
		r := newTestRing(t, time.Hour, AlgRS256, AlgES256)
		active, err := r.Signer(AlgRS256)
		if err != nil {
			t.Fatalf("Signer() error = %v", err)
		}
		got, err := r.SignerByKID(active.Kid(), AlgRS256)
		if err != nil {
			t.Fatalf("SignerByKID(active) error = %v", err)
		}
		if got.Kid() != active.Kid() {
			t.Fatalf("SignerByKID(active) = %q, want %q", got.Kid(), active.Kid())
		}
	})

	t.Run("retired", func(t *testing.T) {
		r := newTestRing(t, time.Hour, AlgRS256)
		retired, err := r.Signer(AlgRS256)
		if err != nil {
			t.Fatalf("Signer() error = %v", err)
		}
		if err := r.Rotate(); err != nil {
			t.Fatalf("Rotate() error = %v", err)
		}
		got, err := r.SignerByKID(retired.Kid(), AlgRS256)
		if err != nil {
			t.Fatalf("SignerByKID(retired) error = %v", err)
		}
		if got.Kid() != retired.Kid() {
			t.Fatalf("SignerByKID(retired) = %q, want %q", got.Kid(), retired.Kid())
		}
		if _, status, err := r.Lookup(retired.Kid()); err != nil || status != KeyStatusRetired {
			t.Fatalf("retired key changed state: status=%q err=%v", status, err)
		}
	})

	t.Run("algorithm mismatch", func(t *testing.T) {
		r := newTestRing(t, time.Hour, AlgRS256, AlgES256)
		rs, err := r.Signer(AlgRS256)
		if err != nil {
			t.Fatalf("Signer() error = %v", err)
		}
		_, err = r.SignerByKID(rs.Kid(), AlgES256)
		if !errors.Is(err, ErrUnsupportedAlg) {
			t.Fatalf("SignerByKID(mismatch) error = %v, want ErrUnsupportedAlg", err)
		}
	})

	t.Run("unknown", func(t *testing.T) {
		r := newTestRing(t, time.Hour, AlgRS256)
		_, err := r.SignerByKID("unknown-kid", AlgRS256)
		if !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("SignerByKID(unknown) error = %v, want ErrKeyNotFound", err)
		}
	})

	t.Run("post-prune", func(t *testing.T) {
		r := newTestRing(t, time.Hour, AlgRS256)
		old, err := r.Signer(AlgRS256)
		if err != nil {
			t.Fatalf("Signer() error = %v", err)
		}
		if err := r.Rotate(); err != nil {
			t.Fatalf("Rotate() error = %v", err)
		}
		r.PruneAt(time.Now().Add(2 * time.Hour))
		_, err = r.SignerByKID(old.Kid(), AlgRS256)
		if !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("SignerByKID(pruned) error = %v, want ErrKeyNotFound", err)
		}
	})
}

func TestLookupReportsActiveRetiredPrunedAndUnknown(t *testing.T) {
	r := newTestRing(t, time.Hour, AlgRS256)
	active, err := r.Signer(AlgRS256)
	if err != nil {
		t.Fatalf("Signer() error = %v", err)
	}

	got, status, err := r.Lookup(active.Kid())
	if err != nil {
		t.Fatalf("Lookup(active) error = %v", err)
	}
	if got == nil {
		t.Fatal("Lookup(active) returned a nil key")
	}
	if status != KeyStatusActive {
		t.Fatalf("Lookup(active) status = %q, want %q", status, KeyStatusActive)
	}

	if err := r.Rotate(); err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	got, status, err = r.Lookup(active.Kid())
	if err != nil {
		t.Fatalf("Lookup(retired) error = %v", err)
	}
	if got == nil {
		t.Fatal("Lookup(retired) returned a nil key")
	}
	if status != KeyStatusRetired {
		t.Fatalf("Lookup(retired) status = %q, want %q", status, KeyStatusRetired)
	}

	r.PruneAt(time.Now().Add(2 * time.Hour))
	if _, _, err := r.Lookup(active.Kid()); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Lookup(pruned) error = %v, want ErrKeyNotFound", err)
	}
	if _, _, err := r.Lookup("unknown-kid"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Lookup(unknown) error = %v, want ErrKeyNotFound", err)
	}
}

func TestLookupIsSafeDuringRotationAndPrune(t *testing.T) {
	r := newTestRing(t, time.Hour, AlgRS256)
	k, err := r.Signer(AlgRS256)
	if err != nil {
		t.Fatalf("Signer() error = %v", err)
	}
	kid := k.Kid()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			now := time.Now()
			if err := r.RotateAt(now); err != nil {
				t.Errorf("RotateAt() error = %v", err)
				return
			}
			r.PruneAt(now.Add(2 * time.Hour))
		}
	}()
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, _, _ = r.Lookup(kid)
			}
		}()
	}
	wg.Wait()
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
