package keyring

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
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
