package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/larryf1/jwtoken-tester/v2/internal/keyring"
	"github.com/larryf1/jwtoken-tester/v2/internal/tokenfactory"
	"github.com/larryf1/jwtoken-tester/v2/internal/verify"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestRunHelpListsNewCommands(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"jwtoken-tester", "help"}, strings.NewReader(""), &stdout, &stderr, discardLogger())
	if code != 0 {
		t.Fatalf("run(help) = %d, want 0", code)
	}
	for _, want := range []string{"decode", "verify", "print-token", "healthcheck"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("help output does not mention %q:\n%s", want, stdout.String())
		}
	}
}

func TestRunUnknownCommandFails(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"jwtoken-tester", "bogus"}, strings.NewReader(""), &stdout, &stderr, discardLogger())
	if code == 0 {
		t.Fatal("run(bogus) = 0, want non-zero")
	}
	if !strings.Contains(stderr.String(), "unknown command: bogus") {
		t.Errorf("stderr = %q, want unknown-command error", stderr.String())
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Errorf("stdout = %q, want usage text", stdout.String())
	}
}

type cliTestIssuer struct {
	ring    *keyring.KeyRing
	factory *tokenfactory.Factory
	jwks    []byte
	issuer  string
}

func newCLITestIssuer(t *testing.T, issuer string, algs ...keyring.Algorithm) *cliTestIssuer {
	t.Helper()
	if len(algs) == 0 {
		algs = []keyring.Algorithm{keyring.AlgRS256}
	}
	ring, err := keyring.New(time.Hour, algs)
	if err != nil {
		t.Fatalf("keyring.New() error = %v", err)
	}
	set, err := ring.JWKS()
	if err != nil {
		t.Fatalf("JWKS() error = %v", err)
	}
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	return &cliTestIssuer{
		ring:    ring,
		factory: tokenfactory.NewFactory(ring, issuer, time.Hour, 24*time.Hour),
		jwks:    raw,
		issuer:  issuer,
	}
}

func (i *cliTestIssuer) mint(t *testing.T, claims map[string]any, alg string) string {
	t.Helper()
	resp, err := i.factory.Mint(&tokenfactory.Request{Claims: claims, Alg: alg})
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	return resp.AccessToken
}

func writeJWKS(t *testing.T, raw []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func runDecodeCLI(t *testing.T, args []string, stdin string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runDecodeCommand(args, strings.NewReader(stdin), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func runVerifyCLI(t *testing.T, args []string, stdin string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runVerifyCommand(args, strings.NewReader(stdin), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestDecodeCommand(t *testing.T) {
	issuer := newCLITestIssuer(t, "http://127.0.0.1:8080")
	valid := issuer.mint(t, map[string]any{"sub": "user-1", "aud": "my-service"}, "")
	expired := issuer.mint(t, map[string]any{"sub": "user-1", "exp": "-5m"}, "")
	foreign := newCLITestIssuer(t, "https://foreign.example").mint(t, map[string]any{"sub": "user-2"}, "")

	t.Run("valid token", func(t *testing.T) {
		code, stdout, stderr := runDecodeCLI(t, []string{valid}, "")
		if code != 0 {
			t.Fatalf("decode = %d, want 0; stderr: %s", code, stderr)
		}
		for _, want := range []string{`"header"`, `"claims"`, `"alg": "RS256"`, `"sub": "user-1"`} {
			if !strings.Contains(stdout, want) {
				t.Errorf("output missing %q:\n%s", want, stdout)
			}
		}
	})

	t.Run("expired token decodes", func(t *testing.T) {
		code, stdout, stderr := runDecodeCLI(t, []string{expired}, "")
		if code != 0 {
			t.Fatalf("decode = %d, want 0; stderr: %s", code, stderr)
		}
		if !strings.Contains(stdout, `"exp"`) {
			t.Errorf("output missing exp claim:\n%s", stdout)
		}
	})

	t.Run("foreign token decodes", func(t *testing.T) {
		code, stdout, stderr := runDecodeCLI(t, []string{foreign}, "")
		if code != 0 {
			t.Fatalf("decode = %d, want 0; stderr: %s", code, stderr)
		}
		if !strings.Contains(stdout, `"iss": "https://foreign.example"`) {
			t.Errorf("output missing foreign issuer:\n%s", stdout)
		}
	})

	t.Run("malformed value rejected", func(t *testing.T) {
		code, _, stderr := runDecodeCLI(t, []string{"not-a-token"}, "")
		if code == 0 {
			t.Fatal("decode = 0, want non-zero")
		}
		if !strings.Contains(stderr, "three-segment") {
			t.Errorf("stderr = %q, want structural error", stderr)
		}
	})

	t.Run("piped input", func(t *testing.T) {
		code, stdout, stderr := runDecodeCLI(t, nil, valid)
		if code != 0 {
			t.Fatalf("decode = %d, want 0; stderr: %s", code, stderr)
		}
		if !strings.Contains(stdout, `"sub": "user-1"`) {
			t.Errorf("output missing piped token claims:\n%s", stdout)
		}
	})

	t.Run("empty input rejected", func(t *testing.T) {
		code, _, stderr := runDecodeCLI(t, nil, "")
		if code == 0 {
			t.Fatal("decode = 0, want non-zero")
		}
		if !strings.Contains(stderr, "no token") {
			t.Errorf("stderr = %q, want missing-token error", stderr)
		}
	})
}

func TestVerifyAgainstJWKSFile(t *testing.T) {
	issuer := newCLITestIssuer(t, "http://127.0.0.1:8080")
	token := issuer.mint(t, map[string]any{"sub": "user-1", "aud": "my-service"}, "")
	path := writeJWKS(t, issuer.jwks)

	code, stdout, stderr := runVerifyCLI(t, []string{"--jwks", path, token}, "")
	if code != 0 {
		t.Fatalf("verify = %d, want 0; stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "valid: token verified") {
		t.Errorf("stdout = %q, want valid verdict", stdout)
	}

	t.Run("audience mismatch", func(t *testing.T) {
		code, stdout, _ := runVerifyCLI(t, []string{"--jwks", path, "--aud", "other-service", token}, "")
		if code != 1 {
			t.Fatalf("verify = %d, want 1", code)
		}
		if !strings.Contains(stdout, "audience") {
			t.Errorf("stdout = %q, want audience reason", stdout)
		}
	})

	t.Run("audience match", func(t *testing.T) {
		code, _, stderr := runVerifyCLI(t, []string{"--jwks", path, "--aud", "my-service", token}, "")
		if code != 0 {
			t.Fatalf("verify = %d, want 0; stderr: %s", code, stderr)
		}
	})

	t.Run("algorithm mismatch", func(t *testing.T) {
		code, stdout, _ := runVerifyCLI(t, []string{"--jwks", path, "--alg", "ES256", token}, "")
		if code != 1 {
			t.Fatalf("verify = %d, want 1", code)
		}
		if !strings.Contains(stdout, "invalid: alg") {
			t.Errorf("stdout = %q, want alg reason", stdout)
		}
	})

	t.Run("expired with leeway", func(t *testing.T) {
		expired := issuer.mint(t, map[string]any{"sub": "user-1", "exp": "-5m"}, "")
		if code, stdout, _ := runVerifyCLI(t, []string{"--jwks", path, expired}, ""); code != 1 || !strings.Contains(stdout, "invalid: expired") {
			t.Fatalf("verify without leeway = %d, stdout %q; want expired verdict", code, stdout)
		}
		if code, _, stderr := runVerifyCLI(t, []string{"--jwks", path, "--leeway", "1h", expired}, ""); code != 0 {
			t.Fatalf("verify with leeway = %d, want 0; stderr: %s", code, stderr)
		}
	})
}

func TestVerifyAgainstJWKSURL(t *testing.T) {
	issuer := newCLITestIssuer(t, "http://127.0.0.1:8080")
	token := issuer.mint(t, map[string]any{"sub": "user-1"}, "")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(issuer.jwks)
	}))
	defer srv.Close()

	code, stdout, stderr := runVerifyCLI(t, []string{"--jwks", srv.URL, token}, "")
	if code != 0 {
		t.Fatalf("verify = %d, want 0; stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "valid: token verified") {
		t.Errorf("stdout = %q, want valid verdict", stdout)
	}
}

func TestVerifyKeySourceSizeCap(t *testing.T) {
	issuer := newCLITestIssuer(t, "http://127.0.0.1:8080")
	token := issuer.mint(t, map[string]any{"sub": "user-1"}, "")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("a"), maxKeySourceBytes+1))
	}))
	defer srv.Close()

	code, _, stderr := runVerifyCLI(t, []string{"--jwks", srv.URL, token}, "")
	if code != 2 {
		t.Fatalf("verify = %d, want 2", code)
	}
	if !strings.Contains(stderr, "exceeds") {
		t.Errorf("stderr = %q, want size-cap error", stderr)
	}
}

func TestVerifyUnreachableKeySource(t *testing.T) {
	issuer := newCLITestIssuer(t, "http://127.0.0.1:8080")
	token := issuer.mint(t, map[string]any{"sub": "user-1"}, "")

	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	code, _, stderr := runVerifyCLI(t, []string{"--jwks", url, token}, "")
	if code != 2 {
		t.Fatalf("verify = %d, want 2", code)
	}
	if !strings.Contains(stderr, "fetching") {
		t.Errorf("stderr = %q, want fetch error", stderr)
	}
}

func TestVerifyIssuerDiscovery(t *testing.T) {
	var srv *httptest.Server
	var issuer *cliTestIssuer
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   srv.URL,
			"jwks_uri": srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(issuer.jwks)
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	issuer = newCLITestIssuer(t, srv.URL)
	token := issuer.mint(t, map[string]any{"sub": "user-1"}, "")

	code, stdout, stderr := runVerifyCLI(t, []string{"--issuer", srv.URL, token}, "")
	if code != 0 {
		t.Fatalf("verify = %d, want 0; stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "valid: token verified") {
		t.Errorf("stdout = %q, want valid verdict", stdout)
	}
}

func TestVerifyIssuerDiscoveryMissingJWKSURI(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": srv.URL})
	}))
	defer srv.Close()

	issuer := newCLITestIssuer(t, srv.URL)
	token := issuer.mint(t, map[string]any{"sub": "user-1"}, "")

	code, _, stderr := runVerifyCLI(t, []string{"--issuer", srv.URL, token}, "")
	if code != 2 {
		t.Fatalf("verify = %d, want 2", code)
	}
	if !strings.Contains(stderr, "jwks_uri") {
		t.Errorf("stderr = %q, want missing-jwks_uri error", stderr)
	}
}

func TestVerifyIssuerMismatch(t *testing.T) {
	var srv *httptest.Server
	var issuer *cliTestIssuer
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   srv.URL,
			"jwks_uri": srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(issuer.jwks)
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	issuer = newCLITestIssuer(t, srv.URL)
	token := issuer.mint(t, map[string]any{"sub": "user-1", "iss": "https://attacker.example"}, "")

	code, stdout, _ := runVerifyCLI(t, []string{"--issuer", srv.URL, token}, "")
	if code != 1 {
		t.Fatalf("verify = %d, want 1", code)
	}
	if !strings.Contains(stdout, "invalid: issuer") {
		t.Errorf("stdout = %q, want issuer reason", stdout)
	}
}

func TestVerifyJSONMatchesVerdictShape(t *testing.T) {
	issuer := newCLITestIssuer(t, "http://127.0.0.1:8080")
	token := issuer.mint(t, map[string]any{"sub": "user-1", "aud": "my-service"}, "")
	path := writeJWKS(t, issuer.jwks)

	code, stdout, stderr := runVerifyCLI(t, []string{"--jwks", path, "--json", token}, "")
	if code != 0 {
		t.Fatalf("verify = %d, want 0; stderr: %s", code, stderr)
	}
	var verdict verify.Verdict
	if err := json.Unmarshal([]byte(stdout), &verdict); err != nil {
		t.Fatalf("unmarshal verdict: %v\n%s", err, stdout)
	}
	if !verdict.Valid || verdict.Reason != "" {
		t.Fatalf("verdict = %+v, want valid", verdict)
	}
	if verdict.Claims == nil || verdict.UnverifiedClaims != nil {
		t.Fatalf("verdict claims labeling = claims:%v unverified:%v, want authenticated claims only", verdict.Claims, verdict.UnverifiedClaims)
	}
	if verdict.Alg != "RS256" || verdict.Kid == "" || verdict.KidStatus != keyring.KeyStatusActive {
		t.Fatalf("verdict = %+v, want alg/kid/kid_status populated", verdict)
	}

	code, stdout, _ = runVerifyCLI(t, []string{"--jwks", path, "--json", "--aud", "other-service", token}, "")
	if code != 1 {
		t.Fatalf("verify = %d, want 1", code)
	}
	verdict = verify.Verdict{}
	if err := json.Unmarshal([]byte(stdout), &verdict); err != nil {
		t.Fatalf("unmarshal invalid verdict: %v\n%s", err, stdout)
	}
	if verdict.Valid || verdict.Reason != verify.ReasonAudience {
		t.Fatalf("verdict = %+v, want audience failure", verdict)
	}
}

func TestVerifyUsageErrors(t *testing.T) {
	issuer := newCLITestIssuer(t, "http://127.0.0.1:8080")
	token := issuer.mint(t, map[string]any{"sub": "user-1"}, "")
	path := writeJWKS(t, issuer.jwks)

	cases := []struct {
		name string
		args []string
	}{
		{name: "no key source", args: []string{token}},
		{name: "both key sources", args: []string{"--jwks", path, "--issuer", "http://127.0.0.1:8080", token}},
		{name: "unknown algorithm", args: []string{"--jwks", path, "--alg", "none", token}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := runVerifyCLI(t, tc.args, "")
			if code != 2 {
				t.Fatalf("verify = %d, want 2; stderr: %s", code, stderr)
			}
			if stderr == "" {
				t.Error("stderr is empty, want a usage error")
			}
		})
	}
}

func TestVerifyUnknownKidHint(t *testing.T) {
	known := newCLITestIssuer(t, "http://127.0.0.1:8080")
	foreign := newCLITestIssuer(t, "http://127.0.0.1:8080")
	token := foreign.mint(t, map[string]any{"sub": "user-1"}, "")
	path := writeJWKS(t, known.jwks)

	code, stdout, stderr := runVerifyCLI(t, []string{"--jwks", path, token}, "")
	if code != 1 {
		t.Fatalf("verify = %d, want 1", code)
	}
	if !strings.Contains(stdout, "invalid: kid") {
		t.Errorf("stdout = %q, want kid reason", stdout)
	}
	for _, want := range []string{"print-token", "restart"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr = %q, want hint mentioning %q", stderr, want)
		}
	}
}

func TestVerifyTokenFromStdin(t *testing.T) {
	issuer := newCLITestIssuer(t, "http://127.0.0.1:8080")
	token := issuer.mint(t, map[string]any{"sub": "user-1"}, "")
	path := writeJWKS(t, issuer.jwks)

	code, _, stderr := runVerifyCLI(t, []string{"--jwks", path}, token)
	if code != 0 {
		t.Fatalf("verify = %d, want 0; stderr: %s", code, stderr)
	}
}
