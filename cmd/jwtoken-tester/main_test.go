package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveVersionPrefersBakedVersion(t *testing.T) {
	original := Version
	t.Cleanup(func() { Version = original })

	Version = "1.2.3"
	if got := resolveVersion(); got != "1.2.3" {
		t.Fatalf("resolveVersion() = %q, want %q", got, "1.2.3")
	}
}

func TestResolveVersionReadsVersionFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "VERSION"), []byte("4.5.6\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	original := Version
	t.Cleanup(func() { Version = original })

	Version = "dev"
	if got := resolveVersion(); got != "4.5.6" {
		t.Fatalf("resolveVersion() = %q, want %q", got, "4.5.6")
	}
}

func TestResolveVersionNeverReturnsDev(t *testing.T) {
	t.Chdir(t.TempDir())

	original := Version
	t.Cleanup(func() { Version = original })

	Version = "dev"
	got := resolveVersion()
	if got == "" || got == "dev" {
		t.Fatalf("resolveVersion() = %q, want a real version", got)
	}
}

func TestHealthcheckURL(t *testing.T) {
	cases := map[string]string{
		"0.0.0.0:8080":   "http://127.0.0.1:8080/healthz",
		":9090":          "http://127.0.0.1:9090/healthz",
		"127.0.0.1:8080": "http://127.0.0.1:8080/healthz",
		"[::]:8080":      "http://127.0.0.1:8080/healthz",
		"localhost:8080": "http://localhost:8080/healthz",
		"nonsense":       "http://127.0.0.1:8080/healthz",
	}
	for listen, want := range cases {
		if got := healthcheckURL(listen); got != want {
			t.Errorf("healthcheckURL(%q) = %q, want %q", listen, got, want)
		}
	}
}
