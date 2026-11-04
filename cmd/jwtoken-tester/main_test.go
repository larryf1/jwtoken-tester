package main

import (
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

func clearOAuthServeEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{"AUDIENCE", "SCOPES", "DISCOVERY_EXTRA_JSON"} {
		t.Setenv(key, "")
	}
}

func TestDefaultServeConfigOAuthDefaults(t *testing.T) {
	clearOAuthServeEnv(t)

	cfg := defaultServeConfig()
	if cfg.Audience != "" {
		t.Errorf("Audience = %q, want empty", cfg.Audience)
	}
	if cfg.Scopes != "" {
		t.Errorf("Scopes = %q, want empty", cfg.Scopes)
	}
	if cfg.DiscoveryExtraJSON != "" {
		t.Errorf("DiscoveryExtraJSON = %q, want empty", cfg.DiscoveryExtraJSON)
	}
}

func TestServeConfigReadsOAuthEnvironment(t *testing.T) {
	t.Setenv("AUDIENCE", "my-api")
	t.Setenv("SCOPES", "read,write")
	t.Setenv("DISCOVERY_EXTRA_JSON", `{"service_documentation":"https://example.test/docs"}`)

	cfg := defaultServeConfig()
	if cfg.Audience != "my-api" {
		t.Errorf("Audience = %q, want my-api", cfg.Audience)
	}
	if cfg.Scopes != "read,write" {
		t.Errorf("Scopes = %q, want read,write", cfg.Scopes)
	}
	if cfg.DiscoveryExtraJSON != `{"service_documentation":"https://example.test/docs"}` {
		t.Errorf("DiscoveryExtraJSON = %q", cfg.DiscoveryExtraJSON)
	}
}

func TestServeConfigOAuthFlagsOverrideEnvironment(t *testing.T) {
	t.Setenv("AUDIENCE", "from-env")
	t.Setenv("SCOPES", "from-env")
	t.Setenv("DISCOVERY_EXTRA_JSON", `{"source":"env"}`)

	cfg, err := loadServeConfig([]string{
		"--audience", "from-flag",
		"--scopes", "read, write",
		"--discovery-extra-json", `{"source":"flag"}`,
	}, io.Discard)
	if err != nil {
		t.Fatalf("loadServeConfig() error = %v", err)
	}
	if cfg.Audience != "from-flag" {
		t.Errorf("Audience = %q, want from-flag", cfg.Audience)
	}
	if cfg.Scopes != "read, write" {
		t.Errorf("Scopes = %q, want %q", cfg.Scopes, "read, write")
	}
	if cfg.DiscoveryExtraJSON != `{"source":"flag"}` {
		t.Errorf("DiscoveryExtraJSON = %q", cfg.DiscoveryExtraJSON)
	}
}

func TestLoadServeConfigRejectsInvalidDiscoveryExtra(t *testing.T) {
	clearOAuthServeEnv(t)

	for _, raw := range []string{
		`[]`,
		`"string"`,
		`123`,
		`true`,
		`null`,
		`{invalid`,
	} {
		t.Run(raw, func(t *testing.T) {
			_, err := loadServeConfig([]string{"--discovery-extra-json", raw}, io.Discard)
			if err == nil {
				t.Fatalf("loadServeConfig(%q) error = nil, want configuration error", raw)
			}
			if !strings.Contains(err.Error(), "DISCOVERY_EXTRA_JSON") {
				t.Errorf("error = %v, want mention of DISCOVERY_EXTRA_JSON", err)
			}
		})
	}

	t.Run("valid object", func(t *testing.T) {
		cfg, err := loadServeConfig([]string{"--discovery-extra-json", `{"custom":"value"}`}, io.Discard)
		if err != nil {
			t.Fatalf("loadServeConfig() error = %v", err)
		}
		if cfg.DiscoveryExtraJSON != `{"custom":"value"}` {
			t.Errorf("DiscoveryExtraJSON = %q", cfg.DiscoveryExtraJSON)
		}
		extra, err := parseDiscoveryExtra(cfg.DiscoveryExtraJSON)
		if err != nil {
			t.Fatalf("parseDiscoveryExtra() error = %v", err)
		}
		if extra["custom"] != "value" {
			t.Errorf("extra = %#v", extra)
		}
	})
}

func TestParseScopes(t *testing.T) {
	cases := map[string][]string{
		"":                nil,
		"read":            {"read"},
		"read,write":      {"read", "write"},
		" read , , write": {"read", "write"},
	}
	for raw, want := range cases {
		if got := parseScopes(raw); !reflect.DeepEqual(got, want) {
			t.Errorf("parseScopes(%q) = %#v, want %#v", raw, got, want)
		}
	}
}
