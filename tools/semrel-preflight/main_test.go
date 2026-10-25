package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateConfigMatchesConfiguredUpdaterRulesWithoutWriting(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, ".semrel.yaml")
	config := `plugins:
  - uses: "@semrel/updater-replace"
    args:
      replacements: |
        - files: VERSION
          from: '^[0-9]+\.[0-9]+\.[0-9]+$'
          flags: m
          to: '${nextRelease.version}'
          results:
            - file: VERSION
              numMatches: 1
              numReplacements: 1
        - files: docs/openapi.yaml
          from: '^  version: "[0-9]+\.[0-9]+\.[0-9]+"$'
          flags: m
          to: '  version: "${nextRelease.version}"'
          results:
            - file: docs/openapi.yaml
              numMatches: 1
              numReplacements: 1
`

	files := map[string]string{
		"VERSION":           "2.0.0\n",
		"docs/openapi.yaml": "info:\n  version: \"2.0.0\"\n",
	}
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0755); err != nil {
		t.Fatal(err)
	}
	for path, contents := range files {
		if err := os.WriteFile(filepath.Join(root, path), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}

	before := readFiles(t, root, files)
	if err := validateConfig(configPath, root); err != nil {
		t.Fatalf("validateConfig() error = %v", err)
	}
	for path, contents := range before {
		if got := readFile(t, filepath.Join(root, path)); got != contents {
			t.Errorf("validator modified %s", path)
		}
	}
}

func TestValidateConfigRejectsUnexpectedMatchCount(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, ".semrel.yaml")
	config := strings.ReplaceAll(validConfig, "numMatches: 1", "numMatches: 2")
	writeValidFixture(t, root, configPath, config)

	err := validateConfig(configPath, root)
	if err == nil || !strings.Contains(err.Error(), "expected 2 matches, found 1") {
		t.Fatalf("validateConfig() error = %v, want a match-count error", err)
	}
}

func TestValidateConfigRejectsZeroExpectedMatches(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, ".semrel.yaml")
	config := strings.ReplaceAll(validConfig, "numMatches: 1", "numMatches: 0")
	writeValidFixture(t, root, configPath, config)

	err := validateConfig(configPath, root)
	if err == nil || !strings.Contains(err.Error(), "must expect at least one match") {
		t.Fatalf("validateConfig() error = %v, want a zero-match error", err)
	}
}

const validConfig = `plugins:
  - uses: "@semrel/updater-replace"
    args:
      replacements: |
        - files: VERSION
          from: '^[0-9]+\.[0-9]+\.[0-9]+$'
          flags: m
          to: '${nextRelease.version}'
          results:
            - file: VERSION
              numMatches: 1
              numReplacements: 1
        - files: docs/openapi.yaml
          from: '^  version: "[0-9]+\.[0-9]+\.[0-9]+"$'
          flags: m
          to: '  version: "${nextRelease.version}"'
          results:
            - file: docs/openapi.yaml
              numMatches: 1
              numReplacements: 1
`

func writeValidFixture(t *testing.T, root, configPath, config string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "VERSION"), []byte("2.0.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "docs", "openapi.yaml"), []byte("info:\n  version: \"2.0.0\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
}

func readFiles(t *testing.T, root string, files map[string]string) map[string]string {
	t.Helper()
	contents := make(map[string]string, len(files))
	for path := range files {
		contents[path] = readFile(t, filepath.Join(root, path))
	}
	return contents
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(contents)
}
