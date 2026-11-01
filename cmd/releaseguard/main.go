// Command releaseguard fails a release when the computed version's major does
// not match the major encoded in the Go module path.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/larryf1/jwtoken-tester/v2/internal/releaseguard"
)

type summary struct {
	Released bool   `json:"released"`
	Version  string `json:"version"`
	Tag      string `json:"tag"`
}

func main() {
	var (
		version     string
		summaryPath string
		modulePath  string
		goModPath   string
	)
	flag.StringVar(&version, "version", "", "computed release version, for example v2.4.0")
	flag.StringVar(&summaryPath, "summary", "", "Semrel release metadata JSON written by --output-file")
	flag.StringVar(&modulePath, "module", "", "module path override (defaults to the go.mod module directive)")
	flag.StringVar(&goModPath, "go-mod", "go.mod", "path to go.mod")
	flag.Parse()

	if version == "" && summaryPath == "" {
		fmt.Fprintln(os.Stderr, "release guard: one of --version or --summary is required")
		flag.Usage()
		os.Exit(2)
	}

	if version == "" {
		computed, released, err := readSummary(summaryPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if !released || computed == "" {
			fmt.Println("release guard: no release candidate; nothing to check")
			return
		}
		version = computed
	}

	if modulePath == "" {
		path, err := releaseguard.ReadModulePath(goModPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		modulePath = path
	}

	if err := releaseguard.Check(modulePath, version); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	major, err := releaseguard.ModuleMajor(modulePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("release guard: %s matches module path %s (major %d)\n", version, modulePath, major)
}

func readSummary(path string) (version string, released bool, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false, fmt.Errorf("release guard: read %s: %w", path, err)
	}
	var meta summary
	if err := json.Unmarshal(data, &meta); err != nil {
		return "", false, fmt.Errorf("release guard: decode %s: %w", path, err)
	}
	if meta.Tag != "" {
		return meta.Tag, meta.Released, nil
	}
	return meta.Version, meta.Released, nil
}
