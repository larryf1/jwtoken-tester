// Package releaseguard keeps a release version's major component in sync with
// the Go module path's /vN suffix.
package releaseguard

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var (
	moduleMajorSuffix = regexp.MustCompile(`/v([0-9]+)$`)
	versionPattern    = regexp.MustCompile(`^v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:[-+][0-9A-Za-z.-]+)?$`)
)

// ModuleMajor returns the major version encoded by a module path. A final
// /vN segment selects N; any other path is major 1.
func ModuleMajor(modulePath string) (int, error) {
	path := strings.TrimSpace(modulePath)
	if path == "" {
		return 0, errors.New("release guard: module path is empty")
	}
	path = strings.TrimSuffix(path, "/")

	if match := moduleMajorSuffix.FindStringSubmatch(path); match != nil {
		major, err := strconv.Atoi(match[1])
		if err != nil {
			return 0, fmt.Errorf("release guard: module path %q has an invalid major: %w", modulePath, err)
		}
		if major < 1 {
			return 0, fmt.Errorf("release guard: module path %q has invalid major v%d", modulePath, major)
		}
		return major, nil
	}
	return 1, nil
}

// VersionMajor returns the major component of a semantic version. The leading
// "v" is optional so both tag and plain version forms are accepted.
func VersionMajor(version string) (int, error) {
	match := versionPattern.FindStringSubmatch(strings.TrimSpace(version))
	if match == nil {
		return 0, fmt.Errorf("release guard: invalid release version %q: want vMAJOR.MINOR.PATCH", version)
	}
	major, err := strconv.Atoi(match[1])
	if err != nil {
		return 0, fmt.Errorf("release guard: invalid release version %q: %w", version, err)
	}
	return major, nil
}

// Check fails when version's major does not match the major required by
// modulePath. The returned error names the module path to migrate to.
func Check(modulePath, version string) error {
	want, err := ModuleMajor(modulePath)
	if err != nil {
		return err
	}
	got, err := VersionMajor(version)
	if err != nil {
		return err
	}
	if got == want {
		return nil
	}
	return fmt.Errorf(
		"release guard: computed version %s has major %d, but module path %q requires major %d; "+
			"change the module path to %q and rewrite all imports before releasing %s",
		version, got, modulePath, want, targetModulePath(modulePath, got), version,
	)
}

// ParseModulePath extracts the module directive from go.mod contents.
func ParseModulePath(goMod []byte) (string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(goMod))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "module ") {
			continue
		}
		fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, "module")))
		if len(fields) == 0 {
			continue
		}
		path := fields[0]
		if strings.HasPrefix(path, `"`) {
			unquoted, err := strconv.Unquote(path)
			if err != nil {
				return "", fmt.Errorf("release guard: parse module directive %q: %w", line, err)
			}
			path = unquoted
		}
		return path, nil
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("release guard: read go.mod: %w", err)
	}
	return "", errors.New("release guard: go.mod has no module directive")
}

// ReadModulePath reads the module directive from the go.mod file at path.
func ReadModulePath(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("release guard: read %s: %w", path, err)
	}
	return ParseModulePath(data)
}

func targetModulePath(modulePath string, major int) string {
	base := strings.TrimSuffix(modulePath, "/")
	if loc := moduleMajorSuffix.FindStringIndex(base); loc != nil {
		base = base[:loc[0]]
	}
	if major >= 2 {
		return fmt.Sprintf("%s/v%d", base, major)
	}
	return base
}
