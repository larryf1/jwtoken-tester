// openapi-lint extracts the HTTP routes registered in the server code and
// compares them against the paths declared in docs/openapi.yaml. It fails if
// any route exists in only one source, so that a new endpoint added to code
// without a matching OpenAPI entry (or vice versa) is caught early.
//
// Usage:
//
//	go run ./cmd/openapi-lint [server.go] [openapi.yaml]
//
// Defaults: internal/server/server.go and docs/openapi.yaml
package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// route represents a single HTTP method + path pair.
type route struct {
	method string
	path   string
}

func (r route) String() string {
	return r.method + " " + r.path
}

func main() {
	serverFile := "internal/server/server.go"
	openapiFile := "docs/openapi.yaml"

	args := os.Args[1:]
	if len(args) >= 1 {
		serverFile = args[0]
	}
	if len(args) >= 2 {
		openapiFile = args[1]
	}

	codeRoutes, err := extractCodeRoutes(serverFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading %s: %v\n", serverFile, err)
		os.Exit(1)
	}

	specRoutes, err := extractSpecRoutes(openapiFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading %s: %v\n", openapiFile, err)
		os.Exit(1)
	}

	// Build sets for comparison.
	codeSet := make(map[string]route, len(codeRoutes))
	for _, r := range codeRoutes {
		codeSet[r.String()] = r
	}
	specSet := make(map[string]route, len(specRoutes))
	for _, r := range specRoutes {
		specSet[r.String()] = r
	}

	failed := false

	// Routes in code but missing from the spec.
	onlyInCode := make([]string, 0, len(codeRoutes))
	for _, r := range codeRoutes {
		key := r.String()
		if _, ok := specSet[key]; !ok {
			onlyInCode = append(onlyInCode, key)
		}
	}
	sort.Strings(onlyInCode)

	// Routes in the spec but missing from code.
	onlyInSpec := make([]string, 0, len(specRoutes))
	for _, r := range specRoutes {
		key := r.String()
		if _, ok := codeSet[key]; !ok {
			onlyInSpec = append(onlyInSpec, key)
		}
	}
	sort.Strings(onlyInSpec)

	if len(onlyInCode) > 0 {
		fmt.Fprintln(os.Stderr, "routes in code but missing from OpenAPI spec:")
		for _, r := range onlyInCode {
			fmt.Fprintf(os.Stderr, "  - %s\n", r)
		}
		failed = true
	}

	if len(onlyInSpec) > 0 {
		fmt.Fprintln(os.Stderr, "routes in OpenAPI spec but missing from code:")
		for _, r := range onlyInSpec {
			fmt.Fprintf(os.Stderr, "  - %s\n", r)
		}
		failed = true
	}

	if failed {
		fmt.Fprintln(os.Stderr, "\nrun 'go run ./cmd/openapi-lint' to check route sync")
		os.Exit(1)
	}

	fmt.Printf("OpenAPI routes are in sync: %d routes matched.\n", len(codeRoutes))
}

// extractCodeRoutes parses HandleFunc calls in the server source and returns
// the registered method+path pairs. It normalizes Go 1.22+ style routes
// (e.g., "GET /healthz") to OpenAPI-style paths.
func extractCodeRoutes(file string) ([]route, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	// Match lines like: mux.HandleFunc("GET /healthz", s.handleHealth)
	re := regexp.MustCompile(`HandleFunc\(\s*"([A-Z]+)\s+([^"]+)"`)

	var routes []route
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		matches := re.FindStringSubmatch(line)
		if matches == nil {
			continue
		}
		method := matches[1]
		path := matches[2]
		// Normalize Go route patterns to OpenAPI paths:
		// "{$}" -> "" (root path)
		// Go patterns don't use {param} in the same way, but the server code
		// uses trailing slash for param routes like /.well-known/jwks.json/
		// The OpenAPI spec uses /.well-known/jwks.json/{kid}
		// We handle this by stripping trailing slashes that indicate a param.
		path = normalizeCodePath(path)
		routes = append(routes, route{method: strings.ToLower(method), path: path})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return routes, nil
}

// normalizeCodePath converts Go 1.22+ route patterns to OpenAPI-style paths.
func normalizeCodePath(p string) string {
	// "GET /{$}" -> "/"
	if strings.HasSuffix(p, "/{$}") {
		return "/"
	}
	// "GET /" -> "/"
	if p == "/" {
		return "/"
	}
	// Trailing slash in code (e.g., /.well-known/jwks.json/) indicates a path
	// parameter in OpenAPI (/.well-known/jwks.json/{kid}). We need to map this.
	// The mapping is file-specific, so we hard-code the known param routes.
	paramRoutes := map[string]string{
		"/.well-known/jwks.json/": "/.well-known/jwks.json/{kid}",
	}
	if openAPIPath, ok := paramRoutes[p]; ok {
		return openAPIPath
	}
	return p
}

// extractSpecRoutes parses the OpenAPI YAML and extracts method+path pairs.
// It uses a simple line-based parser rather than a full YAML library to avoid
// adding a dependency.
func extractSpecRoutes(file string) ([]route, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	// HTTP methods that appear as operation objects in OpenAPI.
	operations := map[string]bool{
		"get": true, "post": true, "put": true, "delete": true,
		"patch": true, "head": true, "options": true,
	}

	var routes []route
	var currentPath string
	inPaths := false

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Detect the paths: section.
		if trimmed == "paths:" {
			inPaths = true
			currentPath = ""
			continue
		}

		// If we're in the paths section, look for path definitions.
		// A path is a top-level key under paths: (2-space indent).
		if inPaths {
			// End of paths section: another top-level key (no indent).
			if trimmed != "" && !strings.HasPrefix(line, " ") {
				inPaths = false
				continue
			}

			// Path definition: exactly 2-space indent, ends with ":"
			if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") {
				trimmed := strings.TrimSpace(line)
				if strings.HasSuffix(trimmed, ":") {
					currentPath = strings.TrimSuffix(trimmed, ":")
					continue
				}
			}

			// Operation method: 4-space indent, lowercase method name.
			if strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "      ") && currentPath != "" {
				method := strings.TrimSuffix(trimmed, ":")
				if operations[method] {
					routes = append(routes, route{method: method, path: currentPath})
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return routes, nil
}
