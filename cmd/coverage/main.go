package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: coverage <profile.out> [--threshold=N]")
		os.Exit(1)
	}

	profilePath := os.Args[1]
	threshold := 90.0
	for _, arg := range os.Args[2:] {
		if strings.HasPrefix(arg, "--threshold=") {
			val := strings.TrimPrefix(arg, "--threshold=")
			if v, err := strconv.ParseFloat(val, 64); err == nil {
				threshold = v
			}
		}
	}

	cmd := exec.Command("go", "tool", "cover", "-func="+profilePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error running go tool cover: %v\n%s\n", err, string(output))
		os.Exit(1)
	}

	var totalCoverage float64
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "total:") {
			parts := strings.Fields(line)
			for _, p := range parts {
				if strings.HasSuffix(p, "%") {
					val := strings.TrimSuffix(p, "%")
					if v, err := strconv.ParseFloat(val, 64); err == nil {
						totalCoverage = v
					}
				}
			}
			break
		}
	}

	fmt.Printf("Total coverage: %.1f%%\n", totalCoverage)

	hasThreshold := false
	for _, arg := range os.Args[2:] {
		if strings.HasPrefix(arg, "--threshold=") {
			hasThreshold = true
			break
		}
	}

	if hasThreshold {
		if totalCoverage < threshold {
			fmt.Printf("FAIL: Coverage %.1f%% is below threshold %.1f%%\n", totalCoverage, threshold)
			os.Exit(1)
		}
		fmt.Printf("PASS: Coverage %.1f%% meets threshold %.1f%%\n", totalCoverage, threshold)
	}
}
