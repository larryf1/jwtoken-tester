package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v2"
)

const (
	defaultConfigPath = ".semrel.yaml"
	updaterPlugin     = "@semrel/updater-replace"
	versionVariable   = "${nextRelease.version}"
)

type semrelConfig struct {
	Plugins []pluginConfig `yaml:"plugins"`
}

type pluginConfig struct {
	Uses string `yaml:"uses"`
	Args struct {
		Replacements string `yaml:"replacements"`
	} `yaml:"args"`
}

type replacementRule struct {
	Files   string              `yaml:"files"`
	From    string              `yaml:"from"`
	Flags   string              `yaml:"flags"`
	To      string              `yaml:"to"`
	Results []replacementResult `yaml:"results"`
}

type replacementResult struct {
	File            string `yaml:"file"`
	NumMatches      int    `yaml:"numMatches"`
	NumReplacements int    `yaml:"numReplacements"`
}

func main() {
	if err := validateConfig(defaultConfigPath, "."); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println("Semrel updater rules match the current version files.")
}

func validateConfig(configPath, root string) error {
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read Semrel config: %w", err)
	}

	var config semrelConfig
	if err := yaml.Unmarshal(configData, &config); err != nil {
		return fmt.Errorf("parse Semrel config: %w", err)
	}

	var replacements string
	for _, plugin := range config.Plugins {
		if plugin.Uses == updaterPlugin {
			if replacements != "" {
				return fmt.Errorf("semrel config contains multiple %s plugins", updaterPlugin)
			}
			replacements = plugin.Args.Replacements
		}
	}
	if strings.TrimSpace(replacements) == "" {
		return fmt.Errorf("semrel config has no replacements for %s", updaterPlugin)
	}

	var rules []replacementRule
	if err := yaml.Unmarshal([]byte(replacements), &rules); err != nil {
		return fmt.Errorf("parse %s replacements: %w", updaterPlugin, err)
	}
	if len(rules) == 0 {
		return fmt.Errorf("semrel config has no replacement rules")
	}

	return validateRules(rules, root)
}

func validateRules(rules []replacementRule, root string) error {
	for i, rule := range rules {
		if rule.Files == "" {
			return fmt.Errorf("replacement %d has no files pattern", i+1)
		}
		if rule.From == "" {
			return fmt.Errorf("replacement %d has no match pattern", i+1)
		}
		if !strings.Contains(rule.To, versionVariable) {
			return fmt.Errorf("replacement %d does not use %s", i+1, versionVariable)
		}
		if len(rule.Results) == 0 {
			return fmt.Errorf("replacement %d has no expected results", i+1)
		}

		pattern := rule.From
		if rule.Flags != "" {
			if strings.Trim(rule.Flags, "ims") != "" {
				return fmt.Errorf("replacement %d uses unsupported regex flags %q", i+1, rule.Flags)
			}
			pattern = "(?" + rule.Flags + ")" + pattern
		}
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("replacement %d has invalid regex: %w", i+1, err)
		}

		for _, result := range rule.Results {
			if result.File == "" || !filepath.IsLocal(result.File) {
				return fmt.Errorf("replacement %d has an invalid result path %q", i+1, result.File)
			}
			if result.NumMatches < 1 || result.NumReplacements < 1 {
				return fmt.Errorf("replacement target %s must expect at least one match and replacement", result.File)
			}
			if filepath.Clean(result.File) != filepath.Clean(rule.Files) {
				return fmt.Errorf("replacement %d checks %q but targets %q", i+1, result.File, rule.Files)
			}

			filePath := filepath.Join(root, result.File)
			contents, err := os.ReadFile(filePath)
			if err != nil {
				return fmt.Errorf("read replacement target %s: %w", result.File, err)
			}
			matches := len(compiled.FindAllIndex(contents, -1))
			if matches != result.NumMatches {
				return fmt.Errorf("replacement target %s: expected %d matches, found %d", result.File, result.NumMatches, matches)
			}
			if matches != result.NumReplacements {
				return fmt.Errorf("replacement target %s: expected %d replacements, found %d", result.File, result.NumReplacements, matches)
			}
		}
	}

	return nil
}
