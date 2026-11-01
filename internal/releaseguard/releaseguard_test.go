package releaseguard

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestModuleMajor(t *testing.T) {
	tests := []struct {
		name       string
		modulePath string
		want       int
		wantErr    bool
	}{
		{name: "v2 suffix", modulePath: "github.com/larryf1/jwtoken-tester/v2", want: 2},
		{name: "multi-digit suffix", modulePath: "example.com/service/v10", want: 10},
		{name: "unsuffixed", modulePath: "github.com/larryf1/jwtoken-tester", want: 1},
		{name: "v2 not final segment", modulePath: "example.com/foo/v2/bar", want: 1},
		{name: "trailing slash", modulePath: "example.com/service/v2/", want: 2},
		{name: "empty", modulePath: "", wantErr: true},
		{name: "invalid v0", modulePath: "example.com/service/v0", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ModuleMajor(tt.modulePath)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ModuleMajor(%q) error = nil, want error", tt.modulePath)
				}
				return
			}
			if err != nil {
				t.Fatalf("ModuleMajor(%q) error = %v", tt.modulePath, err)
			}
			if got != tt.want {
				t.Fatalf("ModuleMajor(%q) = %d, want %d", tt.modulePath, got, tt.want)
			}
		})
	}
}

func TestVersionMajor(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    int
		wantErr bool
	}{
		{name: "tag form", version: "v2.4.0", want: 2},
		{name: "plain form", version: "2.4.0", want: 2},
		{name: "major three", version: "v3.0.0", want: 3},
		{name: "prerelease", version: "v2.4.0-rc.1", want: 2},
		{name: "build metadata", version: "v2.4.0+build.5", want: 2},
		{name: "missing patch", version: "v2.4", wantErr: true},
		{name: "only major", version: "2", wantErr: true},
		{name: "empty", version: "", wantErr: true},
		{name: "double v", version: "vv2.4.0", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := VersionMajor(tt.version)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("VersionMajor(%q) error = nil, want error", tt.version)
				}
				return
			}
			if err != nil {
				t.Fatalf("VersionMajor(%q) error = %v", tt.version, err)
			}
			if got != tt.want {
				t.Fatalf("VersionMajor(%q) = %d, want %d", tt.version, got, tt.want)
			}
		})
	}
}

func TestCheck(t *testing.T) {
	tests := []struct {
		name        string
		modulePath  string
		version     string
		wantErr     bool
		wantMessage []string
	}{
		{
			name:       "v2 matches",
			modulePath: "github.com/larryf1/jwtoken-tester/v2",
			version:    "v2.4.0",
		},
		{
			name:       "v2 matches plain version",
			modulePath: "github.com/larryf1/jwtoken-tester/v2",
			version:    "2.4.0",
		},
		{
			name:        "v2 rejects v3",
			modulePath:  "github.com/larryf1/jwtoken-tester/v2",
			version:     "v3.0.0",
			wantErr:     true,
			wantMessage: []string{"major 3", "requires major 2", "github.com/larryf1/jwtoken-tester/v3", "rewrite all imports"},
		},
		{
			name:       "unsuffixed matches v1",
			modulePath: "github.com/larryf1/jwtoken-tester",
			version:    "v1.5.0",
		},
		{
			name:        "unsuffixed rejects v2",
			modulePath:  "github.com/larryf1/jwtoken-tester",
			version:     "v2.0.0",
			wantErr:     true,
			wantMessage: []string{"major 2", "requires major 1", "github.com/larryf1/jwtoken-tester/v2"},
		},
		{
			name:       "invalid version",
			modulePath: "github.com/larryf1/jwtoken-tester/v2",
			version:    "next",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Check(tt.modulePath, tt.version)
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("Check(%q, %q) error = %v", tt.modulePath, tt.version, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Check(%q, %q) error = nil, want error", tt.modulePath, tt.version)
			}
			for _, want := range tt.wantMessage {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("Check(%q, %q) error = %q, want it to contain %q", tt.modulePath, tt.version, err, want)
				}
			}
		})
	}
}

func TestParseModulePath(t *testing.T) {
	tests := []struct {
		name    string
		goMod   string
		want    string
		wantErr bool
	}{
		{
			name:  "plain directive",
			goMod: "module github.com/larryf1/jwtoken-tester/v2\n\ngo 1.27\n",
			want:  "github.com/larryf1/jwtoken-tester/v2",
		},
		{
			name:  "comment before directive",
			goMod: "// generated\nmodule example.com/service\n",
			want:  "example.com/service",
		},
		{
			name:  "quoted directive",
			goMod: "module \"example.com/service/v2\"\n",
			want:  "example.com/service/v2",
		},
		{name: "missing directive", goMod: "go 1.27\n", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseModulePath([]byte(tt.goMod))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseModulePath() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseModulePath() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("ParseModulePath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRepositoryModuleMatchesGoList(t *testing.T) {
	root := filepath.Join("..", "..")
	declared, err := ReadModulePath(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("ReadModulePath() error = %v", err)
	}

	cmd := exec.Command("go", "list", "-m", "-f", "{{.Path}}")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -m: %v", err)
	}
	listed := strings.TrimSpace(string(out))
	if declared != listed {
		t.Fatalf("go.mod module = %q, go list -m = %q, want agreement", declared, listed)
	}

	major, err := ModuleMajor(declared)
	if err != nil {
		t.Fatalf("ModuleMajor(%q) error = %v", declared, err)
	}
	if major != 2 {
		t.Fatalf("module %q major = %d, want 2", declared, major)
	}
}
