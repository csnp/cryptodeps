// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package version

import (
	"bufio"
	"os"
	"runtime/debug"
	"strings"
	"testing"
)

// notARealChecksum stands in for the h1: checksum the go command records
// beside a module it downloaded. Only its presence matters here.
const notARealChecksum = "h1:not-a-real-checksum"

// withBuildInfo makes readBuildInfo return info, starts from the defaults main
// passes for a build without -ldflags, and restores everything when the test
// ends. A nil info is a binary with no build information.
func withBuildInfo(t *testing.T, info *debug.BuildInfo) {
	t.Helper()
	savedRead, savedVersion, savedCommit, savedDate := readBuildInfo, version, commit, date
	readBuildInfo = func() (*debug.BuildInfo, bool) { return info, info != nil }
	version, commit, date = devVersion, noCommit, unknown
	t.Cleanup(func() {
		readBuildInfo = savedRead
		version, commit, date = savedVersion, savedCommit, savedDate
	})
}

// installed is the build information of a binary that the go command built
// from a module it downloaded. `go version -m` on the binary that
// `go install github.com/csnp/qramm-cryptodeps/cmd/cryptodeps@latest` built
// (v1.3.1) prints its module line as
// "mod github.com/csnp/qramm-cryptodeps v1.3.1 h1:...", with no vcs lines.
// A build through go tool, in a module whose go.mod requires this one, has
// a module line of the same form.
func installed(moduleVersion string) *debug.BuildInfo {
	return &debug.BuildInfo{
		Path: modulePath + "/cmd/cryptodeps",
		Main: debug.Module{Path: modulePath, Version: moduleVersion, Sum: notARealChecksum},
	}
}

// TestSetReportsTheModuleVersionTheGoCommandRecorded is the regression test
// for a `go install` binary reporting its version as dev. go install passes
// no -ldflags, so main hands Set its defaults, and a v1.3.1 binary built that
// way reported dev in the version command and in JSON, SARIF and CBOM output,
// although its build information records v1.3.1.
func TestSetReportsTheModuleVersionTheGoCommandRecorded(t *testing.T) {
	tests := []struct {
		name string
		info *debug.BuildInfo
		want string
	}{
		{
			name: "go install at a release tag",
			info: installed("v1.3.1"),
			want: "1.3.1",
		},
		{
			// What `go install ...@09d9c66`, a commit after v1.3.1, records.
			name: "go install at a commit",
			info: installed("v1.3.2-0.20261017190020-09d9c66085f5"),
			want: "1.3.2-0.20261017190020-09d9c66085f5",
		},
	}
	for _, tt := range tests {
		// "dev" is main's default, and "" is what -X main.version= leaves.
		for _, injected := range []string{devVersion, ""} {
			t.Run(tt.name+"/injected "+injected, func(t *testing.T) {
				withBuildInfo(t, tt.info)
				Set(injected, noCommit, unknown)
				if got := Version(); got != tt.want {
					t.Errorf("Version() = %q, want %q", got, tt.want)
				}
			})
		}
	}
}

// TestSetKeepsDevWithoutADownloadedModuleVersion covers the builds whose
// recorded version is not a published version of this module. They keep dev
// rather than a version the build does not stand for.
func TestSetKeepsDevWithoutADownloadedModuleVersion(t *testing.T) {
	tests := []struct {
		name string
		info *debug.BuildInfo
	}{
		{
			// go1.26.3 recorded this for `go build ./cmd/cryptodeps` in a git
			// checkout: a version derived from the git state, +dirty beside
			// vcs.modified=true, and no checksum.
			name: "go build in a git checkout",
			info: &debug.BuildInfo{
				Path: modulePath + "/cmd/cryptodeps",
				Main: debug.Module{Path: modulePath, Version: "v1.3.1-0.20261005091433-0e9d8ff098eb+dirty"},
				Settings: []debug.BuildSetting{
					{Key: "vcs", Value: "git"},
					{Key: "vcs.revision", Value: "0e9d8ff098ebbafac96a3045ca4e55b92c494f1c"},
					{Key: "vcs.modified", Value: "true"},
				},
			},
		},
		{
			// What `go build -buildvcs=false ./cmd/cryptodeps` records.
			name: "go build with no version recorded",
			info: &debug.BuildInfo{
				Path: modulePath + "/cmd/cryptodeps",
				Main: debug.Module{Path: modulePath, Version: "(devel)"},
			},
		},
		{
			// A replace directive in the go.mod of a module that runs this
			// one through go tool. Replaced by a local directory, the module
			// is recorded with no checksum and the replacement as (devel).
			name: "replaced by a local directory",
			info: &debug.BuildInfo{
				Path: modulePath + "/cmd/cryptodeps",
				Main: debug.Module{
					Path: modulePath, Version: "v1.3.1",
					Replace: &debug.Module{Path: "../cryptodeps", Version: "(devel)"},
				},
			},
		},
		{
			// Replaced by another module's version, the version recorded for
			// this module is not the code that was built, whether or not a
			// checksum is recorded beside it.
			name: "replaced by another module",
			info: &debug.BuildInfo{
				Path: modulePath + "/cmd/cryptodeps",
				Main: debug.Module{
					Path: modulePath, Version: "v1.3.1", Sum: notARealChecksum,
					Replace: &debug.Module{Path: "example.com/fork/cryptodeps", Version: "v1.3.2", Sum: notARealChecksum},
				},
			},
		},
		{
			name: "another module's binary",
			info: &debug.BuildInfo{
				Path: "example.com/other/cmd/other",
				Main: debug.Module{Path: "example.com/other", Version: "v2.0.0", Sum: notARealChecksum},
			},
		},
		{
			name: "no build information",
			info: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withBuildInfo(t, tt.info)
			Set(devVersion, noCommit, unknown)
			if got := Version(); got != devVersion {
				t.Errorf("Version() = %q, want %q", got, devVersion)
			}
		})
	}
}

// TestSetPrefersTheInjectedIdentity covers the release archives and make
// build, which inject the version through -ldflags: what they inject is
// reported even when the binary also records a module version.
func TestSetPrefersTheInjectedIdentity(t *testing.T) {
	withBuildInfo(t, installed("v1.3.1"))
	Set("1.4.0", "abc1234", "2026-10-18T00:00:00Z")
	if got := Version(); got != "1.4.0" {
		t.Errorf("Version() = %q, want the injected 1.4.0", got)
	}
	if got := Commit(); got != "abc1234" {
		t.Errorf("Commit() = %q, want the injected abc1234", got)
	}
	if got := Date(); got != "2026-10-18T00:00:00Z" {
		t.Errorf("Date() = %q, want the injected 2026-10-18T00:00:00Z", got)
	}
}

// TestModulePathIsTheModuleGoModDeclares keeps modulePath in step with
// go.mod. If they differed, no build would find its own module in the build
// information and every go install binary would report dev again.
func TestModulePathIsTheModuleGoModDeclares(t *testing.T) {
	f, err := os.Open("../../go.mod")
	if err != nil {
		t.Fatalf("open go.mod: %v", err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if rest, ok := strings.CutPrefix(scanner.Text(), "module "); ok {
			if got := strings.TrimSpace(rest); got != modulePath {
				t.Errorf("go.mod declares module %q, modulePath is %q", got, modulePath)
			}
			return
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	t.Fatal("go.mod has no module line")
}
