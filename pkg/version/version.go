// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

// Package version holds the single source of truth for the running build's
// identity.
//
// GoReleaser injects the real values into main via -X main.version, so main is
// the only place that learns them from the linker. Every other package reads
// them from here. Before this existed each output format carried its own
// literal, and they drifted: a 1.3.0 binary emitted SARIF claiming 1.0.0, a CBOM
// claiming 1.0.0 and JSON claiming nothing at all. SARIF and CBOM are provenance
// artifacts, so a stale literal there is a false provenance record, not a
// cosmetic bug.
package version

import (
	"runtime/debug"
	"strings"
)

const (
	// devVersion is what a build reports when neither -ldflags nor a module
	// the go command downloaded gives it a version. It matches the default in
	// main, so a plain `go build` in a checkout is honest about not being a
	// release.
	devVersion = "dev"
	unknown    = "unknown"
	noCommit   = "none"

	// modulePath is this module's path as go.mod declares it. The repository
	// was renamed to cryptodeps and the module path was kept.
	modulePath = "github.com/csnp/qramm-cryptodeps"
)

var (
	version = devVersion
	commit  = noCommit
	date    = unknown
)

// readBuildInfo reads what the go command recorded in the running binary.
// Tests replace it.
var readBuildInfo = debug.ReadBuildInfo

// Set records the build identity. main calls this once at startup with the
// values the linker injected. Empty arguments are ignored so that a build
// without -X keeps the honest defaults rather than reporting empty strings.
//
// A version the linker did not inject, empty or main's default "dev", is
// taken from moduleVersion when it finds one. go install passes no -ldflags,
// so this is what makes a binary built by
// `go install github.com/csnp/qramm-cryptodeps/cmd/cryptodeps@vX.Y.Z` report
// X.Y.Z rather than dev.
func Set(v, c, d string) {
	if v == "" || v == devVersion {
		if recorded := moduleVersion(readBuildInfo()); recorded != "" {
			v = recorded
		}
	}
	if v != "" {
		version = v
	}
	if c != "" {
		commit = c
	}
	if d != "" {
		date = d
	}
}

// moduleVersion returns the version of this module recorded in the build
// information, without its leading "v", when the go command built the binary
// from a downloaded copy of the module, as go install does for a module
// version and go tool does for a module version that go.mod requires. Both
// record the module that holds the main package with its version and
// checksum. moduleVersion returns "" when that module carries no checksum,
// as in a `go build` of a git checkout, whose recorded version describes the
// checkout rather than a published version; when a replace directive swapped
// the module out; and when the build information is missing or the main
// package is in another module.
func moduleVersion(info *debug.BuildInfo, ok bool) string {
	if !ok || info == nil {
		return ""
	}
	m := info.Main
	if m.Path != modulePath || m.Replace != nil || m.Sum == "" || m.Version == "" || m.Version == "(devel)" {
		return ""
	}
	return strings.TrimPrefix(m.Version, "v")
}

// Version returns the tool version, for example "1.3.0" for a release build or
// "dev" for a local one.
func Version() string { return version }

// Commit returns the commit the binary was built from.
func Commit() string { return commit }

// Date returns the build date.
func Date() string { return date }

// Name is the tool name reported in machine-readable output. It is lower case
// to match the binary and the purl/package identity, not the display name.
const Name = "cryptodeps"

// DisplayName is the tool name for human-facing and SARIF driver use.
const DisplayName = "CryptoDeps"

// InformationURI is the tool's home, reported in SARIF and in the markdown
// footer. The repository was renamed from qramm-cryptodeps to cryptodeps, and
// the database download comes from releases under the new name, so this names
// it too. The Go module path keeps the old name.
const InformationURI = "https://github.com/csnp/cryptodeps"

// Vendor is the publishing organisation, reported in CBOM.
const Vendor = "CSNP"
