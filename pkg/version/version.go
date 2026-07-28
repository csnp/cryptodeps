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

const (
	// devVersion is what an un-injected build reports. It matches the default
	// in main so a plain `go build` is honest about not being a release.
	devVersion = "dev"
	unknown    = "unknown"
	noCommit   = "none"
)

var (
	version = devVersion
	commit  = noCommit
	date    = unknown
)

// Set records the build identity. main calls this once at startup with the
// values the linker injected. Empty arguments are ignored so that a build
// without -X keeps the honest defaults rather than reporting empty strings.
func Set(v, c, d string) {
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

// InformationURI is the tool's home, reported in SARIF.
const InformationURI = "https://github.com/csnp/qramm-cryptodeps"

// Vendor is the publishing organisation, reported in CBOM.
const Vendor = "CSNP"
