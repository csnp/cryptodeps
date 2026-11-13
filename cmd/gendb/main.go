// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

// Command gendb generates a JSON database file from the embedded database
// and optionally fetches additional packages from package registries.
//
// Usage:
//
//	go run cmd/gendb/main.go > data/crypto-database.json           # curated only
//	go run cmd/gendb/main.go --fetch > data/crypto-database.json   # curated + registry
//
// Every record names this generator and its version. Run in a git checkout of
// this repository, the version is what git describe reports for the checkout;
// elsewhere, pass it with --tool-version. When neither gives a version, the
// generator exits with an error and writes no database.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/csnp/qramm-cryptodeps/internal/database"
	"github.com/csnp/qramm-cryptodeps/internal/netguard"
	"github.com/csnp/qramm-cryptodeps/internal/registry"
	"github.com/csnp/qramm-cryptodeps/pkg/types"
	"github.com/csnp/qramm-cryptodeps/pkg/version"
)

// DatabaseExport is the format for the exported database.
type DatabaseExport struct {
	Version   string                  `json:"version"`
	UpdatedAt string                  `json:"updatedAt"`
	Stats     DatabaseStats           `json:"stats"`
	Packages  []types.PackageAnalysis `json:"packages"`
}

// DatabaseStats contains statistics about the database.
type DatabaseStats struct {
	TotalPackages    int                      `json:"totalPackages"`
	VerifiedPackages int                      `json:"verifiedPackages"`
	InferredPackages int                      `json:"inferredPackages"`
	ByEcosystem      map[types.Ecosystem]int  `json:"byEcosystem"`
	ByConfidence     map[types.Confidence]int `json:"byConfidence"`
}

var (
	fetchFlag       = flag.Bool("fetch", false, "Fetch additional packages from registries")
	timeoutFlag     = flag.Duration("timeout", 2*time.Minute, "Timeout for registry fetches")
	toolVersionFlag = flag.String("tool-version", "", "Version every record names as its generator (default: git describe of the checkout)")
)

func main() {
	flag.Parse()

	// Settled before any record is made, and set as this process's version so
	// that the records inferred from the registries, which take the running
	// version, name it too. The Makefile and the update workflow run this with
	// `go run` and no -X linker flag, which leaves the running version at
	// "dev".
	toolVersion, err := generatorVersion(*toolVersionFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	version.Set(toolVersion, "", "")

	var packages []types.PackageAnalysis
	var stats DatabaseStats

	if *fetchFlag {
		// Fetch from registries and merge with curated data
		packages, stats = fetchAndMerge()
	} else {
		// Curated only
		packages, stats = curatedOnly()
	}
	nameGenerator(packages, toolVersion)

	// Sort by ecosystem then package name for consistent output
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Ecosystem != packages[j].Ecosystem {
			return packages[i].Ecosystem < packages[j].Ecosystem
		}
		return packages[i].Package < packages[j].Package
	})

	export := DatabaseExport{
		Version:   "1.1.0",
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Stats:     stats,
		Packages:  packages,
	}

	// Stats to stderr
	fmt.Fprintf(os.Stderr, "CryptoDeps Database Export:\n")
	fmt.Fprintf(os.Stderr, "  Total packages: %d\n", stats.TotalPackages)
	fmt.Fprintf(os.Stderr, "  Verified: %d\n", stats.VerifiedPackages)
	fmt.Fprintf(os.Stderr, "  Inferred: %d\n", stats.InferredPackages)
	fmt.Fprintf(os.Stderr, "  By ecosystem:\n")
	// Sorted, for the same reason the status command is: ranging over the map
	// printed the ecosystems in a different order on almost every run.
	ecosystems := make([]string, 0, len(stats.ByEcosystem))
	for eco := range stats.ByEcosystem {
		ecosystems = append(ecosystems, string(eco))
	}
	sort.Strings(ecosystems)
	for _, eco := range ecosystems {
		fmt.Fprintf(os.Stderr, "    %s: %d\n", eco, stats.ByEcosystem[types.Ecosystem(eco)])
	}

	// Marshal and output to stdout
	output, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(output))
}

func curatedOnly() ([]types.PackageAnalysis, DatabaseStats) {
	db := database.NewEmbedded()
	packages := db.ExportAll()

	// Mark all as verified
	for i := range packages {
		for j := range packages[i].Crypto {
			packages[i].Crypto[j].Confidence = types.ConfidenceVerified
		}
	}

	stats := DatabaseStats{
		TotalPackages:    len(packages),
		VerifiedPackages: len(packages),
		InferredPackages: 0,
		ByEcosystem:      make(map[types.Ecosystem]int),
		ByConfidence:     make(map[types.Confidence]int),
	}

	for _, pkg := range packages {
		stats.ByEcosystem[pkg.Ecosystem]++
	}
	stats.ByConfidence[types.ConfidenceVerified] = len(packages)

	return packages, stats
}

func fetchAndMerge() ([]types.PackageAnalysis, DatabaseStats) {
	ctx, cancel := context.WithTimeout(context.Background(), *timeoutFlag)
	defer cancel()

	fmt.Fprintf(os.Stderr, "Fetching packages from registries (timeout: %s)...\n", *timeoutFlag)

	merger := registry.NewMerger()
	result, err := merger.Merge(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: merge error: %v\n", err)
	}

	// Log any registry errors
	for _, e := range result.Errors {
		fmt.Fprintf(os.Stderr, "Warning: %v\n", e)
	}

	stats := DatabaseStats{
		TotalPackages:    result.Stats.TotalPackages,
		VerifiedPackages: result.Stats.CuratedPackages,
		InferredPackages: result.Stats.InferredPackages,
		ByEcosystem:      make(map[types.Ecosystem]int),
		ByConfidence:     make(map[types.Confidence]int),
	}

	// Count by ecosystem
	for eco, count := range result.Stats.ByEcosystem {
		stats.ByEcosystem[eco] = count
	}

	// Count by confidence
	for _, pkg := range result.Packages {
		for _, crypto := range pkg.Crypto {
			stats.ByConfidence[crypto.Confidence]++
		}
	}

	fmt.Fprintf(os.Stderr, "Fetched %d new packages from registries\n", result.Stats.NewPackages)

	return result.Packages, stats
}

// nameGenerator records on every package that this generator, at toolVersion,
// wrote it into the database. The curated records set no version of their own,
// and were written out with "toolVersion": "" beside "tool": "cryptodeps".
func nameGenerator(packages []types.PackageAnalysis, toolVersion string) {
	for i := range packages {
		packages[i].Analysis.Tool = version.Name
		packages[i].Analysis.ToolVersion = toolVersion
	}
}

// devVersion is what pkg/version reports when no version was set. It names no
// release and no commit, so no record is written with it.
const devVersion = "dev"

// generatorVersion returns the version every record names as its generator:
// given, used as given when it is not empty, and otherwise what git describe
// reports for the checkout in the current directory.
func generatorVersion(given string) (string, error) {
	if v := strings.TrimSpace(given); v != "" {
		if v == devVersion {
			return "", fmt.Errorf("--tool-version %q names no release and no commit; pass the version of the source being run, or leave the flag out to read it from git", v)
		}
		return v, nil
	}
	v, err := describeCheckout()
	if err != nil {
		return "", fmt.Errorf("cannot tell which version of the generator is running, so no record could name it (%v); run it in a git checkout of cryptodeps, or pass --tool-version", err)
	}
	return v, nil
}

// describeCheckout returns git describe of the checkout, matched against the
// release tags only and without their leading "v": "1.4.0" on the commit
// tagged v1.4.0, "1.4.0-3-g" and the abbreviated commit three commits after
// it, or the abbreviated commit alone when no release tag is reachable. The
// database release tags (db-v...) name no version of this code, and an
// unrestricted git describe picks them first.
//
// "-dirty" is added when a Go file, go.mod or go.sum differs from that commit,
// tracked or not, since the commit named did not produce such a database. Other
// files are left out of the comparison: the Makefile and the update workflow
// write the database into a tracked file through a shell redirect, which
// empties it before this runs, so git describe --dirty would mark every run.
func describeCheckout() (string, error) {
	described, err := gitOutput("describe", "--tags", "--match", "v[0-9]*", "--always")
	if err != nil {
		return "", err
	}
	v := strings.TrimPrefix(described, "v")

	changed, err := gitOutput("status", "--porcelain", "--untracked-files=all", "--",
		":(top)*.go", ":(top)go.mod", ":(top)go.sum")
	if err != nil {
		return "", err
	}
	if changed != "" {
		v += "-dirty"
	}
	return v, nil
}

// gitOutput runs git in the current directory and returns what it printed,
// trimmed, or an error carrying what it wrote on stderr.
//
// git describe and git status read the local repository. They are started
// through netguard because every program this module runs, other than tar and
// unzip, is started there; TestNetworkUseGoesThroughNetguard holds that.
func gitOutput(args ...string) (string, error) {
	cmd, err := netguard.Command("git", args...)
	if err != nil {
		return "", err
	}
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			return "", fmt.Errorf("git %s: %s", args[0], strings.TrimSpace(string(exitErr.Stderr)))
		}
		return "", fmt.Errorf("git %s: %w", args[0], err)
	}
	return strings.TrimSpace(string(out)), nil
}
