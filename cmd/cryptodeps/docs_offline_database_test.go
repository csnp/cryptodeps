// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/csnp/qramm-cryptodeps/internal/database"
	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// offlineProbeAlgorithm is the one algorithm the downloaded copy written by
// writeDownloadedDatabase lists for golang.org/x/crypto. The built-in record
// does not list it, so the algorithms a report gives for the package show
// which of the two records the scan read.
const offlineProbeAlgorithm = "SHA3-512"

// writeDownloadedDatabase writes a database file under home where
// `cryptodeps update` saves the one it downloads, holding a single record:
// golang.org/x/crypto with offlineProbeAlgorithm. It returns the file's path.
func writeDownloadedDatabase(t *testing.T, home string) string {
	t.Helper()
	path := filepath.Join(home, database.CacheDir, database.DatabaseFileName)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(database.RemoteDatabase{
		Version:   "offline-test",
		UpdatedAt: "2026-01-02T00:00:00Z",
		Packages: []types.PackageAnalysis{{
			Package:   "golang.org/x/crypto",
			Version:   "v0.17.0",
			Ecosystem: types.EcosystemGo,
			Crypto: []types.CryptoUsage{{
				Algorithm:   offlineProbeAlgorithm,
				Type:        "hash",
				QuantumRisk: types.RiskSafe,
				Severity:    types.SeverityInfo,
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// offlineScanOf runs `analyze --offline` on project with HOME set to home and
// returns the database the JSON report names and the algorithms it lists for
// golang.org/x/crypto.
func offlineScanOf(t *testing.T, proxy, home, project string) (types.DatabaseInfo, []string) {
	t.Helper()
	stdout, stderr, code := runCLIWithHome(t, proxy, home, "analyze", project, "--offline",
		"--reachability=false", "--format", "json", "--fail-on", "none")
	if code != ExitSuccess {
		t.Fatalf("analyze --offline exited %d, want %d; stderr:\n%s", code, ExitSuccess, stderr)
	}
	var doc struct {
		Database types.DatabaseInfo `json:"database"`
		Projects []struct {
			Dependencies []types.DependencyResult `json:"dependencies"`
		} `json:"projects"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("parsing the JSON report: %v\n%s", err, stdout)
	}
	var algorithms []string
	for _, p := range doc.Projects {
		for _, d := range p.Dependencies {
			if d.Dependency.Name != "golang.org/x/crypto" || d.Analysis == nil {
				continue
			}
			for _, c := range d.Analysis.Crypto {
				algorithms = append(algorithms, c.Algorithm)
			}
		}
	}
	return doc.Database, algorithms
}

// firstLineWithPrefix returns the first line of out that starts with prefix,
// or "" when none does.
func firstLineWithPrefix(out, prefix string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimRight(line, "\r")
		}
	}
	return ""
}

// TestDocsSayOfflineReadsTheDatabaseAlreadyDownloaded covers the 1.3.0
// release notes, which said "Pass `--offline` to use only the database built
// into the binary". --offline stops the download, but a scan with it still
// reads the copy that `cryptodeps update`, or an earlier scan without
// --offline, saved under ~/.cryptodeps, and uses that copy's record for a
// package the built-in database also carries. The README and the Commands
// page say what --offline reads and how to scan with the built-in database
// alone, and the release notes after 1.3.0 correct the sentence.
//
// The command line runs first, and the status line and the report line the
// pages quote are taken from what it printed, so the pages are held to the
// behaviour: when it changes, this test fails until they are rewritten.
func TestDocsSayOfflineReadsTheDatabaseAlreadyDownloaded(t *testing.T) {
	builtIn, ok := database.NewEmbedded().Lookup(types.EcosystemGo, "golang.org/x/crypto", "v0.17.0")
	if !ok {
		t.Fatal("the built-in database has no record for golang.org/x/crypto; pick a package it carries")
	}
	for _, c := range builtIn.Crypto {
		if c.Algorithm == offlineProbeAlgorithm {
			t.Fatalf("the built-in record for golang.org/x/crypto lists %s, so the two records "+
				"cannot be told apart; pick another algorithm", offlineProbeAlgorithm)
		}
	}

	proxy, log := startConnectionLog(t)
	project := t.TempDir()
	writeTestFile(t, project, "go.mod", "module example.com/offline\n\ngo 1.21\n\nrequire golang.org/x/crypto v0.17.0\n")

	// Without --offline and with no copy on the machine, the scan starts the
	// download, and the proxy sees it. That is what makes the zero connections
	// counted under --offline below mean something.
	if _, stderr, code := runCLIWithHome(t, proxy, t.TempDir(), "analyze", project,
		"--reachability=false", "--fail-on", "none"); code != ExitSuccess {
		t.Fatalf("analyze without --offline exited %d, want %d; stderr:\n%s", code, ExitSuccess, stderr)
	}
	if got := log.snapshot(); len(got) == 0 || got[0] != "CONNECT api.github.com:443 HTTP/1.1" {
		t.Fatalf("without --offline and with no downloaded copy, the connections were %q, "+
			"want the database lookup on api.github.com first", got)
	}

	home := t.TempDir()
	cacheFile := writeDownloadedDatabase(t, home)
	before := len(log.snapshot())

	// With the copy in place, --offline reads it, and the copy's record for
	// golang.org/x/crypto is used instead of the built-in one.
	db, algorithms := offlineScanOf(t, proxy, home, project)
	if db.Source != types.DatabaseDownloaded {
		t.Errorf("--offline with a downloaded copy in place read the %q database, want %q",
			db.Source, types.DatabaseDownloaded)
	}
	if strings.Join(algorithms, ",") != offlineProbeAlgorithm {
		t.Errorf("--offline listed %q for golang.org/x/crypto, want only the downloaded record's %s",
			algorithms, offlineProbeAlgorithm)
	}

	// Moved aside, the copy is not read: the scan uses the built-in database
	// alone.
	if err := os.Rename(cacheFile, cacheFile+".bak"); err != nil {
		t.Fatal(err)
	}
	db, algorithms = offlineScanOf(t, proxy, home, project)
	if db.Source != types.DatabaseBuiltIn {
		t.Errorf("--offline with the copy moved aside read the %q database, want %q",
			db.Source, types.DatabaseBuiltIn)
	}
	if len(algorithms) == 0 || strings.Contains(strings.Join(algorithms, ","), offlineProbeAlgorithm) {
		t.Errorf("--offline with the copy moved aside listed %q for golang.org/x/crypto, want the built-in record's",
			algorithms)
	}
	tableOut, stderr, code := runCLIWithHome(t, proxy, home, "analyze", project, "--offline",
		"--reachability=false", "--fail-on", "none")
	if code != ExitSuccess {
		t.Fatalf("analyze --offline exited %d, want %d; stderr:\n%s", code, ExitSuccess, stderr)
	}
	if got := log.snapshot()[before:]; len(got) != 0 {
		t.Errorf("%d connection(s) under --offline, want 0: %q", len(got), got)
	}
	// The line is quoted up to the comma that comes before the number of
	// packages, so a change in the number of built-in records does not fail
	// this test.
	reportLine, _, _ := strings.Cut(firstLineWithPrefix(tableOut, "Database: "), ",")
	if reportLine != "Database: "+types.DatabaseBuiltIn {
		t.Fatalf("the table report's database line reads %q, want it to start %q:\n%s",
			reportLine, "Database: "+types.DatabaseBuiltIn, tableOut)
	}

	statusOut, stderr, code := runCLIWithHome(t, proxy, home, "status")
	if code != ExitSuccess {
		t.Fatalf("status exited %d, want %d; stderr:\n%s", code, ExitSuccess, stderr)
	}
	statusLine := firstLineWithPrefix(statusOut, "Local cache:")
	if statusLine == "" || statusLine == "Local cache:" {
		t.Fatalf("with the copy moved aside, status reads %q, want a line saying there is no copy:\n%s",
			statusLine, statusOut)
	}

	cachePath := "~/" + database.CacheDir + "/" + database.DatabaseFileName
	for _, page := range []struct{ file, heading string }{
		{"README.md", "Scan without network access"},
		{"docs/commands.md", "The database a scan uses"},
	} {
		section := strings.Join(strings.Fields(
			markdownSection(t, readRepoFile(t, page.file), page.file, page.heading)), " ")
		for _, want := range []string{"--offline", cachePath, "move", "delete", statusLine, reportLine} {
			if !strings.Contains(section, want) {
				t.Errorf("%s, section %q, does not say %q", page.file, page.heading, want)
			}
		}
	}

	newer, _, found := strings.Cut(readRepoFile(t, "CHANGELOG.md"), "\n## [1.3.0]")
	if !found {
		t.Fatal("CHANGELOG.md has no 1.3.0 section")
	}
	corrected := false
	for _, entry := range strings.Split(newer, "\n\n") {
		entry = strings.Join(strings.Fields(entry), " ")
		if strings.Contains(entry, "1.3.0") && strings.Contains(entry, "--offline") &&
			strings.Contains(entry, cachePath) && strings.Contains(entry, statusLine) {
			corrected = true
			break
		}
	}
	if !corrected {
		t.Errorf("no entry after the 1.3.0 section of CHANGELOG.md corrects its --offline workaround: "+
			"none names 1.3.0, --offline, %s and %q together", cachePath, statusLine)
	}
}
