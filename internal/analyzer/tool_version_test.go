// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/csnp/qramm-cryptodeps/internal/database"
	"github.com/csnp/qramm-cryptodeps/pkg/output"
	"github.com/csnp/qramm-cryptodeps/pkg/types"
	"github.com/csnp/qramm-cryptodeps/pkg/version"
)

// scannerVersion is the version the tests give this process, as main does with
// the version a release build is linked with. It is not "dev", so that a
// record's own "dev" cannot pass for it.
const scannerVersion = "9.9.9-scanner"

// setScannerVersion sets the version this process reports for the length of
// the test.
func setScannerVersion(t *testing.T) {
	t.Helper()
	previous := version.Version()
	version.Set(scannerVersion, "", "")
	t.Cleanup(func() { version.Set(previous, "", "") })
}

// downloadedDatabase is a database file shaped like the one the update workflow
// publishes: an inferred record that its generator, run without a version,
// wrote with "toolVersion": "dev", and a curated record written with an empty
// version.
const downloadedDatabase = `{"version":"1.1.0","updatedAt":"2026-11-09T09:06:25Z","packages":[
	{"package":"fixture-inferred","version":"","ecosystem":"npm",
	 "analysis":{"date":"2026-11-09T09:06:25Z","method":"inferred","tool":"cryptodeps","toolVersion":"dev"},
	 "crypto":[{"algorithm":"RSA","type":"signature","quantumRisk":"VULNERABLE","severity":"HIGH","location":{"file":"","line":0},"confidence":"medium"}],
	 "quantumSummary":{"vulnerable":1,"partial":0,"safe":0,"unknown":0}},
	{"package":"fixture-curated","version":"","ecosystem":"npm",
	 "analysis":{"date":"2026-11-09T09:05:25Z","method":"verified","tool":"cryptodeps","toolVersion":""},
	 "crypto":[{"algorithm":"ECDSA","type":"signature","quantumRisk":"VULNERABLE","severity":"HIGH","location":{"file":"","line":0},"confidence":"verified"}],
	 "quantumSummary":{"vulnerable":1,"partial":0,"safe":0,"unknown":0}}
]}`

// TestDatabaseRecordsNameTheScannerThatWroteTheReport is the regression test
// for issue #34 on the database path.
//
// Each dependency's analysis block in a JSON report carried the tool and
// version its database record was written with, beside the report's own
// top-level tool: "dev" for an inferred record of the downloaded database, and
// an empty version for a curated record of that database and for a record of
// the built-in one. The block now names the scanner that wrote the report.
func TestDatabaseRecordsNameTheScannerThatWroteTheReport(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, database.CacheDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, database.CacheDir, database.DatabaseFileName),
		[]byte(downloadedDatabase), 0o644); err != nil {
		t.Fatal(err)
	}

	project := t.TempDir()
	manifest := `{"name":"fixture","version":"1.0.0","dependencies":{` +
		`"fixture-inferred":"1.0.0","fixture-curated":"2.0.0","node-forge":"1.3.1"}}`
	if err := os.WriteFile(filepath.Join(project, "package.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}

	setScannerVersion(t)
	db := database.NewWithCachedData()
	if got := db.Info().Source; got != types.DatabaseDownloaded {
		t.Fatalf("database source = %q, want %q: the fixture database was not loaded", got, types.DatabaseDownloaded)
	}

	result, err := New(db, Options{Offline: true}).Analyze(project)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	// The record each dependency is read from, and the version it was written
	// with. node-forge is not in the downloaded fixture, so it comes from the
	// built-in records, none of which sets a version.
	wantRecord := map[string]struct{ method, toolVersion string }{
		"fixture-inferred": {"inferred", "dev"},
		"fixture-curated":  {"verified", ""},
		"node-forge":       {"embedded", ""},
	}
	if len(result.Dependencies) != len(wantRecord) {
		t.Fatalf("got %d dependencies, want %d: %+v", len(result.Dependencies), len(wantRecord), result.Dependencies)
	}
	for _, dep := range result.Dependencies {
		want, ok := wantRecord[dep.Dependency.Name]
		if !ok {
			t.Fatalf("unexpected dependency %q", dep.Dependency.Name)
		}
		if !dep.InDatabase || dep.Analysis == nil {
			t.Fatalf("%s was not read from the database: %+v", dep.Dependency.Name, dep)
		}
		if dep.Analysis.Analysis.Method != want.method {
			t.Fatalf("%s: method = %q, want %q, so the record under test is not the one this test wrote",
				dep.Dependency.Name, dep.Analysis.Analysis.Method, want.method)
		}
		if got := dep.Analysis.Analysis.Tool; got != version.Name {
			t.Errorf("%s: analysis tool = %q, want %q", dep.Dependency.Name, got, version.Name)
		}
		if got := dep.Analysis.Analysis.ToolVersion; got != scannerVersion {
			t.Errorf("%s: analysis toolVersion = %q, want the scanner's %q", dep.Dependency.Name, got, scannerVersion)
		}

		// The database record is left as it was written. Lookup hands the
		// analyzer a copy, and a scan names itself on that copy only.
		record, found := db.Lookup(dep.Dependency.Ecosystem, dep.Dependency.Name, dep.Dependency.Version)
		if !found {
			t.Fatalf("%s: no database record", dep.Dependency.Name)
		}
		if got := record.Analysis.ToolVersion; got != want.toolVersion {
			t.Errorf("%s: the database record's toolVersion became %q after the scan, want %q as written",
				dep.Dependency.Name, got, want.toolVersion)
		}
	}

	// The same check on the JSON report, which is where the reader compares the
	// two: every dependency's block names the top-level tool and its version.
	var buf bytes.Buffer
	if err := (&output.JSONFormatter{}).Format(result, &buf); err != nil {
		t.Fatalf("format: %v", err)
	}
	var doc struct {
		Tool struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"tool"`
		Dependencies []struct {
			Dependency struct {
				Name string `json:"name"`
			} `json:"dependency"`
			Analysis *struct {
				Analysis map[string]any `json:"analysis"`
			} `json:"analysis"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("parse JSON report: %v", err)
	}
	if doc.Tool.Name != version.Name || doc.Tool.Version != scannerVersion {
		t.Fatalf("top-level tool = %+v, want %s %s", doc.Tool, version.Name, scannerVersion)
	}
	if len(doc.Dependencies) != len(wantRecord) {
		t.Fatalf("JSON report has %d dependencies, want %d", len(doc.Dependencies), len(wantRecord))
	}
	for _, dep := range doc.Dependencies {
		if dep.Analysis == nil {
			t.Fatalf("%s has no analysis in the JSON report", dep.Dependency.Name)
		}
		block := dep.Analysis.Analysis
		if block["tool"] != doc.Tool.Name || block["toolVersion"] != doc.Tool.Version {
			t.Errorf("%s: analysis.analysis = %v, want tool %q and toolVersion %q as at the top of the report",
				dep.Dependency.Name, block, doc.Tool.Name, doc.Tool.Version)
		}
	}
}

// TestSourceAnalysisNamesTheScannerThatWroteTheReport is the same check for a
// package read by --deep, whose analysis block had an empty tool and version.
func TestSourceAnalysisNamesTheScannerThatWroteTheReport(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("PATH", t.TempDir())

	project := mavenDeepFixture(t, tmpDir, map[string]string{
		"com/google/common/util/concurrent/Hashing.java": `package com.google.common.util.concurrent;
import java.security.MessageDigest;
public class Hashing {
    public byte[] digest(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data);
    }
}
`,
		"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n",
	})

	setScannerVersion(t)
	_, dep, _ := runDeepScan(t, project)

	if !dep.DeepAnalyzed || dep.Analysis == nil {
		t.Fatalf("the fixture package was not read by source analysis: %+v (%s)", dep, dep.Error)
	}
	if got := dep.Analysis.Analysis.Tool; got != version.Name {
		t.Errorf("analysis tool = %q, want %q", got, version.Name)
	}
	if got := dep.Analysis.Analysis.ToolVersion; got != scannerVersion {
		t.Errorf("analysis toolVersion = %q, want the scanner's %q", got, scannerVersion)
	}
}
