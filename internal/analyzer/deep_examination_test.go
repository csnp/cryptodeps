// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/csnp/qramm-cryptodeps/internal/database"
	"github.com/csnp/qramm-cryptodeps/pkg/output"
	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// The artifact from the reproduction: its sources JAR 404s and its main JAR
// 200s, so --deep fetches a JAR holding compiled classes and no source at all.
const (
	unreadableGroupID    = "com.google.guava"
	unreadableArtifactID = "listenablefuture"
	unreadableVersion    = "9999.0-empty-to-avoid-conflict-with-guava"
)

// mavenDeepFixture builds a pom.xml project plus a Maven source-cache entry
// already extracted, and returns the project directory.
//
// files maps a path inside the extracted JAR to its contents, so a caller
// chooses whether the archive holds anything an analyzer can read. The cache
// entry is what keeps this offline: the fetcher resolves it as a cache hit and
// never reaches the network.
//
// The cache path is spelled out rather than computed, because it is what the
// fetcher's own sanitizer produces for this coordinate. If that ever stops
// matching, the fetch fails instead of hitting the cache, and every test here
// fails loudly on its fixture guard rather than passing for the wrong reason.
func mavenDeepFixture(t *testing.T, tmpDir string, files map[string]string) string {
	t.Helper()

	project := filepath.Join(tmpDir, "project")
	if err := os.MkdirAll(project, 0755); err != nil {
		t.Fatalf("create project dir: %v", err)
	}

	pom := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>fixture</artifactId>
    <version>1.0.0</version>
    <dependencies>
        <dependency>
            <groupId>` + unreadableGroupID + `</groupId>
            <artifactId>` + unreadableArtifactID + `</artifactId>
            <version>` + unreadableVersion + `</version>
        </dependency>
    </dependencies>
</project>`
	if err := os.WriteFile(filepath.Join(project, "pom.xml"), []byte(pom), 0644); err != nil {
		t.Fatalf("write pom.xml: %v", err)
	}

	// cacheSegment maps the ':' in a Maven coordinate to '_' and leaves the
	// version alone; "extracted" is where the fetcher unzips a JAR.
	extracted := filepath.Join(tmpDir, "cryptodeps-cache", "maven",
		unreadableGroupID+"_"+unreadableArtifactID, unreadableVersion, "extracted")
	for name, content := range files {
		path := filepath.Join(extracted, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatalf("create cache dir for %s: %v", name, err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("write cached file %s: %v", name, err)
		}
	}

	return project
}

// runDeepScan scans project with --deep and returns the whole result together
// with the rendered table, failing if the fixture did not produce exactly one
// dependency.
func runDeepScan(t *testing.T, project string) (*types.ScanResult, types.DependencyResult, string) {
	t.Helper()

	result, err := New(database.NewEmbedded(), Options{Deep: true}).Analyze(project)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(result.Dependencies) != 1 {
		t.Fatalf("fixture declared %d dependencies, want exactly 1: %+v",
			len(result.Dependencies), result.Dependencies)
	}
	dep := result.Dependencies[0]

	// The fetch has to have reached the walker, or every assertion below is
	// answered by a download that failed rather than by an archive that carried
	// nothing to read. PATH is cleared by these tests, so a cache miss is
	// unrecoverable and says so here rather than passing quietly.
	if strings.Contains(dep.Error, "could not fetch") {
		t.Fatalf("fixture never reached source analysis, so this test cannot tell an "+
			"unreadable archive from a failed download: %s", dep.Error)
	}
	if dep.InDatabase {
		t.Fatalf("fixture dependency is in the crypto database, so --deep is not the "+
			"path under test: %+v", dep)
	}
	if !result.Summary.DeepAttempted {
		t.Fatalf("source analysis was never attempted for this fixture: %+v", result.Summary)
	}

	var buf bytes.Buffer
	if err := (&output.TableFormatter{Options: output.DefaultOptions()}).Format(result, &buf); err != nil {
		t.Fatalf("format: %v", err)
	}

	return result, dep, buf.String()
}

// TestDeepScanOfClassOnlyArchiveIsNotReportedAsExamined is the regression test
// for the third defect of unit 152.
//
// `analyze <tree> --deep` over a Maven artifact whose sources JAR does not
// exist fell back to the main JAR, which holds compiled classes only. The Java
// walker accepts .java, .kt and .kts, found none, and returned no usages and no
// error. DeepAnalyzed was set from that absent error, so the report said:
//
//	[OK] No cryptographic usage detected in the 1 of 1 dependencies that were
//	     examined.
//
// for a scan that parsed zero files. The claim of examination is now made from
// the count of files an analyzer parsed.
func TestDeepScanOfClassOnlyArchiveIsNotReportedAsExamined(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("TMPDIR", tmpDir)
	t.Setenv("PATH", t.TempDir())

	project := mavenDeepFixture(t, tmpDir, map[string]string{
		// A JAR of compiled classes: bytes an analyzer cannot read, in a
		// directory that is neither empty nor a failed extraction.
		"com/google/common/util/concurrent/ListenableFuture.class": "\xca\xfe\xba\xbe\x00\x00\x00\x34",
		"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n",
	})

	result, dep, out := runDeepScan(t, project)

	if dep.DeepAnalyzed {
		t.Errorf("DeepAnalyzed is set for a package whose fetched archive holds no source "+
			"this tool can read: %+v", dep)
	}
	if dep.Analysis.SourceWasRead() {
		t.Errorf("the result claims source was read from an archive of compiled classes: %+v",
			dep.Analysis.Analysis)
	}
	if !strings.Contains(dep.Error, "read no files it can parse") {
		t.Errorf("the report does not say why the package was not examined, so a consumer "+
			"reading JSON cannot tell this from a package that was skipped: %q",
			dep.Error)
	}
	if result.Summary.NotExamined != 1 {
		t.Errorf("Summary.NotExamined = %d for a scan that parsed no file at all",
			result.Summary.NotExamined)
	}

	if strings.Contains(out, "dependencies that were examined") {
		t.Errorf("the verdict claims an examination that read no files:\n%s", out)
	}
	if !strings.Contains(out, "Not analyzed") {
		t.Errorf("the verdict does not say the scan established nothing:\n%s", out)
	}
	if strings.Contains(out, "use --deep") {
		t.Errorf("the user ran --deep and the next step offered is --deep:\n%s", out)
	}
}

// TestDeepScanOfReadableArchiveIsStillReportedAsExamined asks the inverse
// question of the same change.
//
// Narrowing what counts as an examination must not stop the tool reporting the
// packages it really did read. Same fixture shape, one .java file in the
// archive, and the finding in it has to survive.
func TestDeepScanOfReadableArchiveIsStillReportedAsExamined(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("TMPDIR", tmpDir)
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

	result, dep, out := runDeepScan(t, project)

	if !dep.DeepAnalyzed {
		t.Fatalf("a package whose archive carries readable source is reported as not "+
			"examined: %+v (%s)", dep, dep.Error)
	}
	if got := dep.Analysis.Analysis.FilesAnalyzed; got != 1 {
		t.Errorf("filesAnalyzed = %d for an archive holding one .java file", got)
	}
	if result.Summary.NotExamined != 0 {
		t.Errorf("Summary.NotExamined = %d after the only dependency was read",
			result.Summary.NotExamined)
	}
	if !strings.Contains(out, "MD5") {
		t.Errorf("a finding read from the fetched archive is missing from the report:\n%s", out)
	}
}
