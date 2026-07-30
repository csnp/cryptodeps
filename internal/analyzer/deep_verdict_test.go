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
)

// deepScanFixture builds a project whose dependencies are absent from the
// crypto database, together with a source cache holding each one already
// extracted.
//
// The cache is what makes this an offline test of the real --deep path: the
// analyzer's on-demand fetcher resolves the packages from it and never reaches
// the network, so the whole chain from manifest to rendered verdict runs
// exactly as it does for a user, in a unit test.
//
// It returns the project directory. The caller must have redirected TMPDIR
// before calling New, because that is where the fetcher puts its cache.
func deepScanFixture(t *testing.T, tmpDir string, source map[string]string) string {
	t.Helper()

	project := filepath.Join(tmpDir, "project")
	if err := os.MkdirAll(project, 0755); err != nil {
		t.Fatalf("create project dir: %v", err)
	}

	var deps []string
	for name := range source {
		deps = append(deps, `"`+name+`": "1.0.0"`)
	}
	manifest := `{"name":"fixture","version":"1.0.0","dependencies":{` +
		strings.Join(deps, ",") + `}}`
	if err := os.WriteFile(filepath.Join(project, "package.json"), []byte(manifest), 0644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	for name, code := range source {
		// The layout npm pack plus tar produces, which is what the fetcher
		// looks for on a cache hit.
		dir := filepath.Join(tmpDir, "cryptodeps-cache", "npm", name, "1.0.0", "package")
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("create cache entry for %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte(code), 0644); err != nil {
			t.Fatalf("write cached source for %s: %v", name, err)
		}
	}

	return project
}

// TestDeepScanOfCleanTreeReportsClean is the end-to-end regression test for the
// defect that held the v1.3.0 tag.
//
// `analyze <tree> --deep`, where every dependency is absent from the crypto
// database and none of them carries cryptography, printed:
//
//	[?] Not analyzed. All 3 dependencies are absent from the crypto database,
//	    so no conclusion about cryptographic usage can be drawn from this scan.
//	    Run with --deep to analyze package source code directly.
//
// The scan had read all three. The JSON for the same invocation reported
// deepAnalyzed on every one of them, so the two formats contradicted each other
// for one command, and the released 1.2.2 printed the correct verdict for this
// case. The classifier was asking whether the database covered the packages in
// order to answer whether anything had been examined.
func TestDeepScanOfCleanTreeReportsClean(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("TMPDIR", tmpDir)

	project := deepScanFixture(t, tmpDir, map[string]string{
		"chalk":     "module.exports = s => s;\n",
		"commander": "module.exports = { parse() {} };\n",
		"lodash":    "module.exports = { get() {} };\n",
	})

	result, err := New(database.NewEmbedded(), Options{Deep: true}).Analyze(project)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	// Guard the fixture on both sides. Source analysis has to have actually
	// run, and the database has to have covered nothing, or the two predicates
	// are indistinguishable here and the test proves nothing.
	if result.Summary.NotInDatabase != result.Summary.TotalDependencies {
		t.Fatalf("fixture dependencies are in the database: %+v", result.Summary)
	}
	for _, dep := range result.Dependencies {
		if !dep.DeepAnalyzed {
			t.Fatalf("source analysis did not run for %s, so the scan really did examine "+
				"nothing and this test cannot detect the defect", dep.Dependency.Name)
		}
	}
	if result.Summary.NotExamined != 0 {
		t.Fatalf("Summary.NotExamined = %d after every dependency was read",
			result.Summary.NotExamined)
	}

	var buf bytes.Buffer
	if err := (&output.TableFormatter{Options: output.DefaultOptions()}).Format(result, &buf); err != nil {
		t.Fatalf("format: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "No cryptographic usage detected") {
		t.Errorf("a --deep scan that read every dependency and found no cryptography did "+
			"not report a clean result:\n%s", out)
	}
	if strings.Contains(out, "Not analyzed") ||
		strings.Contains(out, "no conclusion about cryptographic usage") {
		t.Errorf("scan examined every dependency and reported that it had examined "+
			"nothing:\n%s", out)
	}
	if strings.Contains(out, "--deep") {
		t.Errorf("the user ran --deep and the only next step offered is --deep:\n%s", out)
	}
	if !strings.Contains(out, "3 of 3") {
		t.Errorf("verdict does not state how much of the tree was examined:\n%s", out)
	}
}

// TestDeepScanStillReportsFindings is the inverse question for the same change.
//
// Narrowing when the tool says "nothing was examined" must not make it quieter
// about cryptography it did find. Same fixture shape, one dependency carrying a
// broken hash.
func TestDeepScanStillReportsFindings(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("TMPDIR", tmpDir)

	project := deepScanFixture(t, tmpDir, map[string]string{
		"clean-pkg": "module.exports = s => s;\n",
		"hashing-lib": "const crypto = require('crypto');\n" +
			"module.exports = d => crypto.createHash('md5').update(d).digest('hex');\n",
	})

	result, err := New(database.NewEmbedded(), Options{Deep: true}).Analyze(project)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	if result.Summary.WithCrypto == 0 {
		t.Fatalf("fixture produced no findings, so it cannot show that findings survive: %+v",
			result.Summary)
	}

	var buf bytes.Buffer
	if err := (&output.TableFormatter{Options: output.DefaultOptions()}).Format(result, &buf); err != nil {
		t.Fatalf("format: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "MD5") {
		t.Errorf("a finding read by source analysis is missing from the report:\n%s", out)
	}
	if strings.Contains(out, "No cryptographic usage detected") {
		t.Errorf("report carries a finding and a clean verdict at the same time:\n%s", out)
	}
}

// TestDeepScanReportsPackagesItCouldNotRead covers the mixed case, which is the
// one the narrowed trigger moves into the clean branch.
//
// One dependency read, one that source analysis could not fetch. The report has
// to say the second was not examined, and must not answer with --deep, which is
// what the user already ran.
func TestDeepScanReportsPackagesItCouldNotRead(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("TMPDIR", tmpDir)
	// No downloader on PATH, so the dependency without a cache entry cannot be
	// fetched and the run produces one examined and one unexamined package.
	t.Setenv("PATH", t.TempDir())

	project := deepScanFixture(t, tmpDir, map[string]string{
		"cached-pkg": "module.exports = s => s;\n",
	})
	// A second dependency with no cache entry behind it.
	manifest := `{"name":"fixture","version":"1.0.0","dependencies":` +
		`{"cached-pkg":"1.0.0","missing-pkg":"1.0.0"}}`
	if err := os.WriteFile(filepath.Join(project, "package.json"), []byte(manifest), 0644); err != nil {
		t.Fatalf("rewrite package.json: %v", err)
	}

	result, err := New(database.NewEmbedded(), Options{Deep: true}).Analyze(project)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	if result.Summary.NotExamined != 1 || result.Summary.TotalDependencies != 2 {
		t.Fatalf("fixture does not mix examined and unexamined dependencies: %+v",
			result.Summary)
	}

	var buf bytes.Buffer
	if err := (&output.TableFormatter{Options: output.DefaultOptions()}).Format(result, &buf); err != nil {
		t.Fatalf("format: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "1 of 2") {
		t.Errorf("verdict does not say how much of the tree it covers:\n%s", out)
	}
	if !strings.Contains(out, "1 could not be examined") {
		t.Errorf("verdict does not account for the package source analysis could not read:\n%s", out)
	}
	if strings.Contains(out, "use --deep") {
		t.Errorf("the user ran --deep and the tool suggests running --deep:\n%s", out)
	}
}
