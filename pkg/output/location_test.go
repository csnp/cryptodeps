// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// npmDeclaredScan is the shape of the reproduction: a package.json declaring
// jsonwebtoken on line 4, scanned from the directory that holds it.
func npmDeclaredScan(root string) *types.MultiProjectResult {
	return &types.MultiProjectResult{
		RootPath: root,
		Projects: []*types.ScanResult{{
			Project:   root,
			Manifest:  filepath.Join(root, "package.json"),
			Ecosystem: types.EcosystemNPM,
			Dependencies: []types.DependencyResult{{
				Dependency: types.Dependency{Name: "jsonwebtoken", Version: "8.0.0",
					Ecosystem: types.EcosystemNPM, Direct: true, Line: 4},
				InDatabase: true,
				Analysis: &types.PackageAnalysis{Package: "jsonwebtoken", Crypto: []types.CryptoUsage{
					{Algorithm: "RS256", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh,
						Location: types.Location{File: "package.json", Line: 4}},
				}},
			}},
			Summary: types.ScanSummary{TotalDependencies: 1, DirectDependencies: 1, WithCrypto: 1,
				QuantumVulnerable: 1},
		}},
	}
}

const npmDeclaredManifest = "{\n" +
	"  \"name\": \"web\",\n" +
	"  \"dependencies\": {\n" +
	"    \"jsonwebtoken\": \"^8.0.0\"\n" +
	"  }\n" +
	"}\n"

// linesWithPrefix returns every line of out that starts with prefix once its
// indentation is removed.
func linesWithPrefix(out, prefix string) []string {
	var found []string
	for _, line := range strings.Split(out, "\n") {
		if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, prefix) {
			found = append(found, trimmed)
		}
	}
	return found
}

// runVerify runs a printed Verify command from dir the way a reader would, with
// a POSIX shell, and returns what it printed.
func runVerify(t *testing.T, dir, command string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the Verify command is a POSIX shell command")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no POSIX shell on PATH")
	}
	cmd := exec.Command(sh, "-c", command)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Verify command %q failed: %v\n%s", command, err, out)
	}
	return string(out)
}

// TestSARIFResultCarriesDeclarationLine is the regression test for SARIF
// results that located every finding at the manifest with no region, so a code
// scanning alert opened at the top of go.mod rather than at the dependency.
func TestSARIFResultCarriesDeclarationLine(t *testing.T) {
	root := t.TempDir()
	scan := npmDeclaredScan(root)
	// A second dependency whose line is unknown must name the file alone.
	scan.Projects[0].Dependencies = append(scan.Projects[0].Dependencies, types.DependencyResult{
		Dependency: types.Dependency{Name: "node-forge", Version: "1.3.1", Ecosystem: types.EcosystemNPM},
		InDatabase: true,
		Analysis: &types.PackageAnalysis{Package: "node-forge", Crypto: []types.CryptoUsage{
			{Algorithm: "DES", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical},
		}},
	})

	var doc struct {
		Runs []struct {
			Results []struct {
				Message   struct{ Text string } `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region *struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	out := renderMulti(t, FormatSARIF, scan)
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("SARIF does not decode: %v", err)
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 2 {
		t.Fatalf("want 2 results, got %s", out)
	}
	for _, r := range doc.Runs[0].Results {
		loc := r.Locations[0].PhysicalLocation
		if loc.ArtifactLocation.URI != "package.json" {
			t.Errorf("%s: uri %q, want package.json", r.Message.Text, loc.ArtifactLocation.URI)
		}
		switch {
		case strings.HasPrefix(r.Message.Text, "jsonwebtoken"):
			if loc.Region == nil || loc.Region.StartLine != 4 {
				t.Errorf("jsonwebtoken: region %+v, want startLine 4", loc.Region)
			}
		case strings.HasPrefix(r.Message.Text, "node-forge"):
			if loc.Region != nil {
				t.Errorf("node-forge: line unknown, so no region; got startLine %d", loc.Region.StartLine)
			}
		}
	}
	// SARIF requires startLine >= 1 when a region is present, so line 0 must
	// not be written as one.
	if strings.Contains(out, `"startLine": 0`) {
		t.Errorf("SARIF carries a zero startLine:\n%s", out)
	}
}

// TestTableBlockSaysWhereAndHowToVerify is the regression test for remediation
// blocks that had an Action and a replacement and no way to find, or confirm,
// the dependency they were about.
func TestTableBlockSaysWhereAndHowToVerify(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(npmDeclaredManifest), 0o644); err != nil {
		t.Fatal(err)
	}
	out := renderMulti(t, FormatTable, npmDeclaredScan(root))

	where := linesWithPrefix(out, "Where:")
	if len(where) != 1 || where[0] != "Where:        ./package.json:4  jsonwebtoken 8.0.0" {
		t.Fatalf("want one Where line naming ./package.json:4, got %q\n%s", where, out)
	}
	verify := linesWithPrefix(out, "Verify:")
	if len(verify) != 1 {
		t.Fatalf("want one Verify line, got %q\n%s", verify, out)
	}
	command := strings.TrimSpace(strings.TrimPrefix(verify[0], "Verify:"))
	if command != "grep -n -F -e jsonwebtoken ./package.json" {
		t.Errorf("Verify command %q", command)
	}
	// The block keeps its fix: a migration is code work, and it is described,
	// not scripted.
	if len(linesWithPrefix(out, "Action:")) != 1 {
		t.Errorf("Action line missing:\n%s", out)
	}

	// The command has to run, from the scan root, and show the line Where named.
	got := runVerify(t, root, command)
	if strings.TrimSpace(got) != `4:    "jsonwebtoken": "^8.0.0"` {
		t.Errorf("Verify printed %q, want the declaration on line 4", got)
	}
}

// TestTableBlockListsEveryProvider pins that an algorithm two dependencies
// provide lists both, in the order they are declared, and that one Verify
// command confirms both. The reachability layout prints this block through a
// different path from the plain one, so it is covered too.
func TestTableBlockListsEveryProvider(t *testing.T) {
	root := t.TempDir()
	gomod := "module example.com/app\n\nrequire (\n" +
		"\tgolang.org/x/crypto v0.21.0\n" + // 4
		"\tgithub.com/cloudflare/circl v1.3.7\n" + // 5
		")\n"
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte(gomod), 0o644); err != nil {
		t.Fatal(err)
	}
	dep := func(name, version string, line int) types.DependencyResult {
		return types.DependencyResult{
			Dependency: types.Dependency{Name: name, Version: version, Ecosystem: types.EcosystemGo,
				Direct: true, Line: line},
			InDatabase: true,
			Analysis: &types.PackageAnalysis{Package: name, Crypto: []types.CryptoUsage{
				{Algorithm: "Ed25519", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh,
					Reachability: types.ReachabilityConfirmed},
			}},
		}
	}

	for _, reachability := range []bool{false, true} {
		scan := &types.MultiProjectResult{
			RootPath: root,
			Projects: []*types.ScanResult{{
				Project:   root,
				Manifest:  filepath.Join(root, "go.mod"),
				Ecosystem: types.EcosystemGo,
				// Listed out of declaration order on purpose.
				Dependencies: []types.DependencyResult{
					dep("github.com/cloudflare/circl", "v1.3.7", 5),
					dep("golang.org/x/crypto", "v0.21.0", 4),
				},
				Summary: types.ScanSummary{TotalDependencies: 2, WithCrypto: 2, QuantumVulnerable: 2,
					ReachabilityAnalyzed: reachability, ConfirmedCrypto: 2},
			}},
		}
		out := renderMulti(t, FormatTable, scan)

		want := []string{
			"Where:        ./go.mod:4  golang.org/x/crypto v0.21.0",
			"Where:        ./go.mod:5  github.com/cloudflare/circl v1.3.7",
		}
		if got := linesWithPrefix(out, "Where:"); strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("reachability=%v: Where lines\n%q\nwant\n%q\n%s", reachability, got, want, out)
		}
		verify := linesWithPrefix(out, "Verify:")
		if len(verify) != 1 {
			t.Fatalf("reachability=%v: want one Verify line, got %q", reachability, verify)
		}
		command := strings.TrimSpace(strings.TrimPrefix(verify[0], "Verify:"))
		got := runVerify(t, root, command)
		if got != "4:\tgolang.org/x/crypto v0.21.0\n5:\tgithub.com/cloudflare/circl v1.3.7\n" {
			t.Errorf("reachability=%v: Verify %q printed %q", reachability, command, got)
		}
	}
}

// TestTableWhereWithoutALineNamesTheFile covers a dependency whose line the
// parser could not find: the file alone, never ":0".
func TestTableWhereWithoutALineNamesTheFile(t *testing.T) {
	root := t.TempDir()
	scan := npmDeclaredScan(root)
	scan.Projects[0].Dependencies[0].Dependency.Line = 0
	out := renderMulti(t, FormatTable, scan)
	where := linesWithPrefix(out, "Where:")
	if len(where) != 1 || where[0] != "Where:        ./package.json  jsonwebtoken 8.0.0" {
		t.Errorf("want the file alone, got %q", where)
	}
}

// TestVerifyCommandQuotesWhatTheManifestControls pins that a dependency name is
// data in the printed command and never shell syntax. The name comes from the
// manifest under scan, which a pull request can change, and a reader is being
// asked to paste this command into a shell.
func TestVerifyCommandQuotesWhatTheManifestControls(t *testing.T) {
	root := t.TempDir()
	hostile := "evil$(touch pwned)'x"
	manifest := "{\n  \"dependencies\": {\n    \"" + hostile + "\": \"1.0.0\"\n  }\n}\n"
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	scan := npmDeclaredScan(root)
	scan.Projects[0].Dependencies[0].Dependency.Name = hostile
	scan.Projects[0].Dependencies[0].Dependency.Version = "1.0.0"
	scan.Projects[0].Dependencies[0].Dependency.Line = 3

	out := renderMulti(t, FormatTable, scan)
	verify := linesWithPrefix(out, "Verify:")
	if len(verify) != 1 {
		t.Fatalf("want one Verify line, got %q\n%s", verify, out)
	}
	command := strings.TrimSpace(strings.TrimPrefix(verify[0], "Verify:"))
	got := runVerify(t, root, command)
	if _, err := os.Stat(filepath.Join(root, "pwned")); err == nil {
		t.Fatalf("running the Verify command %q executed text from the manifest", command)
	}
	if !strings.HasPrefix(got, "3:") {
		t.Errorf("Verify %q printed %q, want the declaration on line 3", command, got)
	}
}

// TestVerifyFindsWhatEachEcosystemWrites runs the Verify command for the two
// ecosystems whose reported name is not the text in the manifest: a PyPI name
// after PEP 503 normalisation, and a Maven coordinate the pom writes as two
// elements. A literal search for either would print nothing and exit 1.
func TestVerifyFindsWhatEachEcosystemWrites(t *testing.T) {
	tests := []struct {
		ecosystem types.Ecosystem
		file      string
		content   string
		deps      []types.Dependency
		want      string
	}{
		{
			ecosystem: types.EcosystemPyPI,
			file:      "Pipfile",
			content:   "[packages]\nPyNaCl = \"==1.5.0\"\ntyping_extensions = \"*\"\n",
			deps:      []types.Dependency{{Name: "pynacl", Line: 2}, {Name: "typing-extensions", Line: 3}},
			want:      "2:PyNaCl = \"==1.5.0\"\n3:typing_extensions = \"*\"\n",
		},
		{
			ecosystem: types.EcosystemMaven,
			file:      "pom.xml",
			content: "<project>\n  <dependencies>\n    <dependency>\n" +
				"      <groupId>org.bouncycastle</groupId>\n" +
				"      <artifactId>bcprov-jdk18on</artifactId>\n" +
				"    </dependency>\n  </dependencies>\n</project>\n",
			deps: []types.Dependency{{Name: "org.bouncycastle:bcprov-jdk18on", Line: 5}},
			want: "5:      <artifactId>bcprov-jdk18on</artifactId>\n",
		},
	}
	for _, tt := range tests {
		t.Run(string(tt.ecosystem), func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, tt.file), []byte(tt.content), 0o644); err != nil {
				t.Fatal(err)
			}
			command := verifyDeclarationCommand(tt.ecosystem, "./"+tt.file, tt.deps)
			if got := runVerify(t, root, command); got != tt.want {
				t.Errorf("%q printed %q, want %q", command, got, tt.want)
			}
		})
	}
}

// TestMarkdownRemediationSaysWhereAndHowToVerify is the markdown form of the
// table test: the report the GitHub Action posts names the declaration and a
// command that confirms it beside each algorithm's guidance.
func TestMarkdownRemediationSaysWhereAndHowToVerify(t *testing.T) {
	root := t.TempDir()
	scan := npmDeclaredScan(root)
	scan.Projects[0].Dependencies[0].Analysis.Crypto[0].Remediation = "Use HS256/HS512 for symmetric signing"
	out := renderMulti(t, FormatMarkdown, scan)

	if !strings.Contains(out, "| Algorithm | Recommended Action | Where | Verify |") {
		t.Fatalf("remediation table has no Where and Verify columns:\n%s", out)
	}
	wantRow := "| **RS256** | Use HS256/HS512 for symmetric signing | " +
		"`./package.json:4` `jsonwebtoken 8.0.0` | `grep -n -F -e jsonwebtoken ./package.json` |"
	if !strings.Contains(out, wantRow) {
		t.Errorf("remediation row missing or different; want\n%s\nin\n%s", wantRow, out)
	}
}
