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
// asked to paste this command into a shell. A name that needs quoting reaches
// grep as one word. A name holding a quote gets no command: the quote would be
// written the POSIX way, which fish and PowerShell read differently.
func TestVerifyCommandQuotesWhatTheManifestControls(t *testing.T) {
	tests := []struct {
		name, dependency string
		wantVerify       bool
	}{
		{"name that needs quoting", "evil name [x]", true},
		{"name holding a quote", "evil$(touch pwned)'x", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			manifest := "{\n  \"dependencies\": {\n    \"" + tt.dependency + "\": \"1.0.0\"\n  }\n}\n"
			if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(manifest), 0o644); err != nil {
				t.Fatal(err)
			}
			scan := npmDeclaredScan(root)
			scan.Projects[0].Dependencies[0].Dependency.Name = tt.dependency
			scan.Projects[0].Dependencies[0].Dependency.Version = "1.0.0"
			scan.Projects[0].Dependencies[0].Dependency.Line = 3

			out := renderMulti(t, FormatTable, scan)
			verify := linesWithPrefix(out, "Verify:")
			if !tt.wantVerify {
				for _, line := range verify {
					runPasted(t, root, strings.TrimSpace(strings.TrimPrefix(line, "Verify:")))
				}
				if _, err := os.Stat(filepath.Join(root, "pwned")); err == nil {
					t.Fatalf("running the Verify command %q executed text from the manifest", verify)
				}
				if len(verify) != 0 {
					t.Errorf("want no Verify line for %q, got %q\n%s", tt.dependency, verify, out)
				}
				if where := linesWithPrefix(out, "Where:"); len(where) != 1 {
					t.Errorf("want one Where line, got %q\n%s", where, out)
				}
				return
			}
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
		})
	}
}

// runPasted runs text a report printed as a command the way a reader pasting
// it would, with a POSIX shell in dir, whatever its exit status.
func runPasted(t *testing.T, dir, command string) {
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
	_ = cmd.Run()
}

// TestNoVerifyCommandWhenTheReportEscapesIt is the regression test for a
// Verify command that ran text from the path it named. The reports print a
// string holding a control character, a backtick or a pipe as a Go-quoted
// string, and inside those double quotes "$(...)" and backticks are live
// again: pasting the table's Verify line for a manifest under a directory
// named "tools|$(touch pwned)" created the file. The single quotes inside the
// command do not help once the whole of it is double-quoted, so such a command
// is not printed at all, and the Where line still names the file.
func TestNoVerifyCommandWhenTheReportEscapesIt(t *testing.T) {
	tests := []struct {
		name, dir, dependency string
	}{
		{"pipe in the path", "tools|$(touch pwned)", "jsonwebtoken"},
		{"backtick in the path", "tools`touch pwned`", "jsonwebtoken"},
		{"control character in the path", "tools$(touch pwned)\x01", "jsonwebtoken"},
		{"pipe in the dependency name", "tools", "jsonwebtoken|$(touch pwned)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			scan := npmDeclaredScan(root)
			scan.Projects[0].Manifest = filepath.Join(root, tt.dir, "package.json")
			scan.Projects[0].Dependencies[0].Dependency.Name = tt.dependency
			scan.Projects[0].Dependencies[0].Analysis.Crypto[0].Remediation = "Use HS256/HS512 for symmetric signing"

			table := renderMulti(t, FormatTable, scan)
			markdown := renderMulti(t, FormatMarkdown, scan)

			// Everything either report prints as a command, as a reader would
			// copy it: the table's Verify lines, and the markdown code spans
			// holding a grep, where a cell's "\|" renders as "|".
			var printed []string
			for _, line := range linesWithPrefix(table, "Verify:") {
				printed = append(printed, strings.TrimSpace(strings.TrimPrefix(line, "Verify:")))
			}
			for _, line := range strings.Split(markdown, "\n") {
				spans := strings.Split(line, "`")
				for i := 1; i < len(spans); i += 2 {
					if strings.Contains(spans[i], "grep ") {
						printed = append(printed, strings.ReplaceAll(spans[i], `\|`, "|"))
					}
				}
			}

			scratch := t.TempDir()
			for _, command := range printed {
				runPasted(t, scratch, command)
			}
			if _, err := os.Stat(filepath.Join(scratch, "pwned")); err == nil {
				t.Fatalf("pasting a printed Verify command ran text from the manifest: %q", printed)
			}
			if len(printed) != 0 {
				t.Errorf("want no Verify command for a path or name the report escapes, got %q", printed)
			}

			// The finding still says where it is declared.
			if where := linesWithPrefix(table, "Where:"); len(where) != 1 {
				t.Errorf("want one Where line, got %q\n%s", where, table)
			}
			if !strings.Contains(markdown, "| **RS256** |") {
				t.Errorf("remediation row missing:\n%s", markdown)
			}
		})
	}
}

// TestNoVerifyCommandUnlessFishAndPowerShellReadItAsText is the regression test
// for a Verify command that was safe to paste into a POSIX shell and ran text
// from the path in another one. The command quotes each word for POSIX
// shells. Inside those single quotes fish reads a backslash before a quote as
// an escape, and PowerShell reads a quote that is closed, escaped and
// reopened differently and takes the typographic quotes for quotes, so
// pasting the printed command for a manifest under each of the first three
// directories below created a file: in fish for the first, in PowerShell for
// the other two. A path holding such a character gets no command, and the
// Where line still names the file. A path that needs quoting and holds only
// characters all three read literally inside single quotes still gets one.
func TestNoVerifyCommandUnlessFishAndPowerShellReadItAsText(t *testing.T) {
	// U+2019, built from its code point so it cannot be taken for an ASCII
	// quote when reading this file.
	rsquo := string(rune(0x2019))
	tests := []struct {
		name, dir, wantVerify string
	}{
		{"backslash before a quote, read by fish", `a\'b;touch PWNED_FISH;c\'d`, ""},
		{"quotes around a command, read by PowerShell", `a'$(touch PWNED_PS)'b`, ""},
		{"typographic quotes, read by PowerShell", "a" + rsquo + "$(touch PWNED_PS2)" + rsquo + "b", ""},
		{"space and brackets", "my project [v2]",
			`grep -n -F -e jsonwebtoken './my project [v2]/package.json'`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, tt.dir), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, tt.dir, "package.json"), []byte(npmDeclaredManifest), 0o644); err != nil {
				t.Fatal(err)
			}
			scan := npmDeclaredScan(root)
			scan.Projects[0].Manifest = filepath.Join(root, tt.dir, "package.json")
			scan.Projects[0].Dependencies[0].Analysis.Crypto[0].Remediation = "Use HS256/HS512 for symmetric signing"

			table := renderMulti(t, FormatTable, scan)
			markdown := renderMulti(t, FormatMarkdown, scan)

			// The finding still says where it is declared.
			if where := linesWithPrefix(table, "Where:"); len(where) != 1 {
				t.Errorf("want one Where line, got %q\n%s", where, table)
			}
			var row string
			for _, line := range strings.Split(markdown, "\n") {
				if strings.HasPrefix(line, "| **RS256** |") {
					row = line
				}
			}
			if row == "" {
				t.Fatalf("remediation row missing:\n%s", markdown)
			}
			verify := linesWithPrefix(table, "Verify:")

			if tt.wantVerify == "" {
				if len(verify) != 0 {
					t.Errorf("want no Verify line, got %q", verify)
				}
				if !strings.HasSuffix(row, " |  |") {
					t.Errorf("want an empty Verify cell, got %q", row)
				}
				return
			}
			if len(verify) != 1 || strings.TrimSpace(strings.TrimPrefix(verify[0], "Verify:")) != tt.wantVerify {
				t.Fatalf("want Verify %q, got %q\n%s", tt.wantVerify, verify, table)
			}
			if !strings.HasSuffix(row, " | `"+tt.wantVerify+"` |") {
				t.Errorf("want the Verify cell `%s`, got %q", tt.wantVerify, row)
			}
			got := runVerify(t, root, tt.wantVerify)
			if strings.TrimSpace(got) != `4:    "jsonwebtoken": "^8.0.0"` {
				t.Errorf("Verify printed %q, want the declaration on line 4", got)
			}
		})
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
