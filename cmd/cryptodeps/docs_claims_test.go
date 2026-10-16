// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// These tests hold the documentation to what the code does. Each one derives
// the fact from the code where it can, and fails when the page states
// something else. All four checks come from one report in which the roadmap,
// the changelog, the GitLab recipe and the Commands page each described the
// tool differently from how it behaves.

// repoRoot is the repository root. Go runs a package's tests in the package
// directory, two levels below it.
const repoRoot = "../.."

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("reading %s: %v", rel, err)
	}
	return string(b)
}

// markdownSection returns the body under the first heading whose text is
// heading, up to the next heading of the same or a higher level.
func markdownSection(t *testing.T, doc, file, heading string) string {
	t.Helper()
	lines := strings.Split(doc, "\n")
	inFence := false
	for i, line := range lines {
		if strings.HasPrefix(line, "```") {
			inFence = !inFence
		}
		if inFence {
			continue
		}
		level := len(line) - len(strings.TrimLeft(line, "#"))
		if level == 0 || strings.TrimSpace(line[level:]) != heading {
			continue
		}
		var body []string
		fence := false
		for _, next := range lines[i+1:] {
			if strings.HasPrefix(next, "```") {
				fence = !fence
			}
			if !fence {
				l := len(next) - len(strings.TrimLeft(next, "#"))
				if l > 0 && l <= level && strings.HasPrefix(next[l:], " ") {
					break
				}
			}
			body = append(body, next)
		}
		return strings.Join(body, "\n")
	}
	t.Fatalf("%s has no %q heading", file, heading)
	return ""
}

// TestDocsMakeNoCNSAClaimTheSourceDoesNotBackUp covers a delivered roadmap item
// ("Quantum risk classification with CNSA 2.0 timeline") and a 1.0.0 changelog
// line ("Maps findings to CNSA 2.0 compliance requirements") that no Go source
// file implemented. The timeline the tool prints comes from the remediation
// Timeline field ("Short-term (1-2 years)"), not from CNSA 2.0 dates.
//
// Pages that cite CNSA 2.0 as further reading are not claims about the tool, so
// only the two places that list what a release did are checked.
func TestDocsMakeNoCNSAClaimTheSourceDoesNotBackUp(t *testing.T) {
	cnsa := regexp.MustCompile(`(?i)cnsa`)

	var backing []string
	for _, dir := range []string{"cmd", "internal", "pkg"} {
		err := filepath.WalkDir(filepath.Join(repoRoot, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if cnsa.Match(b) {
				backing = append(backing, path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", dir, err)
		}
	}
	if len(backing) > 0 {
		t.Skipf("source now mentions CNSA (%s); check the roadmap and changelog claims "+
			"against it by hand", strings.Join(backing, ", "))
	}

	delivered := regexp.MustCompile(`^\s*- \[[xX]\]`)
	for i, line := range strings.Split(readRepoFile(t, "docs/releases.md"), "\n") {
		if delivered.MatchString(line) && cnsa.MatchString(line) {
			t.Errorf("docs/releases.md:%d lists a delivered CNSA item, and no Go source "+
				"mentions CNSA: %s", i+1, strings.TrimSpace(line))
		}
	}

	for i, line := range strings.Split(readRepoFile(t, "CHANGELOG.md"), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "- ") && cnsa.MatchString(line) {
			t.Errorf("CHANGELOG.md:%d states a CNSA change, and no Go source mentions "+
				"CNSA: %s", i+1, strings.TrimSpace(line))
		}
	}
}

// TestDocsGitLabRecipeKeepsItsReportWhenTheGateFails covers the GitLab CI
// recipe, which wrote its JSON report under the default --fail-on vulnerable
// and kept artifacts only on success. On a project with a quantum-vulnerable
// finding the report line exited 1, GitLab stopped the job there, the final
// gate line never ran, and the report was not kept.
//
// The recipe is meant to end in a failing gate, so the job fails whenever the
// gate does. GitLab uploads artifacts of a failed job only under
// `artifacts:when: always` or `on_failure`, and runs a later script line only
// when every earlier one exited 0.
func TestDocsGitLabRecipeKeepsItsReportWhenTheGateFails(t *testing.T) {
	vulnerable := types.ScanSummary{TotalDependencies: 1, WithCrypto: 1, QuantumVulnerable: 1}
	if got := exitCodeForSummary(vulnerable, "none"); got != ExitSuccess {
		t.Fatalf("exitCodeForSummary(vulnerable, none) = %d, want %d; --fail-on none no "+
			"longer lets a report line finish, so this test's premise is gone", got, ExitSuccess)
	}

	section := markdownSection(t, readRepoFile(t, "docs/ci.md"), "docs/ci.md", "GitLab CI")
	block := regexp.MustCompile("(?s)```yaml\n(.*?)```").FindStringSubmatch(section)
	if block == nil {
		t.Fatal("docs/ci.md GitLab CI section has no yaml block")
	}
	var recipe map[string]struct {
		Script    []string `yaml:"script"`
		Artifacts struct {
			When  string   `yaml:"when"`
			Paths []string `yaml:"paths"`
		} `yaml:"artifacts"`
	}
	if err := yaml.Unmarshal([]byte(block[1]), &recipe); err != nil {
		t.Fatalf("docs/ci.md GitLab CI recipe is not valid YAML: %v", err)
	}
	job, ok := recipe["cryptodeps"]
	if !ok || len(job.Script) == 0 {
		t.Fatal("docs/ci.md GitLab CI recipe has no cryptodeps job with a script")
	}

	failOn := regexp.MustCompile(`--fail-on[ =](\S+)`)
	threshold := func(line string) string {
		if m := failOn.FindStringSubmatch(line); m != nil {
			return m[1]
		}
		return "vulnerable"
	}

	for i, line := range job.Script[:len(job.Script)-1] {
		if !strings.Contains(line, "cryptodeps analyze") {
			continue
		}
		if got := threshold(line); got != "none" {
			t.Errorf("script line %d runs under --fail-on %s, so on a quantum-vulnerable "+
				"finding it exits %d and the lines after it never run: %s",
				i+1, got, exitCodeForSummary(vulnerable, got), line)
		}
	}

	last := job.Script[len(job.Script)-1]
	if !strings.Contains(last, "cryptodeps analyze") ||
		exitCodeForSummary(vulnerable, threshold(last)) == ExitSuccess {
		t.Errorf("the last script line should be the gate that fails the job on a "+
			"quantum-vulnerable finding: %s", last)
	}

	if len(job.Artifacts.Paths) > 0 && job.Artifacts.When != "always" && job.Artifacts.When != "on_failure" {
		t.Errorf("artifacts:when is %q, so the report is not kept when the gate fails the "+
			"job; set it to always", job.Artifacts.When)
	}
}

// TestDocsFilterParagraphSaysTheExitCodeCountsWithheldFindings covers the
// Commands page saying the exit code was computed from what --risk and
// --min-severity leave. Since 1.3.0 the gate also counts what they withheld.
func TestDocsFilterParagraphSaysTheExitCodeCountsWithheldFindings(t *testing.T) {
	withheld := types.ScanSummary{TotalDependencies: 1, WithheldWithCrypto: 1, WithheldVulnerable: 1}
	if got := exitCodeForSummary(withheld, "vulnerable"); got != ExitVulnerable {
		t.Fatalf("exitCodeForSummary(withheld vulnerable) = %d, want %d; the gate no "+
			"longer counts withheld findings, so the page needs rewriting the other way",
			got, ExitVulnerable)
	}

	doc := readRepoFile(t, "docs/commands.md")
	var paragraph string
	for _, p := range strings.Split(doc, "\n\n") {
		if strings.HasPrefix(p, "`--risk` and `--min-severity`") {
			paragraph = strings.Join(strings.Fields(p), " ")
			break
		}
	}
	if paragraph == "" {
		t.Fatal("docs/commands.md has no paragraph starting with `--risk` and `--min-severity`")
	}

	mentioned := false
	for _, sentence := range strings.SplitAfter(paragraph, ". ") {
		if !strings.Contains(sentence, "exit code") {
			continue
		}
		mentioned = true
		if !strings.Contains(sentence, "withheld") {
			t.Errorf("docs/commands.md describes the exit code without saying it counts "+
				"the findings the filters withheld: %q", strings.TrimSpace(sentence))
		}
	}
	if !mentioned {
		t.Error("docs/commands.md filter paragraph no longer says how the filters affect the exit code")
	}
}

// TestDocsExitCodeTableCoversEveryFailOnThreshold covers an exit-code table
// that described only the default threshold. Under --fail-on none a scan with
// quantum-vulnerable findings exits 0, and under --fail-on any a project whose
// cryptography is all quantum-safe exits 3.
//
// The page carries one row per threshold saying when it exits 1 and when it
// exits 3. Which cells must read "never" is computed here from
// exitCodeForSummary, over a vulnerable, a partial-risk and an all-safe scan.
func TestDocsExitCodeTableCoversEveryFailOnThreshold(t *testing.T) {
	shapes := []types.ScanSummary{
		{TotalDependencies: 1, WithCrypto: 1, QuantumVulnerable: 1},
		{TotalDependencies: 1, WithCrypto: 1, QuantumPartial: 1},
		{TotalDependencies: 1, WithCrypto: 1},
	}

	section := markdownSection(t, readRepoFile(t, "docs/commands.md"), "docs/commands.md", "Exit codes")
	rows := map[string][]string{}
	inTable := false
	for _, line := range strings.Split(section, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") {
			inTable = false
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		if cells[0] == "`--fail-on`" {
			inTable = true
			if len(cells) != 3 || !strings.Contains(cells[1], "1") || !strings.Contains(cells[2], "3") {
				t.Fatalf("docs/commands.md --fail-on table header should be "+
					"| `--fail-on` | Exits 1 when | Exits 3 when |, got %q", line)
			}
			continue
		}
		if !inTable || strings.HasPrefix(cells[0], "-") {
			continue
		}
		if m := regexp.MustCompile("^`([a-z]+)`").FindStringSubmatch(cells[0]); m != nil && len(cells) == 3 {
			rows[m[1]] = cells[1:]
		}
	}
	if len(rows) == 0 {
		t.Fatal("docs/commands.md Exit codes section has no table with one row per --fail-on threshold")
	}

	for _, threshold := range gateThresholds {
		cells, ok := rows[threshold]
		if !ok {
			t.Errorf("docs/commands.md exit-code table has no row for --fail-on %s", threshold)
			continue
		}
		for col, code := range []int{ExitVulnerable, ExitPartial} {
			reachable := false
			for _, s := range shapes {
				if exitCodeForSummary(s, threshold) == code {
					reachable = true
				}
			}
			never := strings.EqualFold(cells[col], "never")
			if reachable && never {
				t.Errorf("--fail-on %s can exit %d, and the table says never", threshold, code)
			}
			if !reachable && !never {
				t.Errorf("--fail-on %s cannot exit %d, and the table says %q", threshold, code, cells[col])
			}
		}
	}
}
