// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// labeledFinding builds a finding the way a database lookup labels it. It is
// decoded from JSON so that the names under test are the serialized ones a
// consumer of the JSON report reads.
func labeledFinding(t *testing.T, algorithm, cryptoType string, risk types.QuantumRisk,
	severity types.Severity, basis, confidence string, reach types.Reachability) types.CryptoUsage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"algorithm":    algorithm,
		"type":         cryptoType,
		"quantumRisk":  risk,
		"severity":     severity,
		"location":     map[string]any{"file": "", "line": 0},
		"basis":        basis,
		"confidence":   confidence,
		"reachability": reach,
	})
	if err != nil {
		t.Fatal(err)
	}
	var c types.CryptoUsage
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// basisScanResult holds one curated finding and two inferred ones, which is the
// shape of the scan that reported ECDH and ECDSA in xml-crypto: inferred from
// the word "certificate" in its description, and printed exactly like a finding
// that a person had checked.
func basisScanResult(t *testing.T, reach bool) *types.ScanResult {
	t.Helper()
	r := func(v types.Reachability) types.Reachability {
		if reach {
			return v
		}
		return ""
	}
	return &types.ScanResult{
		Project:   "/test/project",
		Manifest:  "/test/project/package.json",
		Ecosystem: types.EcosystemNPM,
		ScanDate:  time.Now(),
		Dependencies: []types.DependencyResult{
			{
				Dependency: types.Dependency{Name: "node-forge", Version: "1.3.1", Ecosystem: types.EcosystemNPM, Direct: true},
				InDatabase: true,
				Analysis: &types.PackageAnalysis{
					Package: "node-forge", Version: "1.3.1", Ecosystem: types.EcosystemNPM,
					Crypto: []types.CryptoUsage{
						labeledFinding(t, "RSA", "encryption", types.RiskVulnerable, types.SeverityHigh,
							"verified", "verified", r(types.ReachabilityAvailable)),
					},
				},
			},
			{
				Dependency: types.Dependency{Name: "xml-crypto", Version: "6.4.0", Ecosystem: types.EcosystemNPM, Direct: true},
				InDatabase: true,
				Analysis: &types.PackageAnalysis{
					Package: "xml-crypto", Version: "6.3.3", Ecosystem: types.EcosystemNPM,
					Crypto: []types.CryptoUsage{
						labeledFinding(t, "ECDH", "key-exchange", types.RiskVulnerable, types.SeverityHigh,
							"inferred", "medium", r(types.ReachabilityConfirmed)),
						labeledFinding(t, "AES-GCM", "encryption", types.RiskPartial, types.SeverityLow,
							"inferred", "medium", r(types.ReachabilityReachable)),
					},
				},
			},
		},
		Summary: types.ScanSummary{TotalDependencies: 2, DirectDependencies: 2, WithCrypto: 2,
			QuantumVulnerable: 2, QuantumPartial: 1, ReachabilityAnalyzed: reach},
	}
}

// verifiedOnly drops the inferred dependency, leaving a scan whose every
// finding is curated.
func verifiedOnly(result *types.ScanResult) *types.ScanResult {
	result.Dependencies = result.Dependencies[:1]
	result.Summary.TotalDependencies, result.Summary.DirectDependencies, result.Summary.WithCrypto = 1, 1, 1
	result.Summary.QuantumVulnerable, result.Summary.QuantumPartial = 1, 0
	return result
}

func linesContaining(out string, parts ...string) []string {
	var found []string
	for _, line := range strings.Split(out, "\n") {
		all := true
		for _, p := range parts {
			if !strings.Contains(line, p) {
				all = false
				break
			}
		}
		if all {
			found = append(found, line)
		}
	}
	return found
}

func TestTableMarksInferredFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := (&TableFormatter{}).Format(basisScanResult(t, false), &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	for _, alg := range []string{"ECDH", "AES-GCM"} {
		rows := linesContaining(out, alg, "xml-crypto@6.4.0")
		if len(rows) == 0 {
			t.Fatalf("no row for %s in xml-crypto:\n%s", alg, out)
		}
		for _, row := range rows {
			if !strings.HasSuffix(strings.TrimRight(row, " "), "(inferred)") {
				t.Errorf("inferred %s row does not end with (inferred): %q", alg, row)
			}
		}
	}
	for _, row := range linesContaining(out, "RSA", "node-forge@1.3.1") {
		if strings.Contains(row, "(inferred)") {
			t.Errorf("verified RSA row is marked inferred: %q", row)
		}
	}

	note := "2 of 3 findings above are inferred from the package name and description, not read from the package."
	if !strings.Contains(out, note) {
		t.Errorf("table does not state how many findings are inferred; want %q in:\n%s", note, out)
	}
	if strings.Index(out, note) > strings.Index(out, "SUMMARY:") {
		t.Errorf("the inferred count should follow the findings, before the summary:\n%s", out)
	}
}

func TestTableMarksInferredFindingsWithReachability(t *testing.T) {
	var buf bytes.Buffer
	if err := (&TableFormatter{}).Format(basisScanResult(t, true), &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	// CONFIRMED prints the algorithm on its own row, the dependency under it.
	confirmed := linesContaining(out, "ECDH", "VULNERABLE")
	if len(confirmed) != 1 || !strings.HasSuffix(strings.TrimRight(confirmed[0], " "), "(inferred)") {
		t.Errorf("confirmed inferred ECDH row is not marked: %q\n%s", confirmed, out)
	}
	reachable := linesContaining(out, "AES-GCM", "xml-crypto@6.4.0")
	if len(reachable) != 1 || !strings.HasSuffix(strings.TrimRight(reachable[0], " "), "(inferred)") {
		t.Errorf("reachable inferred AES-GCM row is not marked: %q\n%s", reachable, out)
	}
	available := linesContaining(out, "RSA")
	if len(available) == 0 || strings.Contains(strings.Join(available, "\n"), "(inferred)") {
		t.Errorf("available verified RSA row missing or marked inferred: %q\n%s", available, out)
	}
	if !strings.Contains(out, "2 of 3 findings above are inferred") {
		t.Errorf("table with reachability does not state the inferred count:\n%s", out)
	}
}

func TestMarkdownMarksInferredFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := (&MarkdownFormatter{}).Format(basisScanResult(t, false), &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	for _, alg := range []string{"ECDH", "AES-GCM"} {
		rows := linesContaining(out, "| `xml-crypto@6.4.0` | "+alg+" |")
		if len(rows) != 1 || !strings.HasSuffix(rows[0], "(inferred) |") {
			t.Errorf("inferred %s markdown row does not end with (inferred): %q", alg, rows)
		}
	}
	for _, row := range linesContaining(out, "| `node-forge@1.3.1` | RSA |") {
		if strings.Contains(row, "(inferred)") {
			t.Errorf("verified RSA markdown row is marked inferred: %q", row)
		}
	}
	if !strings.Contains(out, "2 of 3 findings above are inferred from the package name and description") {
		t.Errorf("markdown does not state how many findings are inferred:\n%s", out)
	}
}

// TestNoInferredFindingPrintsNoNote keeps the note honest in the other
// direction: a scan whose findings were all checked must not carry it.
func TestNoInferredFindingPrintsNoNote(t *testing.T) {
	for name, f := range map[string]Formatter{"table": &TableFormatter{}, "markdown": &MarkdownFormatter{}} {
		var buf bytes.Buffer
		if err := f.Format(verifiedOnly(basisScanResult(t, false)), &buf); err != nil {
			t.Fatal(err)
		}
		if out := buf.String(); strings.Contains(out, "inferred") {
			t.Errorf("%s: a scan with no inferred finding mentions inference:\n%s", name, out)
		}
	}
}

type decodedSARIFResult struct {
	RuleID  string `json:"ruleId"`
	Level   string `json:"level"`
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
	Properties map[string]any `json:"properties"`
}

func renderSARIFResults(t *testing.T, result *types.ScanResult) []decodedSARIFResult {
	t.Helper()
	var buf bytes.Buffer
	if err := (&SARIFFormatter{}).Format(result, &buf); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Results []decodedSARIFResult `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	return doc.Runs[0].Results
}

func TestSARIFResultsCarryBasisAndReachability(t *testing.T) {
	results := renderSARIFResults(t, basisScanResult(t, true))
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}

	want := map[string]struct {
		level, basis, confidence, reachability, risk, clause string
		inferred                                             bool
	}{
		"CRYPTO-RSA":     {"error", "verified", "verified", "AVAILABLE", "VULNERABLE", "in a dependency your code does not call", false},
		"CRYPTO-ECDH":    {"error", "inferred", "medium", "CONFIRMED", "VULNERABLE", "called from your code", true},
		"CRYPTO-AES-GCM": {"note", "inferred", "medium", "REACHABLE", "PARTIAL", "reachable from your code", true},
	}
	for _, res := range results {
		w, ok := want[res.RuleID]
		if !ok {
			t.Errorf("unexpected result %s", res.RuleID)
			continue
		}
		// Levels are deliberately unchanged: reachability misses calls today,
		// so lowering an uncalled finding could drop a called algorithm below a
		// code-scanning gate.
		if res.Level != w.level {
			t.Errorf("%s: level = %q, want %q", res.RuleID, res.Level, w.level)
		}
		for key, value := range map[string]string{
			"basis": w.basis, "confidence": w.confidence, "reachability": w.reachability, "quantumRisk": w.risk,
		} {
			if res.Properties[key] != value {
				t.Errorf("%s: properties.%s = %v, want %q", res.RuleID, key, res.Properties[key], value)
			}
		}
		if !strings.Contains(res.Message.Text, w.clause) {
			t.Errorf("%s: message %q does not say %q", res.RuleID, res.Message.Text, w.clause)
		}
		if got := strings.Contains(res.Message.Text, "inferred from the package name and description"); got != w.inferred {
			t.Errorf("%s: message %q mentions inference = %v, want %v", res.RuleID, res.Message.Text, got, w.inferred)
		}
	}
}

// TestSARIFOmitsReachabilityWhenItDidNotRun keeps the property from claiming a
// reachability verdict that was never reached.
func TestSARIFOmitsReachabilityWhenItDidNotRun(t *testing.T) {
	for _, res := range renderSARIFResults(t, basisScanResult(t, false)) {
		if _, ok := res.Properties["reachability"]; ok {
			t.Errorf("%s: reachability property present on a scan that did not analyze it", res.RuleID)
		}
		if res.Properties["basis"] == nil {
			t.Errorf("%s: no basis property", res.RuleID)
		}
		for _, clause := range []string{"called from your code", "reachable from your code", "your code does not call"} {
			if strings.Contains(res.Message.Text, clause) {
				t.Errorf("%s: message %q states reachability that was not analyzed", res.RuleID, res.Message.Text)
			}
		}
	}
}

type decodedProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type propertyBOM struct {
	Components []struct {
		Type       string            `json:"type"`
		BOMRef     string            `json:"bom-ref"`
		Name       string            `json:"name"`
		Properties []decodedProperty `json:"properties"`
	} `json:"components"`
}

func componentProperties(t *testing.T, doc propertyBOM, ref string) map[string]string {
	t.Helper()
	for _, c := range doc.Components {
		if c.BOMRef == ref {
			props := make(map[string]string, len(c.Properties))
			for _, p := range c.Properties {
				props[p.Name] = p.Value
			}
			return props
		}
	}
	t.Fatalf("no component with bom-ref %s", ref)
	return nil
}

func TestCBOMCarriesRiskBasisAndReachability(t *testing.T) {
	var buf bytes.Buffer
	if err := (&CBOMFormatter{}).Format(basisScanResult(t, true), &buf); err != nil {
		t.Fatal(err)
	}
	var doc propertyBOM
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("CBOM is not valid JSON: %v", err)
	}

	for ref, risk := range map[string]string{"crypto:RSA": "VULNERABLE", "crypto:ECDH": "VULNERABLE", "crypto:AES-GCM": "PARTIAL"} {
		if got := componentProperties(t, doc, ref)["cryptodeps:quantumRisk"]; got != risk {
			t.Errorf("%s: cryptodeps:quantumRisk = %q, want %q", ref, got, risk)
		}
	}

	forge := componentProperties(t, doc, "pkg:npm/node-forge@1.3.1")
	for name, value := range map[string]string{
		"cryptodeps:algorithm:RSA:basis":        "verified",
		"cryptodeps:algorithm:RSA:confidence":   "verified",
		"cryptodeps:algorithm:RSA:reachability": "AVAILABLE",
	} {
		if forge[name] != value {
			t.Errorf("node-forge: %s = %q, want %q", name, forge[name], value)
		}
	}

	xml := componentProperties(t, doc, "pkg:npm/xml-crypto@6.4.0")
	for name, value := range map[string]string{
		"cryptodeps:algorithm:ECDH:basis":           "inferred",
		"cryptodeps:algorithm:ECDH:confidence":      "medium",
		"cryptodeps:algorithm:ECDH:reachability":    "CONFIRMED",
		"cryptodeps:algorithm:AES-GCM:basis":        "inferred",
		"cryptodeps:algorithm:AES-GCM:confidence":   "medium",
		"cryptodeps:algorithm:AES-GCM:reachability": "REACHABLE",
	} {
		if xml[name] != value {
			t.Errorf("xml-crypto: %s = %q, want %q", name, xml[name], value)
		}
	}
	if _, leaked := xml["cryptodeps:algorithm:RSA:basis"]; leaked {
		t.Error("xml-crypto carries a property for an algorithm only node-forge provides")
	}
}
