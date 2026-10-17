// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeProject writes files into a new directory and returns it.
func writeProject(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// section returns the lines of the table output from the line equal to
// heading up to the next blank line.
func section(out, heading string) []string {
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		if line != heading {
			continue
		}
		var body []string
		for _, l := range lines[i+1:] {
			if strings.TrimSpace(l) == "" {
				break
			}
			body = append(body, l)
		}
		return body
	}
	return nil
}

const (
	classicalHeading = "[!] VULNERABLE - Broken today by classical attacks, quantum computers aside:"
	quantumHeading   = "[!] VULNERABLE - Quantum computers will break these:"
)

// The table rows carry no column names, so the migration effort column read as
// a severity: "[!]  MD5  NOW  low  node-forge@1.3.1" while every other format
// rates MD5 CRITICAL. MD5, SHA-1, DES and 3DES were also listed under "Quantum
// computers will break these", although classical attacks break them today.
func TestTableNamesColumnsAndSeparatesClassicallyBroken(t *testing.T) {
	proxy, _ := startConnectionLog(t)
	project := writeProject(t, map[string]string{
		"package.json": `{"name":"fixture","version":"1.0.0","dependencies":{"node-forge":"1.3.1"}}`,
	})
	stdout, stderr, code := runCLI(t, proxy, "analyze", project, "--offline")
	if code != 1 {
		t.Fatalf("exit %d, want 1\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}

	classical := section(stdout, classicalHeading)
	quantum := section(stdout, quantumHeading)
	if len(classical) < 3 || len(quantum) < 3 {
		t.Fatalf("missing a VULNERABLE section:\n%s", stdout)
	}
	for name, rows := range map[string][]string{"classical": classical, "quantum": quantum} {
		header := strings.Fields(rows[0])
		if strings.Join(header, " ") != "ALGORITHM TIMELINE EFFORT DEPENDENCY" {
			t.Errorf("%s section header = %q, want ALGORITHM TIMELINE EFFORT DEPENDENCY", name, rows[0])
		}
	}
	joined := strings.Join(classical, "\n")
	for _, algo := range []string{"MD5", "SHA-1", "DES", "3DES"} {
		if !containsField(classical, algo) {
			t.Errorf("%s not listed under the classical heading:\n%s", algo, joined)
		}
		if containsField(quantum, algo) {
			t.Errorf("%s listed under %q:\n%s", algo, quantumHeading, strings.Join(quantum, "\n"))
		}
	}
	if !containsField(quantum, "RSA") || containsField(classical, "RSA") {
		t.Errorf("RSA should be listed under the quantum heading only:\n%s", stdout)
	}
}

// containsField reports whether any row has value as its second field (after
// the risk icon).
func containsField(rows []string, value string) bool {
	for _, row := range rows {
		if f := strings.Fields(row); len(f) > 1 && f[1] == value {
			return true
		}
	}
	return false
}

// SAFE findings were counted in no summary, so vulnerable plus partial never
// summed to the findings listed. The JSON summary now carries quantumSafe, the
// SUMMARY line a safe count, and the counters sum to the findings.
func TestSummaryCountsSafeFindings(t *testing.T) {
	proxy, _ := startConnectionLog(t)
	project := writeProject(t, map[string]string{
		"requirements.txt": "cryptography==42.0.0\nPyJWT==2.8.0\n",
	})

	stdout, stderr, _ := runCLI(t, proxy, "analyze", project, "--offline", "--format", "json")
	var doc struct {
		Projects []struct {
			Dependencies []struct {
				Analysis *struct {
					Crypto []json.RawMessage `json:"crypto"`
				} `json:"analysis"`
			} `json:"dependencies"`
			Summary map[string]int `json:"summary"`
		} `json:"projects"`
		TotalSummary map[string]int `json:"totalSummary"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil || len(doc.Projects) != 1 {
		t.Fatalf("parsing JSON: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	findings := 0
	for _, dep := range doc.Projects[0].Dependencies {
		if dep.Analysis != nil {
			findings += len(dep.Analysis.Crypto)
		}
	}
	for name, s := range map[string]map[string]int{"summary": doc.Projects[0].Summary, "totalSummary": doc.TotalSummary} {
		if _, ok := s["quantumSafe"]; !ok {
			t.Errorf("%s has no quantumSafe: %v", name, s)
		}
		if got := s["quantumVulnerable"] + s["quantumPartial"] + s["quantumSafe"] + s["quantumUnknown"]; got != findings || s["quantumSafe"] == 0 {
			t.Errorf("%s counters sum to %d with quantumSafe %d, want %d findings and a non-zero safe count: %v",
				name, got, s["quantumSafe"], findings, s)
		}
	}

	table, _, _ := runCLI(t, proxy, "analyze", project, "--offline")
	want := "| " + itoa(doc.Projects[0].Summary["quantumSafe"]) + " safe"
	if !strings.Contains(table, want) {
		t.Errorf("SUMMARY line does not carry %q:\n%s", want, table)
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// A requirements.txt "-r extra.txt" include and a "name @ url" line were
// dropped with no signal. Both are now named, by line, in the table and in
// JSON, and the URL itself is not copied into either.
func TestRequirementsLinesNotReadAreReported(t *testing.T) {
	proxy, _ := startConnectionLog(t)
	project := writeProject(t, map[string]string{
		"requirements.txt": "cryptography==42.0.0\nPyJWT==2.8.0\n-r extra.txt\nparamiko @ https://example.invalid/paramiko.tar.gz\n",
		"extra.txt":        "pycryptodome==3.20.0\n",
	})

	stdout, stderr, _ := runCLI(t, proxy, "analyze", project, "--offline", "--format", "json")
	var doc struct {
		Projects []struct {
			UnreadLines []struct {
				Line   int    `json:"line"`
				Name   string `json:"name"`
				Reason string `json:"reason"`
			} `json:"unreadLines"`
		} `json:"projects"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil || len(doc.Projects) != 1 {
		t.Fatalf("parsing JSON: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	unread := doc.Projects[0].UnreadLines
	if len(unread) != 2 || unread[0].Line != 3 || unread[0].Name != "extra.txt" ||
		unread[1].Line != 4 || unread[1].Name != "paramiko" {
		t.Fatalf("unreadLines = %+v, want line 3 extra.txt and line 4 paramiko", unread)
	}
	for _, u := range unread {
		if u.Reason == "" {
			t.Errorf("unread line %d has no reason", u.Line)
		}
	}

	for _, format := range []string{"json", "table", "markdown"} {
		out, _, _ := runCLI(t, proxy, "analyze", project, "--offline", "--format", format)
		if strings.Contains(out, "example.invalid") {
			t.Errorf("%s output copies the URL from the manifest:\n%s", format, out)
		}
		if format == "json" {
			continue
		}
		for _, want := range []string{"line 3", "extra.txt", "line 4", "paramiko", "did not read"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s output does not contain %q:\n%s", format, want, out)
			}
		}
	}
}
