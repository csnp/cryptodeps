// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reachability

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRepeatedCallsInOneFunctionGiveOneTrace covers examples/vulnerable-demo,
// where one function calling ed25519.GenerateKey, Sign and Verify produced
// three identical traces from main, and the report printed "Called from:
// vulnerable-demo.main" three times for Ed25519. Two functions using the same
// algorithm still give a trace each.
func TestRepeatedCallsInOneFunctionGiveOneTrace(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"go.mod": "module example.com/demo\n\ngo 1.22\n",
		"main.go": `package main

import (
	"crypto/ed25519"
	"crypto/rand"
)

func main() {
	sign()
	verifyAgain()
}

func sign() {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig := ed25519.Sign(priv, []byte("m"))
	_ = ed25519.Verify(pub, []byte("m"), sig)
}

func verifyAgain() {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_ = ed25519.Verify(pub, []byte("m"), nil)
}
`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	traces, err := NewAnalyzer(dir).Analyze()
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	got := traces["Ed25519"]
	targets := make(map[string]int)
	for _, trace := range got {
		targets[trace.TargetFunc]++
	}
	want := map[string]int{"example.com/demo.sign": 1, "example.com/demo.verifyAgain": 1}
	if len(targets) != len(want) {
		t.Fatalf("Ed25519 traces end at %v, want one trace each at %v: %+v", targets, want, got)
	}
	for target, n := range want {
		if targets[target] != n {
			t.Errorf("%d trace(s) end at %s, want %d: %+v", targets[target], target, n, got)
		}
	}
}
