// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package source

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// TestFetchRefusesASpecSmuggledThroughTheName is the regression test for the
// bypass that survived the first attempt at closing this class.
//
// The guard screened the dependency name for the spellings of a local path and
// treated it as one opaque string. `npm pack` does not: it splits `name@spec`
// on the first '@' after index 0, so `x@/tmp/victim` presents a guard-passing
// name to the guard and a directory to npm. Reproduced end to end against the
// 1.3.0 candidate binary: npm packed the victim directory, ran its `prepare`
// script, and the analyzer published the victim's files as that dependency's
// source, with deepAnalyzed set and nothing on stderr.
//
// The equivalent for PyPI is a PEP 508 direct reference, which arrives as a
// Poetry or Pipfile table key and reaches `pip download` the same way.
func TestFetchRefusesASpecSmuggledThroughTheName(t *testing.T) {
	withoutFetchTools(t)

	cacheDir := t.TempDir()
	f := NewFetcher(cacheDir)

	cases := []struct {
		name      string
		ecosystem types.Ecosystem
		dep       string
	}{
		{"npm absolute path after the name", types.EcosystemNPM, "x@/tmp/victim"},
		{"npm file: spec after the name", types.EcosystemNPM, "x@file:../../victim"},
		{"npm home-relative spec after the name", types.EcosystemNPM, "x@~/victim"},
		{"npm scoped name with a spec", types.EcosystemNPM, "@scope/pkg@/tmp/victim"},
		{"npm git spec after the name", types.EcosystemNPM, "x@git+file:///tmp/victim"},
		{"pypi PEP 508 direct reference", types.EcosystemPyPI, "victimpkg @ file:///tmp/victim"},
		{"pypi direct reference without spaces", types.EcosystemPyPI, "victimpkg@file:///tmp/victim"},
		{"go module path with a traversal", types.EcosystemGo, "example.com/../../victim"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := f.Fetch(types.Dependency{Name: tc.dep, Ecosystem: tc.ecosystem})
			if err == nil {
				t.Fatalf("dependency name %q was fetched to %q: the package manager reads it "+
					"as a name plus a spec, and the spec selects something on this machine",
					tc.dep, dir)
			}
			// The reason is the assertion. PATH is emptied by this test, so a
			// fetch that got as far as the downloader would fail anyway, and a
			// test satisfied by err != nil would pass against the code that
			// executed the victim's prepare script.
			if !strings.Contains(err.Error(), "is not a valid") {
				t.Errorf("name %q failed for the wrong reason: %v", tc.dep, err)
			}
			if dir != "" {
				t.Errorf("returned path %q alongside an error", dir)
			}
		})
	}
}

// TestFetchAcceptsRealPackageNames is the other half of the bound.
//
// Holding names to a grammar is only safe if the grammar is the registry's own.
// Every name here is a package that exists and that deep analysis fetches
// today, so a pattern tightened far enough to break real scans fails here
// rather than in a user's CI.
func TestFetchAcceptsRealPackageNames(t *testing.T) {
	withoutFetchTools(t)

	f := NewFetcher(t.TempDir())

	cases := []struct {
		ecosystem types.Ecosystem
		names     []string
	}{
		{types.EcosystemNPM, []string{
			"ejs", "crypto-js", "node-forge", "@noble/post-quantum", "@types/node",
			"lodash.merge", "jsonwebtoken", "@scope/pkg.with.dots",
		}},
		{types.EcosystemPyPI, []string{
			"cryptography", "pycryptodome", "python-dateutil", "zope.interface",
			"ruamel.yaml.clib", "Django", "typing_extensions",
		}},
		{types.EcosystemGo, []string{
			"github.com/spf13/cobra", "golang.org/x/crypto", "gopkg.in/yaml.v3",
			"github.com/BurntSushi/toml", "github.com/csnp/qramm-cryptodeps/v2",
		}},
	}

	for _, tc := range cases {
		for _, name := range tc.names {
			t.Run(name, func(t *testing.T) {
				if err := validPackageName(tc.ecosystem, name); err != nil {
					t.Errorf("a real %s package name is refused: %v", tc.ecosystem, err)
				}
				// And through Fetch, where a refusal would surface as the same
				// message rather than as a download failure.
				_, err := f.Fetch(types.Dependency{Name: name, Ecosystem: tc.ecosystem})
				if err != nil && strings.Contains(err.Error(), "is not a valid") {
					t.Errorf("Fetch refuses a real %s package name: %v", tc.ecosystem, err)
				}
			})
		}
	}
}

// TestNpmPackRunsNoPackageScripts pins the control that holds when a spec is
// legitimately remote.
//
// `npm pack` runs a package's prepare and prepack scripts for any spec it
// resolves from a directory or a git repository, so fetching source in order to
// analyze it was a way to execute code chosen by the manifest under scan. VCS
// references are deliberately still fetched, which means the guards above are
// not the only thing standing between a scanned manifest and code execution.
func TestNpmPackRunsNoPackageScripts(t *testing.T) {
	root := t.TempDir()
	f := NewFetcher(filepath.Join(root, "cache"))

	// A stub npm that records the arguments it was given, so this asserts the
	// flag reaches the process rather than that a real npm behaved.
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0755); err != nil {
		t.Fatalf("create stub dir: %v", err)
	}
	argsFile := filepath.Join(root, "npm-args")
	stub := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argsFile + "\nexit 1\n"
	if err := os.WriteFile(filepath.Join(bin, "npm"), []byte(stub), 0755); err != nil {
		t.Fatalf("write npm stub: %v", err)
	}
	t.Setenv("PATH", bin)

	_, err := f.Fetch(types.Dependency{Name: "ejs", Version: "3.1.10", Ecosystem: types.EcosystemNPM})
	if err == nil {
		t.Fatal("the stub npm exits 1, so the fetch should have failed")
	}

	recorded, readErr := os.ReadFile(argsFile)
	if readErr != nil {
		t.Fatalf("the stub npm was never invoked, so this test asserts nothing: %v", readErr)
	}
	args := strings.Split(strings.TrimSpace(string(recorded)), "\n")
	var sawIgnoreScripts bool
	for _, a := range args {
		if a == "--ignore-scripts" {
			sawIgnoreScripts = true
		}
	}
	if !sawIgnoreScripts {
		t.Errorf("npm pack was invoked as %v, without --ignore-scripts: a fetched package's "+
			"prepare and prepack scripts run on the scanning host", args)
	}
}
