// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestDeepSourceCacheOfItsOwnIsRemovedAtExit is the regression test for the
// --deep source cache left behind in the temporary directory.
//
// Where there is no per-user cache directory, --deep keeps the source it
// fetches in a directory of the run's own and removes it when the run ends. It
// used to keep it in one fixed directory in the temporary directory, shared by
// every user of the machine, and never removed it.
func TestDeepSourceCacheOfItsOwnIsRemovedAtExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stub downloader is a shell script")
	}
	proxy, _ := startConnectionLog(t)

	// A stub npm that records the directory it runs in, which is inside the
	// source cache, and then fails, so the fetch reaches the cache and nothing
	// is downloaded.
	bin := t.TempDir()
	ranIn := filepath.Join(t.TempDir(), "npm-ran-in")
	stub := "#!/bin/sh\npwd -P > '" + ranIn + "'\nexit 1\n"
	if err := os.WriteFile(filepath.Join(bin, "npm"), []byte(stub), 0o755); err != nil {
		t.Fatalf("write stub npm: %v", err)
	}

	// One dependency the crypto database does not hold, so --deep fetches it.
	project := t.TempDir()
	manifest := `{"name":"fixture","version":"1.0.0","dependencies":{"cryptodeps-fixture-absent":"1.0.0"}}`
	if err := os.WriteFile(filepath.Join(project, "package.json"), []byte(manifest), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	tmp := t.TempDir()
	proxyURL := "http://" + proxy
	cmd := exec.Command(os.Args[0], "analyze", project, "--deep")
	cmd.Dir = t.TempDir()
	// No HOME, XDG_CACHE_HOME or LocalAppData, so there is no per-user cache
	// directory. The proxies answer every connection with 502, so the database
	// refresh fails here instead of reaching the network.
	cmd.Env = []string{
		runCLIEnv + "=1",
		"PATH=" + bin,
		"TMPDIR=" + tmp,
		"GOCOVERDIR=" + t.TempDir(),
		"HTTPS_PROXY=" + proxyURL,
		"HTTP_PROXY=" + proxyURL,
		"https_proxy=" + proxyURL,
		"http_proxy=" + proxyURL,
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	// The exit status is not the question here: the dependency could not be
	// fetched, which the report says, and the test asks what was left behind.
	_ = cmd.Run()

	// Guard the fixture: the fetch has to have run inside a cache in the
	// temporary directory, or that directory being empty afterwards says
	// nothing about the cache.
	recorded, err := os.ReadFile(ranIn)
	if err != nil {
		t.Fatalf("--deep never ran the downloader, so this test cannot tell where the source "+
			"cache was: %v\nstderr:\n%s", err, stderr.String())
	}
	physicalTmp, err := filepath.EvalSymlinks(tmp)
	if err != nil {
		t.Fatalf("resolve %s: %v", tmp, err)
	}
	if dir := strings.TrimSpace(string(recorded)); !strings.HasPrefix(dir, physicalTmp+string(filepath.Separator)) {
		t.Fatalf("the downloader ran in %s, outside the temporary directory %s, so this test "+
			"is not looking at a source cache of the run's own", dir, physicalTmp)
	}

	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatalf("read %s: %v", tmp, err)
	}
	var left []string
	for _, e := range entries {
		left = append(left, e.Name())
	}
	if len(left) != 0 {
		t.Errorf("the run left %v in the temporary directory\nstderr:\n%s", left, stderr.String())
	}
}
