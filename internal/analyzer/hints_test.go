// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/csnp/qramm-cryptodeps/internal/database"
)

// TestDeepHintCountsOnePackageInTheSingular covers the hint "1 packages (50%)
// not in database", which JSON carries in hints.
func TestDeepHintCountsOnePackageInTheSingular(t *testing.T) {
	dir := t.TempDir()
	gomod := "module example.com/app\n\ngo 1.22\n\nrequire (\n" +
		"\tgolang.org/x/crypto v0.17.0\n" +
		"\tgithub.com/spf13/cobra v1.8.0\n" +
		")\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := New(database.NewEmbedded(), Options{Offline: true}).Analyze(filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Summary.NotInDatabase != 1 || result.Summary.TotalDependencies != 2 {
		t.Fatalf("the fixture is meant to leave one of two dependencies out of the database: %+v", result.Summary)
	}
	want := "1 package (50%) not in database."
	for _, hint := range result.Hints {
		if strings.HasPrefix(hint, want) {
			return
		}
	}
	t.Errorf("no hint starts %q: %q", want, result.Hints)
}
