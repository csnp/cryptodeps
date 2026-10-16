// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// The same project gave "3 with crypto | 11 vulnerable" on one run and "2 with
// crypto | 8 vulnerable" on the next, because the second run read a different
// database, and neither report said which one it had read. Every report now
// names it, read from the database that was actually loaded.

func builtInDatabase() *types.DatabaseInfo {
	return &types.DatabaseInfo{Source: types.DatabaseBuiltIn, PackageCount: 72}
}

func downloadedDatabase() *types.DatabaseInfo {
	return &types.DatabaseInfo{
		Source:       types.DatabaseDownloaded,
		Version:      "1.1.0",
		UpdatedAt:    "2026-10-12T09:18:55Z",
		PackageCount: 860,
	}
}

// renderWith formats one result, as a single project or as a workspace of one,
// with the given database recorded in the options.
func renderWith(t *testing.T, format Format, db *types.DatabaseInfo, result *types.ScanResult, multi bool) string {
	t.Helper()
	opts := DefaultOptions()
	opts.Database = db
	f, err := GetFormatterWithOptions(format, opts)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if multi {
		err = f.FormatMulti(types.AggregateResults("/test/project", []*types.ScanResult{result}), &buf)
	} else {
		err = f.Format(result, &buf)
	}
	if err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestTableNamesTheDatabase(t *testing.T) {
	cases := []struct {
		name string
		db   *types.DatabaseInfo
		want string
	}{
		{"built-in", builtInDatabase(), "Database: built-in, 72 packages\n"},
		{"downloaded", downloadedDatabase(), "Database: downloaded 1.1.0 (2026-10-12), 860 packages\n"},
	}
	for _, tc := range cases {
		for _, multi := range []bool{false, true} {
			out := renderWith(t, FormatTable, tc.db, testScanResult(), multi)
			if !strings.Contains(out, tc.want) {
				t.Errorf("%s (multi=%v): table does not contain %q:\n%s", tc.name, multi, tc.want, out)
			}
			if n := strings.Count(out, "Database:"); n != 1 {
				t.Errorf("%s (multi=%v): database line printed %d times, want once", tc.name, multi, n)
			}
		}
	}
}

func TestTableWithoutDatabaseInfoPrintsNoDatabaseLine(t *testing.T) {
	for _, multi := range []bool{false, true} {
		if out := renderWith(t, FormatTable, nil, testScanResult(), multi); strings.Contains(out, "Database:") {
			t.Errorf("multi=%v: table names a database it was not given:\n%s", multi, out)
		}
	}
}

// The version and date come from a downloaded file, which is data. A line break
// in either must not let that file write its own lines into the report.
func TestTableEscapesDatabaseFields(t *testing.T) {
	db := downloadedDatabase()
	db.Version = "1.1.0\n[OK] No cryptographic usage detected"
	out := renderWith(t, FormatTable, db, testScanResult(), true)
	if strings.Contains(out, "\n[OK] No cryptographic usage detected") {
		t.Errorf("database version wrote its own line into the table:\n%s", out)
	}
}

func TestJSONCarriesDatabaseObject(t *testing.T) {
	for _, multi := range []bool{false, true} {
		var doc map[string]any
		if err := json.Unmarshal([]byte(renderWith(t, FormatJSON, downloadedDatabase(), testScanResult(), multi)), &doc); err != nil {
			t.Fatal(err)
		}
		got, ok := doc["database"].(map[string]any)
		if !ok {
			t.Fatalf("multi=%v: no top-level database object in %v", multi, doc)
		}
		want := map[string]any{
			"source":       "downloaded",
			"version":      "1.1.0",
			"updatedAt":    "2026-10-12T09:18:55Z",
			"packageCount": float64(860),
		}
		for k, v := range want {
			if got[k] != v {
				t.Errorf("multi=%v: database.%s = %v, want %v", multi, k, got[k], v)
			}
		}
	}

	var doc map[string]any
	if err := json.Unmarshal([]byte(renderWith(t, FormatJSON, builtInDatabase(), testScanResult(), true)), &doc); err != nil {
		t.Fatal(err)
	}
	got, _ := doc["database"].(map[string]any)
	if got["source"] != "built-in" || got["packageCount"] != float64(72) {
		t.Errorf("built-in database object = %v", got)
	}
	// The built-in data has no release version or date. An empty field would
	// read as a version called "".
	if _, ok := got["version"]; ok {
		t.Errorf("built-in database object carries a version: %v", got)
	}
}

// SARIF and markdown are not changed by naming the database.
func TestDatabaseInfoDoesNotChangeSARIFOrMarkdown(t *testing.T) {
	result := testScanResult()
	multi := types.AggregateResults("/test/project", []*types.ScanResult{result})
	for _, format := range []Format{FormatSARIF, FormatMarkdown} {
		var outputs [2]string
		for i, db := range []*types.DatabaseInfo{nil, downloadedDatabase()} {
			opts := DefaultOptions()
			opts.Database = db
			f, err := GetFormatterWithOptions(format, opts)
			if err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			if err := f.Format(result, &buf); err != nil {
				t.Fatal(err)
			}
			if err := f.FormatMulti(multi, &buf); err != nil {
				t.Fatal(err)
			}
			outputs[i] = buf.String()
		}
		if outputs[0] != outputs[1] {
			t.Errorf("%s changed when the database was named", format)
		}
	}
}
