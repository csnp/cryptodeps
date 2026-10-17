// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/csnp/qramm-cryptodeps/internal/analyzer"
	"github.com/csnp/qramm-cryptodeps/internal/database"
	"github.com/csnp/qramm-cryptodeps/pkg/output"
)

// TestReleaseSmokeNamesEveryFieldThatVariesBetweenRuns covers the release smoke
// test, which named JSON scanDate and CBOM serialNumber as the fields to
// normalize before comparing runs, while each dependency's
// analysis.analysis.date in JSON and metadata.timestamp in CBOM differ between
// runs too. The same scan is run twice, more than a second apart because the
// CBOM timestamp has one-second resolution, each time with a database built
// afresh as each run of the command builds it, and every field that differs
// must be named in the checklist. The checklist says the other three formats
// have none, so they must not differ at all.
func TestReleaseSmokeNamesEveryFieldThatVariesBetweenRuns(t *testing.T) {
	const file = "docs/testing/release-smoke.md"
	section := markdownSection(t, readRepoFile(t, file), file, "3. Every output format")

	formats := []output.Format{output.FormatTable, output.FormatJSON, output.FormatCBOM,
		output.FormatSARIF, output.FormatMarkdown}
	run := func() map[output.Format][]byte {
		a := analyzer.New(database.NewEmbedded(), analyzer.Options{Offline: true, Reachability: true})
		result, err := a.AnalyzeAll(filepath.Join(repoRoot, "testdata", "fixtures"))
		if err != nil {
			t.Fatalf("scanning the fixtures: %v", err)
		}
		docs := make(map[output.Format][]byte)
		for _, format := range formats {
			f, err := output.GetFormatter(format)
			if err != nil {
				t.Fatalf("GetFormatter(%s): %v", format, err)
			}
			var buf bytes.Buffer
			if err := f.FormatMulti(result, &buf); err != nil {
				t.Fatalf("FormatMulti(%s): %v", format, err)
			}
			docs[format] = buf.Bytes()
		}
		return docs
	}
	first := run()
	time.Sleep(1100 * time.Millisecond)
	second := run()

	for _, format := range []output.Format{output.FormatJSON, output.FormatCBOM} {
		var a, b any
		if err := json.Unmarshal(first[format], &a); err != nil {
			t.Fatalf("decoding %s: %v", format, err)
		}
		if err := json.Unmarshal(second[format], &b); err != nil {
			t.Fatalf("decoding %s: %v", format, err)
		}
		paths := differingPaths(a, b, "")
		// Both carry the time of the run, so a comparison that finds nothing
		// compared nothing.
		if len(paths) == 0 {
			t.Fatalf("two runs a second apart wrote identical %s, so this asserts nothing", format)
		}
		for _, path := range paths {
			if name := checklistName(path); !strings.Contains(section, "`"+name+"`") {
				t.Errorf("%s field %s differs between two runs of the same scan, and %s does not "+
					"name `%s` among the fields to normalize", format, path, file, name)
			}
		}
	}
	for _, format := range []output.Format{output.FormatTable, output.FormatSARIF, output.FormatMarkdown} {
		if !bytes.Equal(first[format], second[format]) {
			t.Errorf("%s differs between two runs of the same scan, and %s says it has no field to normalize",
				format, file)
		}
	}
}

// differingPaths returns the paths, as ".a[].b", of the values that differ
// between two decoded JSON documents of the same shape.
func differingPaths(a, b any, path string) []string {
	seen := make(map[string]bool)
	var walk func(a, b any, path string)
	walk = func(a, b any, path string) {
		switch x := a.(type) {
		case map[string]any:
			y, _ := b.(map[string]any)
			for k, v := range x {
				walk(v, y[k], path+"."+k)
			}
		case []any:
			y, _ := b.([]any)
			for i, v := range x {
				var w any
				if i < len(y) {
					w = y[i]
				}
				walk(v, w, path+"[]")
			}
		default:
			if a != b {
				seen[path] = true
			}
		}
	}
	walk(a, b, path)
	paths := make([]string, 0, len(seen))
	for p := range seen {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}

// checklistName is how the checklist names a field: relative to the nearest
// array element holding it, or to the document when none does. A JSON path of
// .projects[].dependencies[].analysis.analysis.date is named
// analysis.analysis.date, and .metadata.timestamp is metadata.timestamp.
func checklistName(path string) string {
	if i := strings.LastIndex(path, "[]."); i >= 0 {
		return path[i+len("[]."):]
	}
	return strings.TrimPrefix(path, ".")
}
