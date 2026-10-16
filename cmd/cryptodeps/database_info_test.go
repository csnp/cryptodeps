// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/csnp/qramm-cryptodeps/internal/database"
	"github.com/csnp/qramm-cryptodeps/pkg/output"
	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// The formatter analyze uses is told which database the scan read, from the
// database object itself, so the report cannot name one database while the
// findings came from another.
func TestAnalyzeReportsNameTheDatabaseTheScanRead(t *testing.T) {
	db := database.NewEmbedded()
	packages := db.Stats().TotalPackages
	result := types.AggregateResults("/project", []*types.ScanResult{{
		Project: "/project", Manifest: "/project/go.mod", Ecosystem: types.EcosystemGo,
	}})

	table, err := newFormatter(output.FormatTable, db)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := table.FormatMulti(result, &buf); err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("Database: built-in, %d packages\n", packages); !strings.Contains(buf.String(), want) {
		t.Errorf("table does not contain %q:\n%s", want, buf.String())
	}

	jsonFormatter, err := newFormatter(output.FormatJSON, db)
	if err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	if err := jsonFormatter.FormatMulti(result, &buf); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Database *types.DatabaseInfo `json:"database"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Database == nil || *doc.Database != db.Info() {
		t.Errorf("JSON database = %+v, want %+v", doc.Database, db.Info())
	}
}
