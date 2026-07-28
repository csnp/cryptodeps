// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"encoding/json"
	"errors"
	"io"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
	"github.com/csnp/qramm-cryptodeps/pkg/version"
)

// JSONFormatter formats scan results as JSON.
type JSONFormatter struct {
	Indent bool
}

// jsonTool identifies the build that produced a document. Consumers need this
// to attribute a result to a scanner version; without it a stored report cannot
// be told apart from one produced by a build with different detection rules.
//
// This is deliberately not the same field as a dependency's
// analysis.toolVersion, which records who produced that database record, not who
// ran the scan.
type jsonTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func currentTool() jsonTool {
	return jsonTool{Name: version.Name, Version: version.Version()}
}

// jsonScanDocument is a ScanResult with the emitting tool's identity attached.
// The embedded pointer inlines the scan result's own fields, so the shape is
// the previous one plus a "tool" object.
type jsonScanDocument struct {
	Tool jsonTool `json:"tool"`
	*types.ScanResult
}

// jsonMultiDocument is the same wrapper for multi-project results.
type jsonMultiDocument struct {
	Tool jsonTool `json:"tool"`
	*types.MultiProjectResult
}

// Format writes the scan result as JSON.
func (f *JSONFormatter) Format(result *types.ScanResult, w io.Writer) error {
	if result == nil {
		return errors.New("result cannot be nil")
	}
	if w == nil {
		return errors.New("writer cannot be nil")
	}
	return f.encode(w, jsonScanDocument{Tool: currentTool(), ScanResult: result})
}

// FormatMulti writes multi-project scan results as JSON.
func (f *JSONFormatter) FormatMulti(result *types.MultiProjectResult, w io.Writer) error {
	if result == nil {
		return errors.New("result cannot be nil")
	}
	if w == nil {
		return errors.New("writer cannot be nil")
	}
	return f.encode(w, jsonMultiDocument{Tool: currentTool(), MultiProjectResult: result})
}

func (f *JSONFormatter) encode(w io.Writer, doc any) error {
	encoder := json.NewEncoder(w)
	if f.Indent {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(doc)
}
