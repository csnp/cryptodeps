// Copyright 2024-2025 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"encoding/json"
	"errors"
	"io"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// JSONFormatter formats scan results as JSON.
type JSONFormatter struct {
	Indent bool
}

// Format writes the scan result as JSON.
func (f *JSONFormatter) Format(result *types.ScanResult, w io.Writer) error {
	if result == nil {
		return errors.New("result cannot be nil")
	}
	if w == nil {
		return errors.New("writer cannot be nil")
	}
	encoder := json.NewEncoder(w)
	if f.Indent {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(result)
}
