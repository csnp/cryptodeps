// Copyright 2024 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"encoding/json"
	"io"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// JSONFormatter formats scan results as JSON.
type JSONFormatter struct {
	Indent bool
}

// Format writes the scan result as JSON.
func (f *JSONFormatter) Format(result *types.ScanResult, w io.Writer) error {
	encoder := json.NewEncoder(w)
	if f.Indent {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(result)
}
