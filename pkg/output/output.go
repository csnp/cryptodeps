// Copyright 2024 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

// Package output provides formatters for scan results.
package output

import (
	"fmt"
	"io"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// Format represents an output format.
type Format string

const (
	FormatTable    Format = "table"
	FormatJSON     Format = "json"
	FormatCBOM     Format = "cbom"
	FormatSARIF    Format = "sarif"
	FormatMarkdown Format = "markdown"
)

// Formatter formats scan results for output.
type Formatter interface {
	Format(result *types.ScanResult, w io.Writer) error
}

// GetFormatter returns a formatter for the specified format.
func GetFormatter(format Format) (Formatter, error) {
	switch format {
	case FormatTable:
		return &TableFormatter{}, nil
	case FormatJSON:
		return &JSONFormatter{Indent: true}, nil
	case FormatCBOM:
		return &CBOMFormatter{}, nil
	case FormatSARIF:
		return &SARIFFormatter{}, nil
	case FormatMarkdown:
		return &MarkdownFormatter{}, nil
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

// ParseFormat parses a format string.
func ParseFormat(s string) (Format, error) {
	switch s {
	case "table", "":
		return FormatTable, nil
	case "json":
		return FormatJSON, nil
	case "cbom":
		return FormatCBOM, nil
	case "sarif":
		return FormatSARIF, nil
	case "markdown", "md":
		return FormatMarkdown, nil
	default:
		return "", fmt.Errorf("unsupported format: %s", s)
	}
}
