// Copyright 2024-2025 CSNP (csnp.org)
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

// FormatterOptions configures formatter behavior.
type FormatterOptions struct {
	// ShowRemediation includes remediation guidance in output
	ShowRemediation bool
	// Verbose enables detailed output
	Verbose bool
}

// DefaultOptions returns default formatter options.
func DefaultOptions() FormatterOptions {
	return FormatterOptions{
		ShowRemediation: true, // Show remediation by default
		Verbose:         false,
	}
}

// Formatter formats scan results for output.
type Formatter interface {
	Format(result *types.ScanResult, w io.Writer) error
}

// FormatterWithOptions extends Formatter with options support.
type FormatterWithOptions interface {
	Formatter
	SetOptions(opts FormatterOptions)
}

// GetFormatter returns a formatter for the specified format.
func GetFormatter(format Format) (Formatter, error) {
	return GetFormatterWithOptions(format, DefaultOptions())
}

// GetFormatterWithOptions returns a formatter with custom options.
func GetFormatterWithOptions(format Format, opts FormatterOptions) (Formatter, error) {
	var f Formatter
	switch format {
	case FormatTable:
		f = &TableFormatter{Options: opts}
	case FormatJSON:
		f = &JSONFormatter{Indent: true}
	case FormatCBOM:
		f = &CBOMFormatter{}
	case FormatSARIF:
		f = &SARIFFormatter{Options: opts}
	case FormatMarkdown:
		f = &MarkdownFormatter{Options: opts}
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
	return f, nil
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
