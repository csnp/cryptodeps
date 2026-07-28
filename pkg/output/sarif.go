// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
	"github.com/csnp/qramm-cryptodeps/pkg/version"
)

// SARIFFormatter formats scan results as SARIF for GitHub Security integration.
type SARIFFormatter struct {
	Options FormatterOptions
}

// sarifLog represents a SARIF log structure.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool               sarifTool                    `json:"tool"`
	OriginalURIBaseIDs map[string]sarifArtifactBase `json:"originalUriBaseIds,omitempty"`
	Invocations        []sarifInvocation            `json:"invocations,omitempty"`
	Results            []sarifResult                `json:"results"`
}

// sarifInvocation carries whether the run was complete. A manifest that could
// not be read is reported here as a tool execution notification and clears
// executionSuccessful, which is how a SARIF consumer learns the scan did not
// cover everything it was pointed at.
type sarifInvocation struct {
	ExecutionSuccessful       bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

// sarifArtifactBase declares what a uriBaseId resolves to, so a consumer can
// turn the repository-relative uri on each result back into a real file.
type sarifArtifactBase struct {
	URI string `json:"uri"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	SemanticVersion string     `json:"semanticVersion,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string             `json:"id"`
	Name             string             `json:"name"`
	ShortDescription sarifMessage       `json:"shortDescription"`
	FullDescription  sarifMessage       `json:"fullDescription"`
	DefaultConfig    sarifDefaultConfig `json:"defaultConfiguration"`
	HelpURI          string             `json:"helpUri,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifDefaultConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID    string           `json:"ruleId"`
	Level     string           `json:"level"`
	Message   sarifMessage     `json:"message"`
	Locations []sarifLocation  `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

// sarifURIBaseID names the base that every result uri is relative to.
const sarifURIBaseID = "SRCROOT"

// Format writes the scan result as SARIF.
func (f *SARIFFormatter) Format(result *types.ScanResult, w io.Writer) error {
	if result == nil {
		return errors.New("result cannot be nil")
	}
	if w == nil {
		return errors.New("writer cannot be nil")
	}
	root := result.Project
	if root == "" {
		root = filepath.Dir(result.Manifest)
	}
	return f.write(w, root, []*types.ScanResult{result}, nil)
}

// FormatMulti writes multi-project scan results as SARIF.
// Every project contributes its own results, each located at that project's own
// manifest. An earlier version merged all projects into one synthetic result
// whose manifest was the literal string "multiple", so every alert in the file
// pointed at a path that does not exist and nothing could be ingested.
func (f *SARIFFormatter) FormatMulti(result *types.MultiProjectResult, w io.Writer) error {
	if result == nil {
		return errors.New("result cannot be nil")
	}
	if w == nil {
		return errors.New("writer cannot be nil")
	}
	return f.write(w, result.RootPath, result.Projects, result.Skipped)
}

// write emits one SARIF run covering every supplied project.
func (f *SARIFFormatter) write(w io.Writer, root string, projects []*types.ScanResult, skipped []types.SkippedManifest) error {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		absRoot = root
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:            version.DisplayName,
						Version:         version.Version(),
						SemanticVersion: version.Version(),
						InformationURI:  version.InformationURI,
						Rules:           make([]sarifRule, 0),
					},
				},
				OriginalURIBaseIDs: map[string]sarifArtifactBase{
					sarifURIBaseID: {URI: "file://" + filepath.ToSlash(absRoot) + "/"},
				},
				Results: make([]sarifResult, 0),
			},
		},
	}

	// Record unread manifests as execution notifications. Emitting results
	// without saying that part of the input was never read would let a consumer
	// treat an incomplete scan as a complete one.
	invocation := sarifInvocation{ExecutionSuccessful: len(skipped) == 0}
	for _, s := range skipped {
		uri, baseID := sarifArtifactURI(absRoot, s.Path)
		invocation.ToolExecutionNotifications = append(invocation.ToolExecutionNotifications, sarifNotification{
			Level:   "error",
			Message: sarifMessage{Text: "manifest found but not analyzed: " + s.Reason},
			Locations: []sarifLocation{
				{PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: uri, URIBaseID: baseID},
				}},
			},
		})
	}
	log.Runs[0].Invocations = []sarifInvocation{invocation}

	rulesMap := make(map[string]bool)
	for _, result := range projects {
		if result == nil {
			continue
		}
		uri, baseID := sarifArtifactURI(absRoot, result.Manifest)

		for _, dep := range result.Dependencies {
			if dep.Analysis == nil || len(dep.Analysis.Crypto) == 0 {
				continue
			}

			for _, crypto := range dep.Analysis.Crypto {
				ruleID := "CRYPTO-" + crypto.Algorithm

				// Add rule if not already added
				if !rulesMap[ruleID] {
					rule := sarifRule{
						ID:   ruleID,
						Name: crypto.Algorithm + " Usage",
						ShortDescription: sarifMessage{
							Text: "Dependency uses " + crypto.Algorithm,
						},
						FullDescription: sarifMessage{
							Text: "A dependency uses " + crypto.Algorithm + " which has quantum risk: " + string(crypto.QuantumRisk),
						},
						DefaultConfig: sarifDefaultConfig{
							Level: severityToSARIFLevel(crypto.Severity),
						},
					}
					log.Runs[0].Tool.Driver.Rules = append(log.Runs[0].Tool.Driver.Rules, rule)
					rulesMap[ruleID] = true
				}

				// Build message with remediation if available
				msgText := dep.Dependency.Name + "@" + dep.Dependency.Version + " uses " + crypto.Algorithm + " (Quantum Risk: " + string(crypto.QuantumRisk) + ")"
				if f.Options.ShowRemediation && crypto.Remediation != "" {
					msgText += ". Remediation: " + crypto.Remediation
				}

				res := sarifResult{
					RuleID: ruleID,
					Level:  severityToSARIFLevel(crypto.Severity),
					Message: sarifMessage{
						Text: msgText,
					},
					Locations: []sarifLocation{
						{
							PhysicalLocation: sarifPhysicalLocation{
								ArtifactLocation: sarifArtifactLocation{
									URI:       uri,
									URIBaseID: baseID,
								},
							},
						},
					},
				}
				log.Runs[0].Results = append(log.Runs[0].Results, res)
			}
		}
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(log)
}

// sarifArtifactURI expresses a manifest path relative to the scan root, which is
// the form SARIF consumers such as GitHub code scanning need in order to attach
// an alert to a file in the repository. A manifest that does not sit under the
// root (which a caller can produce by passing an explicit file path) falls back
// to an absolute file URI with no base, since a relative path would be a lie.
func sarifArtifactURI(absRoot, manifestPath string) (uri string, baseID string) {
	if manifestPath == "" {
		return "", ""
	}
	absManifest, err := filepath.Abs(manifestPath)
	if err != nil {
		return filepath.ToSlash(manifestPath), ""
	}
	rel, err := filepath.Rel(absRoot, absManifest)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "file://" + filepath.ToSlash(absManifest), ""
	}
	return filepath.ToSlash(rel), sarifURIBaseID
}

// severityToSARIFLevel converts a severity to SARIF level.
func severityToSARIFLevel(severity types.Severity) string {
	switch severity {
	case types.SeverityCritical, types.SeverityHigh:
		return "error"
	case types.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

