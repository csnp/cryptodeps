// Copyright 2024-2025 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"encoding/json"
	"errors"
	"io"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// SARIFFormatter formats scan results as SARIF for GitHub Security integration.
type SARIFFormatter struct {
	Options FormatterOptions
}

// sarifLog represents a SARIF log structure.
type sarifLog struct {
	Schema  string      `json:"$schema"`
	Version string      `json:"version"`
	Runs    []sarifRun  `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string       `json:"name"`
	Version        string       `json:"version"`
	InformationURI string       `json:"informationUri"`
	Rules          []sarifRule  `json:"rules"`
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
	URI string `json:"uri"`
}

// Format writes the scan result as SARIF.
func (f *SARIFFormatter) Format(result *types.ScanResult, w io.Writer) error {
	if result == nil {
		return errors.New("result cannot be nil")
	}
	if w == nil {
		return errors.New("writer cannot be nil")
	}
	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "CryptoDeps",
						Version:        "1.0.0",
						InformationURI: "https://github.com/csnp/qramm-cryptodeps",
						Rules:          make([]sarifRule, 0),
					},
				},
				Results: make([]sarifResult, 0),
			},
		},
	}

	// Add rules and results for each finding
	rulesMap := make(map[string]bool)
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
						Text: "The dependency " + dep.Dependency.Name + " uses " + crypto.Algorithm + " which has quantum risk: " + string(crypto.QuantumRisk),
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

			// Add result
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
								URI: result.Manifest,
							},
						},
					},
				},
			}
			log.Runs[0].Results = append(log.Runs[0].Results, res)
		}
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(log)
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
