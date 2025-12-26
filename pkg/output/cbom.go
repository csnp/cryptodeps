// Copyright 2024-2025 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// CBOMFormatter formats scan results as CycloneDX CBOM (JSON).
type CBOMFormatter struct{}

// cycloneDXBOM represents a CycloneDX BOM structure.
type cycloneDXBOM struct {
	BOMFormat    string             `json:"bomFormat"`
	SpecVersion  string             `json:"specVersion"`
	SerialNumber string             `json:"serialNumber"`
	Version      int                `json:"version"`
	Metadata     cycloneDXMetadata  `json:"metadata"`
	Components   []cycloneDXComponent `json:"components"`
}

type cycloneDXMetadata struct {
	Timestamp string           `json:"timestamp"`
	Tools     []cycloneDXTool  `json:"tools"`
}

type cycloneDXTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cycloneDXComponent struct {
	Type               string                    `json:"type"`
	Name               string                    `json:"name"`
	Version            string                    `json:"version"`
	CryptoProperties   *cycloneDXCryptoProperties `json:"cryptoProperties,omitempty"`
}

type cycloneDXCryptoProperties struct {
	AssetType             string `json:"assetType"`
	AlgorithmProperties   *cycloneDXAlgorithmProperties `json:"algorithmProperties,omitempty"`
}

type cycloneDXAlgorithmProperties struct {
	Primitive            string `json:"primitive"`
	ParameterSetIdentifier string `json:"parameterSetIdentifier,omitempty"`
	ExecutionEnvironment string `json:"executionEnvironment,omitempty"`
	ImplementationPlatform string `json:"implementationPlatform,omitempty"`
	CryptoFunctions      []string `json:"cryptoFunctions,omitempty"`
}

// Format writes the scan result as CycloneDX CBOM.
func (f *CBOMFormatter) Format(result *types.ScanResult, w io.Writer) error {
	if result == nil {
		return errors.New("result cannot be nil")
	}
	if w == nil {
		return errors.New("writer cannot be nil")
	}
	bom := cycloneDXBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: "urn:uuid:" + generateUUID(),
		Version:      1,
		Metadata: cycloneDXMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []cycloneDXTool{
				{
					Vendor:  "CSNP",
					Name:    "cryptodeps",
					Version: "1.0.0",
				},
			},
		},
		Components: make([]cycloneDXComponent, 0),
	}

	// Convert scan results to CycloneDX components
	for _, dep := range result.Dependencies {
		if dep.Analysis == nil || len(dep.Analysis.Crypto) == 0 {
			continue
		}

		for _, crypto := range dep.Analysis.Crypto {
			component := cycloneDXComponent{
				Type:    "cryptographic-asset",
				Name:    crypto.Algorithm,
				Version: dep.Dependency.Version,
				CryptoProperties: &cycloneDXCryptoProperties{
					AssetType: "algorithm",
					AlgorithmProperties: &cycloneDXAlgorithmProperties{
						Primitive: crypto.Type,
					},
				},
			}
			bom.Components = append(bom.Components, component)
		}
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(bom)
}

// generateUUID generates a simple UUID (placeholder implementation).
func generateUUID() string {
	// In production, use a proper UUID library
	return "00000000-0000-0000-0000-000000000000"
}
