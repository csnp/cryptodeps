// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
	"github.com/csnp/qramm-cryptodeps/pkg/version"
)

// CBOMFormatter formats scan results as CycloneDX CBOM (JSON).
type CBOMFormatter struct{}

// cycloneDXBOM represents a CycloneDX BOM structure.
type cycloneDXBOM struct {
	BOMFormat    string                `json:"bomFormat"`
	SpecVersion  string                `json:"specVersion"`
	SerialNumber string                `json:"serialNumber"`
	Version      int                   `json:"version"`
	Metadata     cycloneDXMetadata     `json:"metadata"`
	Components   []cycloneDXComponent  `json:"components"`
	Dependencies []cycloneDXDependency `json:"dependencies,omitempty"`
}

type cycloneDXMetadata struct {
	Timestamp string          `json:"timestamp"`
	Tools     []cycloneDXTool `json:"tools"`
}

type cycloneDXTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cycloneDXComponent struct {
	Type             string                     `json:"type"`
	BOMRef           string                     `json:"bom-ref"`
	Name             string                     `json:"name"`
	Version          string                     `json:"version,omitempty"`
	Purl             string                     `json:"purl,omitempty"`
	Description      string                     `json:"description,omitempty"`
	CryptoProperties *cycloneDXCryptoProperties `json:"cryptoProperties,omitempty"`
}

// cycloneDXDependency links a component to the components it depends on. This
// is how a cryptographic asset is attributed to the library that provides it.
type cycloneDXDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

type cycloneDXCryptoProperties struct {
	AssetType           string                        `json:"assetType"`
	AlgorithmProperties *cycloneDXAlgorithmProperties `json:"algorithmProperties,omitempty"`
}

type cycloneDXAlgorithmProperties struct {
	Primitive              string   `json:"primitive"`
	ParameterSetIdentifier string   `json:"parameterSetIdentifier,omitempty"`
	ExecutionEnvironment   string   `json:"executionEnvironment,omitempty"`
	ImplementationPlatform string   `json:"implementationPlatform,omitempty"`
	CryptoFunctions        []string `json:"cryptoFunctions,omitempty"`
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
					Vendor:  version.Vendor,
					Name:    version.Name,
					Version: version.Version(),
				},
			},
		},
		Components: make([]cycloneDXComponent, 0),
	}

	// Emit each dependency as a component, then each algorithm it provides as a
	// cryptographic asset, and link the two through the dependencies graph.
	//
	// Previously only the algorithm was emitted, carrying the dependency's
	// version but never its name, so a component reading {"name": "RSA",
	// "version": "1.3.2"} could not be traced back to the library it came from.
	seenAlgorithm := make(map[string]bool)
	dependsOn := make(map[string][]string)

	for _, dep := range result.Dependencies {
		if dep.Analysis == nil || len(dep.Analysis.Crypto) == 0 {
			continue
		}

		depName := dep.Dependency.Name
		depVersion := resolveVersion(dep.Dependency.Version)
		purl := "pkg:" + string(dep.Dependency.Ecosystem) + "/" + depName
		if depVersion != "" {
			purl += "@" + depVersion
		}
		// The bom-ref must stay unique per declared dependency even when two
		// entries resolve to the same purl because neither pinned a version.
		depRef := purl
		if depVersion == "" && strings.TrimSpace(dep.Dependency.Version) != "" {
			depRef = purl + "?constraint=" + url.QueryEscape(strings.TrimSpace(dep.Dependency.Version))
		}

		if _, exists := dependsOn[depRef]; !exists {
			bom.Components = append(bom.Components, cycloneDXComponent{
				Type:        "library",
				BOMRef:      depRef,
				Name:        depName,
				Version:     depVersion,
				Purl:        purl,
				Description: describeConstraint(dep.Dependency.Version),
			})
			dependsOn[depRef] = nil
		}

		for _, crypto := range dep.Analysis.Crypto {
			algorithmRef := "crypto:" + crypto.Algorithm

			if !seenAlgorithm[algorithmRef] {
				seenAlgorithm[algorithmRef] = true
				bom.Components = append(bom.Components, cycloneDXComponent{
					Type:   "cryptographic-asset",
					BOMRef: algorithmRef,
					Name:   crypto.Algorithm,
					CryptoProperties: &cycloneDXCryptoProperties{
						AssetType: "algorithm",
						AlgorithmProperties: &cycloneDXAlgorithmProperties{
							Primitive: cycloneDXPrimitive(crypto.Type, crypto.Algorithm),
						},
					},
				})
			}

			dependsOn[depRef] = append(dependsOn[depRef], algorithmRef)
		}
	}

	// Emit the graph in component order so output is deterministic.
	for _, component := range bom.Components {
		refs, ok := dependsOn[component.BOMRef]
		if !ok || len(refs) == 0 {
			continue
		}
		bom.Dependencies = append(bom.Dependencies, cycloneDXDependency{
			Ref:       component.BOMRef,
			DependsOn: dedupeStrings(refs),
		})
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(bom)
}

// mavenPropertyPattern matches an unresolved build property such as
// ${java-jwt.version}.
var mavenPropertyPattern = regexp.MustCompile(`^\$\{[^}]*\}$`)

// pinnedVersionPattern matches a constraint that names exactly one version,
// either bare (1.2.3) or pinned with == or === as pip and Maven write it.
var pinnedVersionPattern = regexp.MustCompile(`^(?:={2,3})?\s*v?(\d[\w.+-]*)$`)

// resolveVersion converts a declared dependency constraint into a concrete
// version, or an empty string when the constraint does not name one.
//
// CycloneDX `version` and the version segment of a purl are concrete versions,
// not ranges. Emitting ">=2.0" or "^1.0" there states a version that was never
// resolved, and emitting a Maven placeholder such as ${java-jwt.version} states
// one that does not exist at all. An absent version is honest; either of those
// is not. The original constraint is preserved separately in the component
// description so nothing is lost.
func resolveVersion(constraint string) string {
	constraint = strings.TrimSpace(constraint)
	if constraint == "" || mavenPropertyPattern.MatchString(constraint) {
		return ""
	}
	if match := pinnedVersionPattern.FindStringSubmatch(constraint); match != nil {
		return match[1]
	}
	return ""
}

// describeConstraint records the constraint exactly as the manifest declared it,
// for the cases where it could not be resolved to a single version.
func describeConstraint(constraint string) string {
	constraint = strings.TrimSpace(constraint)
	if constraint == "" || resolveVersion(constraint) != "" {
		return ""
	}
	if mavenPropertyPattern.MatchString(constraint) {
		return "Declared version is the unresolved build property " + constraint
	}
	return "Declared version constraint: " + constraint
}

// cycloneDXPrimitive maps this tool's algorithm categories onto the closed
// enum CycloneDX 1.6 allows for algorithmProperties.primitive. Emitting a value
// outside that enum makes the whole document fail schema validation.
func cycloneDXPrimitive(cryptoType, algorithm string) string {
	switch strings.ToLower(cryptoType) {
	case "key-exchange":
		return "key-agree"
	case "signature":
		return "signature"
	case "hash":
		return "hash"
	case "mac":
		return "mac"
	case "encryption":
		// "encryption" covers several CycloneDX primitives, so resolve it by
		// algorithm where the algorithm is recognized.
		switch strings.ToUpper(algorithm) {
		case "AES", "3DES", "DES", "BLOWFISH", "CAMELLIA", "IDEA", "CAST5", "SEED", "ARIA":
			return "block-cipher"
		case "CHACHA20", "RC4", "SALSA20":
			return "stream-cipher"
		case "RSA", "ELGAMAL":
			return "pke"
		case "ML-KEM", "KYBER":
			return "kem"
		}
		return "other"
	default:
		// An unrecognized category is reported as unknown rather than guessed.
		return "unknown"
	}
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// generateUUID returns a random RFC 4122 version 4 UUID. Every CBOM previously
// carried the same all-zero serial number, so documents from different scans
// were indistinguishable and the value did not match the CycloneDX urn:uuid
// pattern.
func generateUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is not recoverable here, and emitting a fixed
		// serial number would reintroduce the collision this replaces.
		panic("cbom: cannot read random bytes for serial number: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// FormatMulti writes multi-project scan results as CBOM.
// It merges all crypto findings from all projects into a single CBOM.
func (f *CBOMFormatter) FormatMulti(result *types.MultiProjectResult, w io.Writer) error {
	if result == nil {
		return errors.New("result cannot be nil")
	}
	if w == nil {
		return errors.New("writer cannot be nil")
	}

	// Create a merged scan result for CBOM output
	merged := &types.ScanResult{
		Project:   result.RootPath,
		Manifest:  "multiple",
		Ecosystem: types.EcosystemUnknown,
		ScanDate:  result.ScanDate,
		Summary:   result.TotalSummary,
	}

	// Collect all dependencies from all projects
	for _, project := range result.Projects {
		merged.Dependencies = append(merged.Dependencies, project.Dependencies...)
	}

	return f.Format(merged, w)
}
