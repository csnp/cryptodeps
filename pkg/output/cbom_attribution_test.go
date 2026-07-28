// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"encoding/json"
	"regexp"
	"testing"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// cycloneDXPrimitiveEnum is the closed set CycloneDX 1.6 allows for
// cryptoProperties.algorithmProperties.primitive.
var cycloneDXPrimitiveEnum = map[string]bool{
	"drbg": true, "mac": true, "block-cipher": true, "stream-cipher": true,
	"signature": true, "hash": true, "pke": true, "xof": true, "kdf": true,
	"key-agree": true, "kem": true, "ae": true, "combiner": true,
	"other": true, "unknown": true,
}

var uuidURNPattern = regexp.MustCompile(
	`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type decodedBOM struct {
	SerialNumber string `json:"serialNumber"`
	Components   []struct {
		Type             string `json:"type"`
		BOMRef           string `json:"bom-ref"`
		Name             string `json:"name"`
		Version          string `json:"version"`
		Purl             string `json:"purl"`
		Description      string `json:"description"`
		CryptoProperties *struct {
			AssetType           string `json:"assetType"`
			AlgorithmProperties *struct {
				Primitive string `json:"primitive"`
			} `json:"algorithmProperties"`
		} `json:"cryptoProperties"`
	} `json:"components"`
	Dependencies []struct {
		Ref       string   `json:"ref"`
		DependsOn []string `json:"dependsOn"`
	} `json:"dependencies"`
}

func renderCBOM(t *testing.T, result *types.ScanResult) decodedBOM {
	t.Helper()

	var buf bytes.Buffer
	if err := (&CBOMFormatter{}).Format(result, &buf); err != nil {
		t.Fatalf("format: %v", err)
	}
	var doc decodedBOM
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("CBOM is not valid JSON: %v", err)
	}
	return doc
}

func scanResultWithCrypto(depName, depVersion string, algorithms ...string) *types.ScanResult {
	crypto := make([]types.CryptoUsage, 0, len(algorithms))
	for _, algo := range algorithms {
		crypto = append(crypto, types.CryptoUsage{Algorithm: algo, Type: "signature"})
	}
	return &types.ScanResult{
		Project:   "testproject",
		Ecosystem: types.EcosystemPyPI,
		Dependencies: []types.DependencyResult{{
			Dependency: types.Dependency{
				Name:      depName,
				Version:   depVersion,
				Ecosystem: types.EcosystemPyPI,
			},
			Analysis: &types.PackageAnalysis{Crypto: crypto},
		}},
	}
}

// TestCBOMAttributesAlgorithmToDependency is the regression guard for issue #2.
// The previous output emitted only the algorithm, carrying the dependency's
// version but never its name, so {"name": "RSA", "version": "1.3.2"} could not
// be traced to the library that provided it.
func TestCBOMAttributesAlgorithmToDependency(t *testing.T) {
	doc := renderCBOM(t, scanResultWithCrypto("java-jwt", "4.4.0", "RS384"))

	var libRef, algoRef string
	for _, c := range doc.Components {
		switch c.Type {
		case "library":
			if c.Name != "java-jwt" {
				t.Errorf("library component name = %q, want java-jwt", c.Name)
			}
			libRef = c.BOMRef
		case "cryptographic-asset":
			if c.Name != "RS384" {
				t.Errorf("crypto asset name = %q, want RS384", c.Name)
			}
			algoRef = c.BOMRef
		}
	}

	if libRef == "" {
		t.Fatal("no library component emitted; the algorithm is unattributable")
	}
	if algoRef == "" {
		t.Fatal("no cryptographic-asset component emitted")
	}

	var linked bool
	for _, d := range doc.Dependencies {
		if d.Ref != libRef {
			continue
		}
		for _, on := range d.DependsOn {
			if on == algoRef {
				linked = true
			}
		}
	}
	if !linked {
		t.Errorf("dependency graph does not link %s to %s", libRef, algoRef)
	}
}

// TestCBOMDoesNotEmitUnresolvedMavenProperty covers the reporter's second
// example, where the algorithm component carried the literal build property
// ${java-jwt.version} as though it were a version.
func TestCBOMDoesNotEmitUnresolvedMavenProperty(t *testing.T) {
	doc := renderCBOM(t, scanResultWithCrypto("java-jwt", "${java-jwt.version}", "RS384"))

	for _, c := range doc.Components {
		if c.Version == "${java-jwt.version}" {
			t.Errorf("component %q emitted an unresolved build property as its version", c.Name)
		}
		if c.Purl == "pkg:pypi/java-jwt@${java-jwt.version}" {
			t.Errorf("purl %q embeds an unresolved build property", c.Purl)
		}
	}

	// The information must still be reachable rather than silently dropped.
	var described bool
	for _, c := range doc.Components {
		if c.Type == "library" && c.Description != "" {
			described = true
		}
	}
	if !described {
		t.Error("unresolved version constraint was dropped without explanation")
	}
}

// TestCBOMVersionIsConcreteNotAConstraint checks that range constraints do not
// masquerade as resolved versions.
func TestCBOMVersionIsConcreteNotAConstraint(t *testing.T) {
	tests := []struct {
		constraint  string
		wantVersion string
	}{
		{"==41.0.0", "41.0.0"},
		{"41.0.0", "41.0.0"},
		{"===1.2.3", "1.2.3"},
		{">=2.0", ""},
		{"^1.0", ""},
		{"~=3.1", ""},
		{"${java-jwt.version}", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.constraint, func(t *testing.T) {
			if got := resolveVersion(tt.constraint); got != tt.wantVersion {
				t.Errorf("resolveVersion(%q) = %q, want %q",
					tt.constraint, got, tt.wantVersion)
			}
		})
	}
}

// TestCBOMSerialNumberIsARealUUID guards the hardcoded all-zero serial number,
// which made every document share one identifier and did not match the
// CycloneDX urn:uuid pattern.
func TestCBOMSerialNumberIsARealUUID(t *testing.T) {
	first := renderCBOM(t, scanResultWithCrypto("cryptography", "41.0.0", "RSA"))
	second := renderCBOM(t, scanResultWithCrypto("cryptography", "41.0.0", "RSA"))

	if !uuidURNPattern.MatchString(first.SerialNumber) {
		t.Errorf("serialNumber %q does not match the CycloneDX urn:uuid pattern",
			first.SerialNumber)
	}
	if first.SerialNumber == "urn:uuid:00000000-0000-0000-0000-000000000000" {
		t.Error("serialNumber is the placeholder all-zero UUID")
	}
	if first.SerialNumber == second.SerialNumber {
		t.Error("two separate CBOMs share a serial number")
	}
}

// TestCBOMPrimitivesAreInSchemaEnum checks every emitted primitive against the
// CycloneDX enum, since a value outside it fails validation for the whole
// document.
func TestCBOMPrimitivesAreInSchemaEnum(t *testing.T) {
	categories := []string{"key-exchange", "encryption", "hash", "signature", "mac", "surprise"}
	algorithms := []string{"AES", "ChaCha20", "RSA", "ML-KEM", "SHA-256", "HMAC", "Whatever"}

	for _, category := range categories {
		for _, algorithm := range algorithms {
			got := cycloneDXPrimitive(category, algorithm)
			if !cycloneDXPrimitiveEnum[got] {
				t.Errorf("cycloneDXPrimitive(%q, %q) = %q, which is not in the CycloneDX enum",
					category, algorithm, got)
			}
		}
	}

	// Spot-check that the mapping is meaningful rather than uniformly "unknown".
	if got := cycloneDXPrimitive("key-exchange", "ECDH"); got != "key-agree" {
		t.Errorf("key-exchange mapped to %q, want key-agree", got)
	}
	if got := cycloneDXPrimitive("encryption", "AES"); got != "block-cipher" {
		t.Errorf("AES mapped to %q, want block-cipher", got)
	}
	if got := cycloneDXPrimitive("encryption", "RSA"); got != "pke" {
		t.Errorf("RSA encryption mapped to %q, want pke", got)
	}
}
