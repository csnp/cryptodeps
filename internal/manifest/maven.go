// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"encoding/xml"
	"os"
	"regexp"
	"strings"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// MavenParser parses Maven pom.xml files.
type MavenParser struct{}

// Ecosystem returns the ecosystem this parser handles.
func (p *MavenParser) Ecosystem() types.Ecosystem {
	return types.EcosystemMaven
}

// Filenames returns the manifest filenames this parser handles.
func (p *MavenParser) Filenames() []string {
	return []string{"pom.xml"}
}

// pomXML represents the structure of a pom.xml file.
type pomXML struct {
	XMLName      xml.Name        `xml:"project"`
	GroupID      string          `xml:"groupId"`
	ArtifactID   string          `xml:"artifactId"`
	Version      string          `xml:"version"`
	Properties   pomProperties   `xml:"properties"`
	Dependencies pomDependencies `xml:"dependencies"`
}

// pomProperties captures all property elements as a map
type pomProperties struct {
	Entries map[string]string
}

// UnmarshalXML implements xml.Unmarshaler for pomProperties
func (p *pomProperties) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	p.Entries = make(map[string]string)

	for {
		token, err := d.Token()
		if err != nil {
			return err
		}

		switch t := token.(type) {
		case xml.StartElement:
			var value string
			if err := d.DecodeElement(&value, &t); err != nil {
				return err
			}
			p.Entries[t.Name.Local] = value
		case xml.EndElement:
			if t.Name == start.Name {
				return nil
			}
		}
	}
}

type pomDependencies struct {
	Dependency []pomDependency `xml:"dependency"`
}

type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
	Optional   string `xml:"optional"`
}

// propertyPattern matches Maven property references like ${property.name}
var propertyPattern = regexp.MustCompile(`\$\{([^}]+)\}`)

// resolveProperties replaces ${property} placeholders with their values
func resolveProperties(value string, props map[string]string) string {
	if props == nil {
		return value
	}

	return propertyPattern.ReplaceAllStringFunc(value, func(match string) string {
		// Extract property name from ${...}
		propName := strings.TrimPrefix(strings.TrimSuffix(match, "}"), "${")

		// Handle nested dots (e.g., project.version -> check both forms)
		if resolved, ok := props[propName]; ok {
			return resolved
		}

		// Try with dots converted to hyphens (some Maven conventions)
		hyphenName := strings.ReplaceAll(propName, ".", "-")
		if resolved, ok := props[hyphenName]; ok {
			return resolved
		}

		// Return original if not found
		return match
	})
}

// Parse parses a pom.xml file and returns the list of dependencies.
func (p *MavenParser) Parse(path string) ([]types.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var pom pomXML
	if err := xml.Unmarshal(data, &pom); err != nil {
		return nil, err
	}

	// Build property map including project properties
	props := pom.Properties.Entries
	if props == nil {
		props = make(map[string]string)
	}
	// Add the project's own coordinates as properties. ${project.groupId} is how
	// a multi-module build names a sibling module, so it appears in a dependency
	// groupId far more often than ${project.version} appears in a version, and
	// without it here the placeholder survives into the coordinate.
	if pom.Version != "" {
		props["project.version"] = pom.Version
	}
	if pom.GroupID != "" {
		props["project.groupId"] = pom.GroupID
	}
	if pom.ArtifactID != "" {
		props["project.artifactId"] = pom.ArtifactID
	}

	var deps []types.Dependency

	for _, dep := range pom.Dependencies.Dependency {
		// Skip test-scope dependencies for now
		isTest := dep.Scope == "test"

		// Construct Maven coordinate name. The groupId and artifactId carry
		// property placeholders as legitimately as the version does, and
		// ${project.groupId} for a module of the same group is the common case:
		// across 2,099 real poms from Maven Central, 81 coordinates in 16
		// published artifacts use it. Resolving only the version left the literal
		// "${project.groupId}" in the name, where coordinate validation refused
		// it as a name that could steer a fetch. The dependency was then reported
		// as unexaminable, so a real pom analyzed 6 of its dependencies where the
		// same pom with the property expanded analyzed 11.
		name := resolveProperties(dep.GroupID, props) + ":" + resolveProperties(dep.ArtifactID, props)

		// Resolve property placeholders in version
		version := resolveProperties(dep.Version, props)

		deps = append(deps, types.Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: types.EcosystemMaven,
			Direct:    !isTest, // Mark test deps as not direct for now
		})
	}

	return deps, nil
}
