// Copyright 2024-2025 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"encoding/xml"
	"os"

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
	XMLName      xml.Name       `xml:"project"`
	GroupID      string         `xml:"groupId"`
	ArtifactID   string         `xml:"artifactId"`
	Version      string         `xml:"version"`
	Dependencies pomDependencies `xml:"dependencies"`
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

	var deps []types.Dependency

	for _, dep := range pom.Dependencies.Dependency {
		// Skip test-scope dependencies for now
		isTest := dep.Scope == "test"

		// Construct Maven coordinate name
		name := dep.GroupID + ":" + dep.ArtifactID

		deps = append(deps, types.Dependency{
			Name:      name,
			Version:   dep.Version,
			Ecosystem: types.EcosystemMaven,
			Direct:    !isTest, // Mark test deps as not direct for now
		})
	}

	return deps, nil
}
