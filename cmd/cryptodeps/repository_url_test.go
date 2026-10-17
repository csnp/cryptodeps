// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/csnp/qramm-cryptodeps/internal/analyzer"
	"github.com/csnp/qramm-cryptodeps/internal/database"
	"github.com/csnp/qramm-cryptodeps/pkg/output"
	"github.com/csnp/qramm-cryptodeps/pkg/types"
	buildinfo "github.com/csnp/qramm-cryptodeps/pkg/version"
)

// TestToolURLsNameTheRepositoryReleasesArePublishedTo covers SARIF's
// informationUri and the markdown footer naming github.com/csnp/qramm-cryptodeps
// while `update` downloads the database from github.com/csnp/cryptodeps. The
// repository was renamed, and the release configuration names it as it is now,
// so every repository URL the tool writes or fetches from names that one.
func TestToolURLsNameTheRepositoryReleasesArePublishedTo(t *testing.T) {
	var cfg struct {
		Release struct {
			GitHub struct {
				Owner string `yaml:"owner"`
				Name  string `yaml:"name"`
			} `yaml:"github"`
		} `yaml:"release"`
	}
	if err := yaml.Unmarshal([]byte(readRepoFile(t, ".goreleaser.yml")), &cfg); err != nil {
		t.Fatalf("reading .goreleaser.yml: %v", err)
	}
	if cfg.Release.GitHub.Owner == "" || cfg.Release.GitHub.Name == "" {
		t.Fatalf(".goreleaser.yml names no release repository: %+v", cfg.Release.GitHub)
	}
	repo := cfg.Release.GitHub.Owner + "/" + cfg.Release.GitHub.Name

	if want := "https://github.com/" + repo; buildinfo.InformationURI != want {
		t.Errorf("InformationURI is %q, want %q", buildinfo.InformationURI, want)
	}
	if want := "https://api.github.com/repos/" + repo + "/releases"; database.DefaultRepoAPI != want {
		t.Errorf("DefaultRepoAPI is %q, want %q", database.DefaultRepoAPI, want)
	}

	var sarif bytes.Buffer
	if err := (&output.SARIFFormatter{}).Format(&types.ScanResult{}, &sarif); err != nil {
		t.Fatalf("writing SARIF: %v", err)
	}
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					InformationURI string `json:"informationUri"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(sarif.Bytes(), &doc); err != nil || len(doc.Runs) == 0 {
		t.Fatalf("decoding the SARIF document: %v\n%s", err, sarif.String())
	}
	if got := doc.Runs[0].Tool.Driver.InformationURI; got != buildinfo.InformationURI {
		t.Errorf("SARIF informationUri is %q, want %q", got, buildinfo.InformationURI)
	}

	var markdown bytes.Buffer
	if err := (&output.MarkdownFormatter{Options: output.DefaultOptions()}).Format(&types.ScanResult{}, &markdown); err != nil {
		t.Fatalf("writing markdown: %v", err)
	}
	if want := "[CryptoDeps](" + buildinfo.InformationURI + ")"; !strings.Contains(markdown.String(), want) {
		t.Errorf("the markdown footer does not link %s:\n%s", buildinfo.InformationURI, markdown.String())
	}
}

// TestDocsSARIFExampleShowsTheInformationURITheToolWrites holds the SARIF
// example on the output formats page to the URL the formatter writes.
func TestDocsSARIFExampleShowsTheInformationURITheToolWrites(t *testing.T) {
	const file = "docs/output-formats.md"
	section := markdownSection(t, readRepoFile(t, file), file, "SARIF (Static Analysis Results Interchange Format)")
	matches := regexp.MustCompile(`"informationUri":\s*"([^"]*)"`).FindAllStringSubmatch(section, -1)
	if len(matches) == 0 {
		t.Fatalf("the SARIF example in %s shows no informationUri", file)
	}
	for _, m := range matches {
		if m[1] != buildinfo.InformationURI {
			t.Errorf("the SARIF example in %s shows informationUri %q, the tool writes %q", file, m[1], buildinfo.InformationURI)
		}
	}
}

// TestDocsCBOMExampleShowsAComponentTheToolWrites covers the CBOM example,
// which showed an RSA-2048 component with a parameterSetIdentifier, and no CBOM
// the tool writes carries either. Each component in the example has to equal,
// key for key, the component of the same bom-ref in the CBOM written for
// testdata/fixtures/go-project, whose golang-jwt dependency provides RS256.
func TestDocsCBOMExampleShowsAComponentTheToolWrites(t *testing.T) {
	const file = "docs/output-formats.md"
	section := markdownSection(t, readRepoFile(t, file), file, "CBOM (Cryptographic Bill of Materials)")
	block := regexp.MustCompile("(?s)```json\n(.*?)```").FindStringSubmatch(section)
	if block == nil {
		t.Fatalf("the CBOM section of %s has no json example", file)
	}
	var example struct {
		Components []map[string]any `json:"components"`
	}
	if err := json.Unmarshal([]byte(block[1]), &example); err != nil {
		t.Fatalf("the CBOM example in %s is not JSON: %v", file, err)
	}
	if len(example.Components) == 0 {
		t.Fatalf("the CBOM example in %s shows no component", file)
	}

	a := analyzer.New(database.NewEmbedded(), analyzer.Options{Offline: true, Reachability: true})
	result, err := a.AnalyzeAll(filepath.Join(repoRoot, "testdata", "fixtures", "go-project"))
	if err != nil {
		t.Fatalf("scanning the fixture: %v", err)
	}
	var buf bytes.Buffer
	if err := (&output.CBOMFormatter{}).FormatMulti(result, &buf); err != nil {
		t.Fatalf("writing the CBOM: %v", err)
	}
	var written struct {
		Components []map[string]any `json:"components"`
	}
	if err := json.Unmarshal(buf.Bytes(), &written); err != nil {
		t.Fatalf("decoding the CBOM: %v", err)
	}
	byRef := make(map[string]map[string]any)
	for _, c := range written.Components {
		if ref, ok := c["bom-ref"].(string); ok {
			byRef[ref] = c
		}
	}

	for _, c := range example.Components {
		ref, _ := c["bom-ref"].(string)
		got, ok := byRef[ref]
		if !ok {
			t.Errorf("the CBOM example in %s shows component %v, and the tool writes no component "+
				"with bom-ref %q for the fixture", file, c, ref)
			continue
		}
		if !reflect.DeepEqual(c, got) {
			t.Errorf("the CBOM example in %s shows\n%v\nand the tool writes\n%v", file, c, got)
		}
	}
}
