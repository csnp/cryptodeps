// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"encoding/json"
	"errors"
	"io"
	"path/filepath"

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
	Tool                     sarifTool                    `json:"tool"`
	VersionControlProvenance []sarifVersionControl        `json:"versionControlProvenance,omitempty"`
	OriginalURIBaseIDs       map[string]sarifArtifactBase `json:"originalUriBaseIds,omitempty"`
	Invocations              []sarifInvocation            `json:"invocations,omitempty"`
	Results                  []sarifResult                `json:"results"`
}

// sarifVersionControl is the SARIF 2.1.0 versionControlDetails object. It names
// the repository and branch a fetched scan read, because SRCROOT for such a
// run is a temporary directory that says nothing about what was scanned. The
// subdirectory, when the argument named one, has no field of its own in the
// specification and goes in the property bag.
type sarifVersionControl struct {
	RepositoryURI string            `json:"repositoryUri"`
	Branch        string            `json:"branch,omitempty"`
	Properties    map[string]string `json:"properties,omitempty"`
}

// sarifProvenance is the versionControlProvenance for a scan, empty for a
// local one.
func sarifProvenance(s *types.ScanSource) []sarifVersionControl {
	if s == nil {
		return nil
	}
	vc := sarifVersionControl{RepositoryURI: s.Repository, Branch: s.Branch}
	if s.Path != "" {
		vc.Properties = map[string]string{"path": s.Path}
	}
	return []sarifVersionControl{vc}
}

// sarifInvocation carries whether the run was complete. A manifest that could
// not be read is reported here as a tool execution notification and clears
// executionSuccessful, which is how a SARIF consumer learns the scan did not
// cover everything it was pointed at.
type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
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
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	SemanticVersion string      `json:"semanticVersion,omitempty"`
	InformationURI  string      `json:"informationUri"`
	Rules           []sarifRule `json:"rules"`
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
	RuleID     string                 `json:"ruleId"`
	Level      string                 `json:"level"`
	Message    sarifMessage           `json:"message"`
	Locations  []sarifLocation        `json:"locations"`
	Properties *sarifResultProperties `json:"properties,omitempty"`
}

// sarifResultProperties is the property bag on each result. It carries what
// the level cannot: whether the code calls the algorithm, and what the finding
// rests on. Reachability is omitted when it was not analyzed rather than
// reported as a verdict nobody reached.
type sarifResultProperties struct {
	QuantumRisk  types.QuantumRisk  `json:"quantumRisk"`
	Basis        types.Basis        `json:"basis,omitempty"`
	Confidence   types.Confidence   `json:"confidence,omitempty"`
	Reachability types.Reachability `json:"reachability,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	// Region is absent when the line is not known. SARIF requires a startLine
	// of at least 1, so a zero line cannot be written as one.
	Region *sarifRegion `json:"region,omitempty"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// declarationRegion returns the region of a manifest line, or nil for line 0.
func declarationRegion(line int) *sarifRegion {
	if line < 1 {
		return nil
	}
	return &sarifRegion{StartLine: line}
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
	return f.write(w, root, result.Source, []*types.ScanResult{result}, nil)
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
	return f.write(w, result.RootPath, result.Source, result.Projects, result.Skipped)
}

// write emits one SARIF run covering every supplied project. source is nil for
// a local scan.
func (f *SARIFFormatter) write(w io.Writer, root string, source *types.ScanSource, projects []*types.ScanResult, skipped []types.SkippedManifest) error {
	// A uriBaseId names a directory, and the root has to be absolute before any
	// manifest path can be expressed relative to it. Both normalizations live in
	// scanRootDir, which CBOM calls too: when SARIF did this inline and CBOM did
	// not, the same run produced repository-relative SARIF and absolute CBOM.
	absRoot := scanRootDir(root)

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
				VersionControlProvenance: sarifProvenance(source),
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
	// An unsupported ecosystem is reported but does not clear
	// executionSuccessful: the tool did not fail to read the file, it has no
	// parser for it, which is a declared limit rather than an incomplete run.
	invocation := sarifInvocation{ExecutionSuccessful: !types.IncompleteScan(skipped)}
	for _, s := range skipped {
		uri, baseID := sarifArtifactURI(absRoot, s.Path)
		level, prefix := "error", "manifest found but not analyzed: "
		if s.Unsupported {
			level, prefix = "warning", "manifest found but not supported: "
		}
		invocation.ToolExecutionNotifications = append(invocation.ToolExecutionNotifications, sarifNotification{
			Level:   level,
			Message: sarifMessage{Text: prefix + s.Reason},
			Locations: []sarifLocation{
				{PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: uri, URIBaseID: baseID},
				}},
			},
		})
	}
	// Say what the run did not cover, for the same reason the table does, and
	// through the same classification so the two cannot disagree. A consumer
	// reading only `results` cannot tell an empty array produced by a clean tree
	// from one produced by a filter that withheld everything, or by a scan where
	// no dependency was in the database.
	//
	// Per project, and only for projects that produced no findings. Evaluated
	// over the whole run instead, these notes contradicted the results beside
	// them: a scan with two CRITICAL findings carried a notification saying no
	// conclusion could be drawn, and a workspace where one project of two went
	// entirely unexamined carried no note at all. These are coverage statements
	// rather than tool failures, so they do not clear executionSuccessful.
	for _, note := range coverageNotes(projects) {
		message := note.Text()
		if note.Manifest != "" && len(projects) > 1 {
			uri, _ := sarifArtifactURI(absRoot, note.Manifest)
			message = uri + ": " + message
		}
		invocation.ToolExecutionNotifications = append(invocation.ToolExecutionNotifications, sarifNotification{
			Level:   note.Level(),
			Message: sarifMessage{Text: message},
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
				msgText += sarifReachabilityClause(crypto.Reachability)
				if crypto.Inferred() {
					msgText += ", inferred from the package name and description"
				}
				if f.Options.ShowRemediation && crypto.Remediation != "" {
					msgText += ". Remediation: " + crypto.Remediation
				}

				res := sarifResult{
					RuleID: ruleID,
					// The level stays with severity even for a finding the code does
					// not call. Reachability misses calls today, calls made on a
					// variable among them, so lowering an uncalled finding would let
					// a called algorithm fall below a code-scanning gate. The
					// property and the message carry reachability instead.
					Level: severityToSARIFLevel(crypto.Severity),
					Properties: &sarifResultProperties{
						QuantumRisk:  crypto.QuantumRisk,
						Basis:        crypto.Basis,
						Confidence:   crypto.Confidence,
						Reachability: crypto.Reachability,
					},
					Message: sarifMessage{
						Text: msgText,
					},
					// The result is located at the manifest, so its line is the
					// dependency's declaration in that manifest. A finding from
					// source analysis carries a location inside the dependency's
					// own source, which is not a line of this file.
					Locations: []sarifLocation{
						{
							PhysicalLocation: sarifPhysicalLocation{
								ArtifactLocation: sarifArtifactLocation{
									URI:       uri,
									URIBaseID: baseID,
								},
								Region: declarationRegion(dep.Dependency.Line),
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
	path, underRoot := relativeToRoot(absRoot, manifestPath)
	if path == "" {
		return "", ""
	}
	if !underRoot {
		return "file://" + path, ""
	}
	return path, sarifURIBaseID
}

// sarifReachabilityClause says in the message whether the code calls the
// algorithm. It is empty when reachability was not analyzed.
func sarifReachabilityClause(reach types.Reachability) string {
	switch reach {
	case types.ReachabilityConfirmed:
		return ", called from your code"
	case types.ReachabilityReachable:
		return ", reachable from your code"
	case types.ReachabilityAvailable:
		return ", in a dependency your code does not call"
	default:
		return ""
	}
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
