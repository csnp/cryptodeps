// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"bytes"
	"encoding/json"
	"os"
	"sort"
	"strings"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// NPMParser parses npm package.json files.
type NPMParser struct{}

// Ecosystem returns the ecosystem this parser handles.
func (p *NPMParser) Ecosystem() types.Ecosystem {
	return types.EcosystemNPM
}

// Filenames returns the manifest filenames this parser handles.
func (p *NPMParser) Filenames() []string {
	return []string{"package.json", "package-lock.json"}
}

// packageJSON represents the structure of a package.json file.
type packageJSON struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

// Parse parses a package.json file and returns the list of dependencies.
func (p *NPMParser) Parse(path string) ([]types.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	data = trimUTF8BOM(data)

	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}

	var deps []types.Dependency
	lines := npmDeclarationLines(data)

	// Each block is emitted in sorted order. Go randomises map iteration, so
	// ranging over these maps directly made the whole report shuffle between
	// runs of the same scan, which breaks diffable CI output and reproducible
	// SBOMs even though the finding set itself was stable.
	for i, block := range []map[string]string{
		pkg.Dependencies,
		pkg.DevDependencies,
		pkg.PeerDependencies,
		pkg.OptionalDependencies,
	} {
		for _, name := range sortedKeys(block) {
			deps = append(deps, types.Dependency{
				Name:      name,
				Version:   cleanNPMVersion(block[name]),
				Ecosystem: types.EcosystemNPM,
				Direct:    true,
				Line:      lines[npmDependencyBlocks[i]][name],
			})
		}
	}

	return deps, nil
}

// utf8BOM is the byte order mark a UTF-8 file can start with.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// trimUTF8BOM drops a leading UTF-8 byte order mark. encoding/json rejects the
// mark as an invalid character, so a package.json saved with one was refused
// with "invalid character 'ï' looking for beginning of value" and none of its
// dependencies were analyzed. The mark holds no newline, so the declaration
// lines found in the trimmed document are the lines of the file.
func trimUTF8BOM(data []byte) []byte {
	return bytes.TrimPrefix(data, utf8BOM)
}

// npmDependencyBlocks names the package.json objects that declare
// dependencies, in the order Parse emits them.
var npmDependencyBlocks = [...]string{
	"dependencies", "devDependencies", "peerDependencies", "optionalDependencies",
}

// npmDeclarationLines finds the line of every key in each dependency block.
//
// json.Unmarshal keeps no positions, so the document is walked a second time
// as a token stream, which reports the byte offset of each key it reads. A
// search of the raw text for the name would be wrong as often as it is right:
// the same name is routinely a script, a description or an override earlier in
// the file. The block names are matched the way json.Unmarshal matches them,
// ignoring case, and a block that appears twice is merged with the later key
// winning, which is also what json.Unmarshal does with a map. Anything that
// does not walk cleanly leaves its dependencies at line 0.
func npmDeclarationLines(data []byte) map[string]map[string]int {
	lines := make(map[string]map[string]int)
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return lines
	}
	index := newLineIndex(data)
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return lines
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return lines
		}
		key, _ := keyTok.(string)
		block := ""
		for _, b := range npmDependencyBlocks {
			if strings.EqualFold(key, b) {
				block = b
			}
		}
		if block == "" || len(value) == 0 || value[0] != '{' {
			continue
		}
		// RawMessage holds the value's exact bytes, so it starts len(value)
		// before the offset the decoder has reached.
		base := dec.InputOffset() - int64(len(value))
		if lines[block] == nil {
			lines[block] = make(map[string]int)
		}
		inner := json.NewDecoder(bytes.NewReader(value))
		if _, err := inner.Token(); err != nil {
			continue
		}
		for inner.More() {
			nameTok, err := inner.Token()
			if err != nil {
				break
			}
			name, ok := nameTok.(string)
			if !ok {
				break
			}
			// A JSON string cannot hold a raw newline, so the line the key
			// ends on is the line it starts on.
			lines[block][name] = index.line(base + inner.InputOffset())
			var skip json.RawMessage
			if err := inner.Decode(&skip); err != nil {
				break
			}
		}
	}
	return lines
}

// lineIndex holds the byte offset of every newline in a document, in order.
//
// The npm and Maven parsers look up one line per dependency. Counting the
// newlines from the start of the file on each lookup made a manifest's parse
// time grow with the number of dependencies times the file size, and the
// manifest under scan is text anyone who can open a pull request can change.
// The newlines are found once here, and each lookup is a binary search over
// them.
type lineIndex []int64

// newLineIndex records the offset of every newline in data.
func newLineIndex(data []byte) lineIndex {
	var index lineIndex
	for offset := 0; ; {
		i := bytes.IndexByte(data[offset:], '\n')
		if i < 0 {
			return index
		}
		index = append(index, int64(offset+i))
		offset += i + 1
	}
}

// line returns the 1-based line holding the byte at offset, or 0 for a
// negative offset. An offset past the end of the document is on the last line.
func (index lineIndex) line(offset int64) int {
	if offset < 0 {
		return 0
	}
	// The newlines before offset are the ones the search passes over.
	return sort.Search(len(index), func(i int) bool { return index[i] >= offset }) + 1
}

// sortedKeys returns a map's keys in a stable order.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// cleanNPMVersion normalizes npm version strings.
func cleanNPMVersion(version string) string {
	version = strings.TrimSpace(version)

	// Remove semver range prefixes for database lookups
	// ^1.2.3 -> 1.2.3
	// ~1.2.3 -> 1.2.3
	// >=1.2.3 -> 1.2.3
	// 1.2.x -> 1.2.x (keep wildcards)
	prefixes := []string{"^", "~", ">=", ">", "<=", "<", "="}
	for _, prefix := range prefixes {
		version = strings.TrimPrefix(version, prefix)
	}

	// Handle version ranges (e.g., "1.0.0 - 2.0.0")
	if idx := strings.Index(version, " - "); idx != -1 {
		version = strings.TrimSpace(version[:idx])
	}

	// Handle OR ranges (e.g., "1.0.0 || 2.0.0")
	if idx := strings.Index(version, " || "); idx != -1 {
		version = strings.TrimSpace(version[:idx])
	}

	return version
}
