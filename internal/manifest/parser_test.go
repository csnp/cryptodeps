// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

func TestGoModParser(t *testing.T) {
	// Create temp go.mod file
	tmpDir, err := os.MkdirTemp("", "manifest-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	gomod := `module github.com/test/project

go 1.21

require (
	golang.org/x/crypto v0.17.0
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.9.0 // indirect
)

require github.com/single/dep v1.0.0
`
	gomodPath := filepath.Join(tmpDir, "go.mod")
	if err := os.WriteFile(gomodPath, []byte(gomod), 0644); err != nil {
		t.Fatal(err)
	}

	parser := &GoModParser{}

	// Test Ecosystem
	if parser.Ecosystem() != types.EcosystemGo {
		t.Errorf("Ecosystem() = %q, want %q", parser.Ecosystem(), types.EcosystemGo)
	}

	// Test Filenames
	filenames := parser.Filenames()
	if len(filenames) == 0 || filenames[0] != "go.mod" {
		t.Errorf("Filenames() = %v, want [go.mod]", filenames)
	}

	// Test Parse
	deps, err := parser.Parse(gomodPath)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if len(deps) < 3 {
		t.Errorf("Expected at least 3 dependencies, got %d", len(deps))
	}

	// Check specific dependencies
	foundCrypto := false
	foundIndirect := false
	foundSingleDep := false
	for _, dep := range deps {
		if dep.Name == "golang.org/x/crypto" {
			foundCrypto = true
			if dep.Version != "v0.17.0" {
				t.Errorf("x/crypto version = %q, want v0.17.0", dep.Version)
			}
			if !dep.Direct {
				t.Error("x/crypto should be direct")
			}
		}
		if dep.Name == "github.com/sirupsen/logrus" {
			foundIndirect = true
			if dep.Direct {
				t.Error("logrus should be indirect")
			}
		}
		if dep.Name == "github.com/single/dep" {
			foundSingleDep = true
			if !dep.Direct {
				t.Error("single/dep should be direct")
			}
		}
	}

	if !foundCrypto {
		t.Error("x/crypto not found in parsed dependencies")
	}
	if !foundIndirect {
		t.Error("logrus not found in parsed dependencies")
	}
	if !foundSingleDep {
		t.Error("single/dep not found in parsed dependencies")
	}
}

func TestGoModParserReplace(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "manifest-test")
	defer os.RemoveAll(tmpDir)

	gomod := `module test

require github.com/foo/bar v1.0.0 => ./local
`
	gomodPath := filepath.Join(tmpDir, "go.mod")
	os.WriteFile(gomodPath, []byte(gomod), 0644)

	parser := &GoModParser{}
	deps, err := parser.Parse(gomodPath)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	for _, dep := range deps {
		if dep.Name == "github.com/foo/bar" {
			// Version should be cleaned (replace directive removed)
			if dep.Version == "=> ./local" {
				t.Error("Replace directive not cleaned from version")
			}
		}
	}
}

func TestNPMParser(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "manifest-test")
	defer os.RemoveAll(tmpDir)

	packageJSON := `{
  "name": "test-project",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.0",
    "jsonwebtoken": "~9.0.0"
  },
  "devDependencies": {
    "jest": ">=29.0.0"
  },
  "peerDependencies": {
    "react": "18.x"
  }
}`
	pkgPath := filepath.Join(tmpDir, "package.json")
	os.WriteFile(pkgPath, []byte(packageJSON), 0644)

	parser := &NPMParser{}

	// Test Ecosystem
	if parser.Ecosystem() != types.EcosystemNPM {
		t.Errorf("Ecosystem() = %q, want %q", parser.Ecosystem(), types.EcosystemNPM)
	}

	// Test Parse
	deps, err := parser.Parse(pkgPath)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if len(deps) != 4 {
		t.Errorf("Expected 4 dependencies, got %d", len(deps))
	}

	// Check version cleaning
	for _, dep := range deps {
		if dep.Name == "express" && dep.Version == "^4.18.0" {
			t.Error("npm version prefix ^ should be removed")
		}
		if dep.Name == "jsonwebtoken" && dep.Version == "~9.0.0" {
			t.Error("npm version prefix ~ should be removed")
		}
	}
}

func TestNPMParserInvalidJSON(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "manifest-test")
	defer os.RemoveAll(tmpDir)

	pkgPath := filepath.Join(tmpDir, "package.json")
	os.WriteFile(pkgPath, []byte("not valid json"), 0644)

	parser := &NPMParser{}
	_, err := parser.Parse(pkgPath)
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

func TestPythonParser(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "manifest-test")
	defer os.RemoveAll(tmpDir)

	requirements := `# Comment line
cryptography==41.0.0
requests>=2.28.0
PyJWT~=2.8.0
bcrypt  # with comment

# Options to skip
-r other-requirements.txt
--index-url https://pypi.org/simple/

numpy==1.24.0 ; python_version >= "3.9"
`
	reqPath := filepath.Join(tmpDir, "requirements.txt")
	os.WriteFile(reqPath, []byte(requirements), 0644)

	parser := &PythonParser{}

	// Test Ecosystem
	if parser.Ecosystem() != types.EcosystemPyPI {
		t.Errorf("Ecosystem() = %q, want %q", parser.Ecosystem(), types.EcosystemPyPI)
	}

	// Test Parse
	deps, err := parser.Parse(reqPath)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if len(deps) < 4 {
		t.Errorf("Expected at least 4 dependencies, got %d", len(deps))
	}

	// Check specific dependencies
	foundCrypto := false
	for _, dep := range deps {
		if dep.Name == "cryptography" {
			foundCrypto = true
			if dep.Version != "41.0.0" {
				t.Errorf("cryptography version = %q, want 41.0.0", dep.Version)
			}
		}
	}

	if !foundCrypto {
		t.Error("cryptography not found in parsed dependencies")
	}
}

func TestMavenParser(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "manifest-test")
	defer os.RemoveAll(tmpDir)

	pomXML := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>test-project</artifactId>
    <version>1.0.0</version>

    <dependencies>
        <dependency>
            <groupId>org.bouncycastle</groupId>
            <artifactId>bcprov-jdk18on</artifactId>
            <version>1.77</version>
        </dependency>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.13.2</version>
            <scope>test</scope>
        </dependency>
    </dependencies>
</project>`
	pomPath := filepath.Join(tmpDir, "pom.xml")
	os.WriteFile(pomPath, []byte(pomXML), 0644)

	parser := &MavenParser{}

	// Test Ecosystem
	if parser.Ecosystem() != types.EcosystemMaven {
		t.Errorf("Ecosystem() = %q, want %q", parser.Ecosystem(), types.EcosystemMaven)
	}

	// Test Parse
	deps, err := parser.Parse(pomPath)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if len(deps) != 2 {
		t.Errorf("Expected 2 dependencies, got %d", len(deps))
	}

	// Check Maven coordinate format
	foundBC := false
	foundJunit := false
	for _, dep := range deps {
		if dep.Name == "org.bouncycastle:bcprov-jdk18on" {
			foundBC = true
			if dep.Version != "1.77" {
				t.Errorf("bcprov version = %q, want 1.77", dep.Version)
			}
			if !dep.Direct {
				t.Error("bcprov should be direct (not test scope)")
			}
		}
		if dep.Name == "junit:junit" {
			foundJunit = true
			if dep.Direct {
				t.Error("junit should not be direct (test scope)")
			}
		}
	}

	if !foundBC {
		t.Error("bouncycastle not found")
	}
	if !foundJunit {
		t.Error("junit not found")
	}
}

func TestMavenParserInvalidXML(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "manifest-test")
	defer os.RemoveAll(tmpDir)

	pomPath := filepath.Join(tmpDir, "pom.xml")
	os.WriteFile(pomPath, []byte("not valid xml"), 0644)

	parser := &MavenParser{}
	_, err := parser.Parse(pomPath)
	if err == nil {
		t.Error("Expected error for invalid XML")
	}
}

func TestDetectAndParse(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "manifest-test")
	defer os.RemoveAll(tmpDir)

	// Create a go.mod file
	gomod := `module test
require github.com/test/dep v1.0.0
`
	gomodPath := filepath.Join(tmpDir, "go.mod")
	os.WriteFile(gomodPath, []byte(gomod), 0644)

	// Test with directory
	manifest, err := DetectAndParse(tmpDir)
	if err != nil {
		t.Fatalf("DetectAndParse(dir) error: %v", err)
	}

	if manifest.Ecosystem != types.EcosystemGo {
		t.Errorf("Ecosystem = %q, want %q", manifest.Ecosystem, types.EcosystemGo)
	}
	if manifest.Path != gomodPath {
		t.Errorf("Path = %q, want %q", manifest.Path, gomodPath)
	}

	// Test with file directly
	manifest, err = DetectAndParse(gomodPath)
	if err != nil {
		t.Fatalf("DetectAndParse(file) error: %v", err)
	}

	if manifest.Ecosystem != types.EcosystemGo {
		t.Errorf("Ecosystem = %q, want %q", manifest.Ecosystem, types.EcosystemGo)
	}
}

func TestDetectAndParseNoManifest(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "manifest-test")
	defer os.RemoveAll(tmpDir)

	// Empty directory with no manifest
	_, err := DetectAndParse(tmpDir)
	if err == nil {
		t.Error("Expected error for directory with no manifest")
	}
}

func TestDetectAndParseUnsupportedFile(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "manifest-test")
	defer os.RemoveAll(tmpDir)

	// Create unsupported file
	unsupported := filepath.Join(tmpDir, "unsupported.txt")
	os.WriteFile(unsupported, []byte("test"), 0644)

	_, err := DetectAndParse(unsupported)
	if err == nil {
		t.Error("Expected error for unsupported manifest file")
	}
}

func TestDetectAndParseNonexistent(t *testing.T) {
	_, err := DetectAndParse("/nonexistent/path")
	if err == nil {
		t.Error("Expected error for nonexistent path")
	}
}

func TestGetParser(t *testing.T) {
	tests := []struct {
		filename  string
		wantEco   types.Ecosystem
		wantError bool
	}{
		{"go.mod", types.EcosystemGo, false},
		{"GO.MOD", types.EcosystemGo, false},
		{"package.json", types.EcosystemNPM, false},
		{"requirements.txt", types.EcosystemPyPI, false},
		{"pyproject.toml", types.EcosystemPyPI, false},
		{"Pipfile", types.EcosystemPyPI, false},
		{"pom.xml", types.EcosystemMaven, false},
		{"unknown.txt", "", true},
		{"Cargo.toml", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			parser, err := getParser(tt.filename)
			if (err != nil) != tt.wantError {
				t.Errorf("getParser(%q) error = %v, wantError %v", tt.filename, err, tt.wantError)
			}
			if !tt.wantError && parser.Ecosystem() != tt.wantEco {
				t.Errorf("getParser(%q).Ecosystem() = %q, want %q", tt.filename, parser.Ecosystem(), tt.wantEco)
			}
		})
	}
}

func TestSupportedManifests(t *testing.T) {
	manifests := SupportedManifests()
	if len(manifests) == 0 {
		t.Error("SupportedManifests() returned empty slice")
	}

	expected := []string{"go.mod", "package.json", "requirements.txt"}
	for _, exp := range expected {
		found := false
		for _, m := range manifests {
			if m == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("SupportedManifests() missing %q", exp)
		}
	}
}

func TestCleanVersion(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"v1.0.0", "v1.0.0"},
		{" v1.0.0 ", "v1.0.0"},
		{"v1.0.0 => ./local", "v1.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := cleanVersion(tt.input)
			if got != tt.want {
				t.Errorf("cleanVersion(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestCleanNPMVersion(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"^1.0.0", "1.0.0"},
		{"~1.0.0", "1.0.0"},
		{">=1.0.0", "1.0.0"},
		{">1.0.0", "1.0.0"},
		{"<=1.0.0", "1.0.0"},
		{"<1.0.0", "1.0.0"},
		{"=1.0.0", "1.0.0"},
		{"1.0.0", "1.0.0"},
		{"1.0.x", "1.0.x"},
		{"1.0.0 - 2.0.0", "1.0.0"},
		{"1.0.0 || 2.0.0", "1.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := cleanNPMVersion(tt.input)
			if got != tt.want {
				t.Errorf("cleanNPMVersion(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestFindManifestPriority(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "manifest-test")
	defer os.RemoveAll(tmpDir)

	// Create multiple manifest files
	os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte("module test"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte("{}"), 0644)

	// go.mod should have priority
	path, err := findManifest(tmpDir)
	if err != nil {
		t.Fatalf("findManifest error: %v", err)
	}

	if filepath.Base(path) != "go.mod" {
		t.Errorf("findManifest() = %q, want go.mod (higher priority)", filepath.Base(path))
	}
}

func TestParserFileNotFound(t *testing.T) {
	parsers := []Parser{
		&GoModParser{},
		&NPMParser{},
		&PythonParser{},
		&MavenParser{},
	}

	for _, p := range parsers {
		t.Run(string(p.Ecosystem()), func(t *testing.T) {
			_, err := p.Parse("/nonexistent/file")
			if err == nil {
				t.Error("Expected error for nonexistent file")
			}
		})
	}
}

func TestParserFilenames(t *testing.T) {
	tests := []struct {
		parser   Parser
		expected []string
	}{
		{&GoModParser{}, []string{"go.mod"}},
		{&NPMParser{}, []string{"package.json", "package-lock.json"}},
		{&PythonParser{}, []string{"requirements.txt", "Pipfile", "pyproject.toml"}},
		{&MavenParser{}, []string{"pom.xml"}},
	}

	for _, tt := range tests {
		t.Run(string(tt.parser.Ecosystem()), func(t *testing.T) {
			filenames := tt.parser.Filenames()
			if len(filenames) == 0 {
				t.Error("Filenames() returned empty slice")
			}
			// Check that expected filenames are present
			for _, expected := range tt.expected {
				found := false
				for _, f := range filenames {
					if f == expected {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected filename %q not found in %v", expected, filenames)
				}
			}
		})
	}
}

// TestParsersRecordDeclarationLine is the regression test for findings that
// named no file and no line. Every finding is reported against the line that
// declares its dependency, so each parser has to record that line. A line that
// is off by one sends the reader to the wrong dependency, which is worse than
// sending them nowhere, so each case puts the dependency somewhere a naive
// search would get wrong: after a same-named key in another block, after a
// comment, or inside a multi-line array.
func TestParsersRecordDeclarationLine(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		parser   Parser
		content  string
		wantLine map[string]int
	}{
		{
			name:   "go.mod require block and single require",
			file:   "go.mod",
			parser: &GoModParser{},
			content: "module example.com/app\n" + // 1
				"\n" + // 2
				"go 1.22\n" + // 3
				"\n" + // 4
				"require github.com/single/dep v1.0.0\n" + // 5
				"\n" + // 6
				"require (\n" + // 7
				"\tgithub.com/golang-jwt/jwt/v5 v5.2.0\n" + // 8
				"\t// a comment\n" + // 9
				"\tgolang.org/x/crypto v0.21.0 // indirect\n" + // 10
				")\n", // 11
			wantLine: map[string]int{
				"github.com/single/dep":        5,
				"github.com/golang-jwt/jwt/v5": 8,
				"golang.org/x/crypto":          10,
			},
		},
		{
			name:   "package.json dependency on line 4",
			file:   "package.json",
			parser: &NPMParser{},
			content: "{\n" + // 1
				"  \"name\": \"app\",\n" + // 2
				"  \"dependencies\": {\n" + // 3
				"    \"jsonwebtoken\": \"^8.0.0\",\n" + // 4
				"    \"express\": \"^4.0.0\"\n" + // 5
				"  },\n" + // 6
				"  \"scripts\": {\"jest\": \"jest\"},\n" + // 7
				"  \"devDependencies\": {\n" + // 8
				"    \"jest\": \"^29.0.0\"\n" + // 9
				"  }\n" + // 10
				"}\n", // 11
			wantLine: map[string]int{
				"jsonwebtoken": 4,
				"express":      5,
				// The "jest" key on line 7 is a script, not a dependency.
				"jest": 9,
			},
		},
		{
			name:   "requirements.txt",
			file:   "requirements.txt",
			parser: &PythonParser{},
			content: "# pinned for production\n" + // 1
				"\n" + // 2
				"--index-url https://pypi.example.org/simple\n" + // 3
				"cryptography==41.0.0\n" + // 4
				"pyjwt[crypto]>=2.8.0  # tokens\n", // 5
			wantLine: map[string]int{
				"cryptography": 4,
				"pyjwt":        5,
			},
		},
		{
			name:   "pyproject.toml PEP 621 and Poetry",
			file:   "pyproject.toml",
			parser: &PythonParser{},
			content: "[project]\n" + // 1
				"name = \"cryptography-demo\"\n" + // 2
				"dependencies = [\n" + // 3
				"  # the comment names rsa, which is not a dependency\n" + // 4
				"  \"cryptography>=41.0.0\",\n" + // 5
				"  \"PyJWT[crypto]>=2.8.0; python_version >= '3.8'\",\n" + // 6
				"]\n" + // 7
				"\n" + // 8
				"[project.optional-dependencies]\n" + // 9
				"ssh = [\"paramiko>=3.0\"]\n" + // 10
				"\n" + // 11
				"[tool.poetry.dependencies]\n" + // 12
				"python = \"^3.11\"\n" + // 13
				"\"pycryptodome\" = \"^3.20\"\n" + // 14
				"\n" + // 15
				"[tool.poetry.group.dev.dependencies]\n" + // 16
				"rsa = { version = \"^4.9\" }\n", // 17
			wantLine: map[string]int{
				"cryptography": 5,
				"pyjwt":        6,
				"paramiko":     10,
				"pycryptodome": 14,
				"rsa":          17,
			},
		},
		{
			name:   "pyproject.toml Poetry dotted key and sub-table",
			file:   "pyproject.toml",
			parser: &PythonParser{},
			content: "[tool.poetry]\n" + // 1
				"description = \"\"\"\n" + // 2
				"[tool.poetry.dependencies]\n" + // 3, inside a string
				"requests = \"*\"\n" + // 4, inside a string
				"\"\"\"\n" + // 5
				"dependencies.cryptography = \"^41.0\"\n" + // 6
				"\n" + // 7
				"[tool.poetry.dependencies.requests]\n" + // 8
				"version = \"^2.31\"\n", // 9
			wantLine: map[string]int{
				"cryptography": 6,
				"requests":     8,
			},
		},
		{
			name:   "Pipfile",
			file:   "Pipfile",
			parser: &PythonParser{},
			content: "[[source]]\n" + // 1
				"url = \"https://pypi.org/simple\"\n" + // 2
				"name = \"pypi\"\n" + // 3
				"\n" + // 4
				"[packages]\n" + // 5
				"requests = \"*\"\n" + // 6
				"PyNaCl = \"==1.5.0\"\n" + // 7
				"\n" + // 8
				"[dev-packages]\n" + // 9
				"\"pycryptodome\" = { version = \"==3.20.0\" }\n", // 10
			wantLine: map[string]int{
				"requests":     6,
				"pynacl":       7,
				"pycryptodome": 10,
			},
		},
		{
			name:   "pom.xml artifactId line",
			file:   "pom.xml",
			parser: &MavenParser{},
			content: "<project>\n" + // 1
				"  <groupId>com.example</groupId>\n" + // 2
				"  <artifactId>app</artifactId>\n" + // 3
				"  <dependencyManagement><dependencies><dependency>\n" + // 4
				"    <groupId>org.bouncycastle</groupId><artifactId>bcprov-jdk18on</artifactId>\n" + // 5
				"  </dependency></dependencies></dependencyManagement>\n" + // 6
				"  <dependencies>\n" + // 7
				"    <dependency>\n" + // 8
				"      <groupId>org.bouncycastle</groupId>\n" + // 9
				"      <artifactId>bcprov-jdk18on</artifactId>\n" + // 10
				"      <version>1.78</version>\n" + // 11
				"    </dependency>\n" + // 12
				"    <!-- <artifactId>commented-out</artifactId> -->\n" + // 13
				"    <dependency>\n" + // 14
				"      <groupId>io.jsonwebtoken</groupId>\n" + // 15
				"      <artifactId>jjwt-api</artifactId>\n" + // 16
				"      <version>0.12.5</version>\n" + // 17
				"    </dependency>\n" + // 18
				"  </dependencies>\n" + // 19
				"</project>\n", // 20
			wantLine: map[string]int{
				"org.bouncycastle:bcprov-jdk18on": 10,
				"io.jsonwebtoken:jjwt-api":        16,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tt.file)
			writeFile(t, path, tt.content)

			deps, err := tt.parser.Parse(path)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			got := make(map[string]int, len(deps))
			for _, d := range deps {
				got[d.Name] = d.Line
			}
			for name, want := range tt.wantLine {
				line, ok := got[name]
				if !ok {
					t.Errorf("%s: dependency not parsed; got %v", name, got)
					continue
				}
				if line != want {
					t.Errorf("%s: declared on line %d, parser recorded line %d", name, want, line)
				}
			}
		})
	}
}

// TestDeclarationLineUnknownStaysZero covers a dependency whose line cannot be
// found. Zero means "not known", and the outputs then name the file alone; a
// guessed line would point the reader at something that is not the dependency.
func TestDeclarationLineUnknownStaysZero(t *testing.T) {
	// Poetry's table written as one inline table on the parent key is valid
	// TOML and is decoded, but the line scanner does not read inside inline
	// tables, so it cannot say which key is the dependency.
	path := filepath.Join(t.TempDir(), "pyproject.toml")
	writeFile(t, path, "[tool]\n"+
		"poetry = { dependencies = { cryptography = \"^41.0\" } }\n")

	deps, err := (&PythonParser{}).Parse(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(deps) != 1 || deps[0].Name != "cryptography" {
		t.Fatalf("want the one dependency parsed, got %+v", deps)
	}
	if deps[0].Line != 0 {
		t.Errorf("cryptography: want line 0 (unknown), got %d", deps[0].Line)
	}
}

// TestNPMDeclarationLineIgnoresTextOutsideTheBlock pins that the line comes
// from the dependency block's own keys, not from the first place the name is
// written: here it appears first in the description and in a script.
func TestNPMDeclarationLineIgnoresTextOutsideTheBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "package.json")
	writeFile(t, path, "{\n"+ // 1
		"  \"description\": \"\\\"jsonwebtoken\\\": wrapper\",\n"+ // 2
		"  \"scripts\": { \"jsonwebtoken\": \"node x.js\" },\n"+ // 3
		"  \"peerDependencies\": { \"react\": \"^18.0.0\" },\n"+ // 4
		"  \"dependencies\": {\n"+ // 5
		"    \"@scope/pkg\": \"1.0.0\",\n"+ // 6
		"    \"jsonwebtoken\": \"^8.0.0\"\n"+ // 7
		"  }\n"+ // 8
		"}\n") // 9

	deps, err := (&NPMParser{}).Parse(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := map[string]int{"jsonwebtoken": 7, "@scope/pkg": 6, "react": 4}
	for _, d := range deps {
		if w, ok := want[d.Name]; ok && d.Line != w {
			t.Errorf("%s: want line %d, got %d", d.Name, w, d.Line)
		}
	}
}
