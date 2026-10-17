// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Every requirements.txt line that declares dependencies the parser skips is
// listed with its line number, option lines that declare none are not, and no
// URL from the manifest is copied into the result, not even the URL of an
// "-r" include, which pip fetches and which can carry credentials.
func TestRequirementsUnreadLines(t *testing.T) {
	dir := t.TempDir()
	content := strings.Join([]string{
		"cryptography==42.0.0",   // 1 read
		"-r extra.txt",           // 2
		"--requirement=more.txt", // 3
		"-rdev.txt",              // 4
		"paramiko[ed25519] @ https://example.invalid/p",  // 5
		"-e git+https://example.invalid/repo.git#egg=x",  // 6
		"https://example.invalid/pkg.whl",                // 7
		"-r https://example.invalid/private-reqs.txt",    // 8 a URL include
		"--requirement=https://example.invalid/more.txt", // 9 a URL include
		"--index-url https://example.invalid/simple",     // 10 not a dependency
		"-c constraints.txt",                             // 11 not a dependency
		"# -r commented.txt",                             // 12 comment
		"",
	}, "\n")
	path := filepath.Join(dir, "requirements.txt")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	m, err := DetectAndParse(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Dependencies) != 1 || m.Dependencies[0].Name != "cryptography" {
		t.Errorf("dependencies = %+v, want cryptography only", m.Dependencies)
	}

	want := []struct {
		line int
		name string
	}{
		{2, "extra.txt"}, {3, "more.txt"}, {4, "dev.txt"}, {5, "paramiko"}, {6, ""}, {7, ""}, {8, ""}, {9, ""},
	}
	if len(m.Unread) != len(want) {
		t.Fatalf("Unread = %+v, want %d entries", m.Unread, len(want))
	}
	for i, w := range want {
		got := m.Unread[i]
		if got.Line != w.line || got.Name != w.name || got.Reason == "" {
			t.Errorf("Unread[%d] = %+v, want line %d name %q and a reason", i, got, w.line, w.name)
		}
		if strings.Contains(got.Name+got.Reason, "example.invalid") {
			t.Errorf("Unread[%d] copies a URL: %+v", i, got)
		}
	}
}

// A requirements.txt line that names a local path, such as
// "./vendor/foo-1.0.tar.gz" or "../lib", declares a dependency the parser does
// not read. It was dropped without an entry, so the unread block read as
// complete while such lines were missing from it. Each is now listed by line
// with the path it names, without any per-requirement option, environment
// marker or inline comment, and the parser still reads none of them.
func TestRequirementsUnreadLocalPathLines(t *testing.T) {
	dir := t.TempDir()
	content := strings.Join([]string{
		"cryptography==42.0.0",                        // 1 read
		"./vendor/foo-1.0.tar.gz",                     // 2
		"../lib",                                      // 3
		"/opt/wheels/bar-2.0-py3-none-any.whl",        // 4
		`\\build\wheels\baz-3.0.tar.gz`,               // 5
		"./vendor/qux[ssh] --hash=sha256:FAKE",        // 6 per-requirement option
		`../lib2 ; python_version < "3.12"`,           // 7 environment marker
		"./vendor/quux-1.0.tar.gz  # a vendored copy", // 8 inline comment
		"-e ./editable",                               // 9 editable, listed by kind
		"",
	}, "\n")
	path := filepath.Join(dir, "requirements.txt")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	m, err := DetectAndParse(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Dependencies) != 1 || m.Dependencies[0].Name != "cryptography" {
		t.Errorf("dependencies = %+v, want cryptography only", m.Dependencies)
	}

	want := []struct {
		line   int
		name   string
		reason string
	}{
		{2, "./vendor/foo-1.0.tar.gz", "local path"},
		{3, "../lib", "local path"},
		{4, "/opt/wheels/bar-2.0-py3-none-any.whl", "local path"},
		{5, `\\build\wheels\baz-3.0.tar.gz`, "local path"},
		{6, "./vendor/qux[ssh]", "local path"},
		{7, "../lib2", "local path"},
		{8, "./vendor/quux-1.0.tar.gz", "local path"},
		{9, "", "editable"},
	}
	if len(m.Unread) != len(want) {
		t.Fatalf("Unread = %+v, want %d entries", m.Unread, len(want))
	}
	for i, w := range want {
		got := m.Unread[i]
		if got.Line != w.line || got.Name != w.name || !strings.Contains(got.Reason, w.reason) {
			t.Errorf("Unread[%d] = %+v, want line %d name %q and a reason naming %q", i, got, w.line, w.name, w.reason)
		}
	}
}

// The scan reads the requirements-*.txt family and requirements/*.txt as well
// as requirements.txt, but listed unread lines only for a file named
// requirements.txt, so the same lines in the others were dropped with no
// signal. Each now lists what requirements.txt lists for the same content, in
// a scan of its directory and, for a file the scan accepts as its argument, in
// a scan of the file itself.
func TestUnreadLinesForEveryRequirementsFile(t *testing.T) {
	content := strings.Join([]string{
		"cryptography==42.0.0", // 1 read
		"-r base.txt",          // 2
		"-r https://example.invalid/private-reqs.txt",   // 3 a URL include
		"-e git+https://example.invalid/repo.git#egg=x", // 4
		"paramiko @ https://example.invalid/p",          // 5
		"https://example.invalid/pkg.whl",               // 6
		"--index-url https://example.invalid/simple",    // 7 not a dependency
		"",
	}, "\n")

	reference, err := DetectAndParse(writeFiles(t, map[string]string{"requirements.txt": content}))
	if err != nil {
		t.Fatal(err)
	}
	if len(reference.Unread) != 5 {
		t.Fatalf("requirements.txt: Unread = %+v, want lines 2 to 6", reference.Unread)
	}

	for _, tc := range []struct {
		name string
		// argument is whether the scan accepts the file as its argument. A
		// requirements/*.txt file is read in a scan of a directory only.
		argument bool
	}{
		{"requirements-dev.txt", true},
		{"requirements_test.txt", true},
		{"requirements.prod.txt", true},
		{filepath.Join("requirements", "dev.txt"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeFiles(t, map[string]string{tc.name: content})
			manifests, skipped, err := DetectAndParseAll(dir)
			if err != nil || len(skipped) != 0 || len(manifests) != 1 {
				t.Fatalf("DetectAndParseAll = %d manifests, skipped %+v, error %v; want 1 manifest", len(manifests), skipped, err)
			}
			if !reflect.DeepEqual(manifests[0].Unread, reference.Unread) {
				t.Errorf("scan of the directory: Unread = %+v, want %+v", manifests[0].Unread, reference.Unread)
			}

			if !tc.argument {
				return
			}
			m, err := DetectAndParse(filepath.Join(dir, tc.name))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(m.Unread, reference.Unread) {
				t.Errorf("scan of the file: Unread = %+v, want %+v", m.Unread, reference.Unread)
			}
		})
	}
}

// pip reads a line that ends in a backslash together with the next one, so
// "-r \" followed by a URL on the next line is one URL include. It was listed
// as an include named "\" and then as a URL requirement. Each continued line
// is now listed once, by the number of its first line, and a comment line is
// not continued.
func TestRequirementsUnreadLinesJoinContinuedLines(t *testing.T) {
	const (
		urlInclude  = "included requirements URLs are not followed"
		fileInclude = "included requirements files are not followed"
		editable    = "editable installs (-e) are not read"
		directRef   = "name @ URL references are not read"
		urlReq      = "URL requirements are not read"
	)
	type entry struct {
		line   int
		name   string
		reason string
	}
	cases := []struct {
		name  string
		lines []string
		want  []entry
	}{
		{"URL include", []string{"cryptography==42.0.0", `-r \`, "https://example.invalid/continued.txt"},
			[]entry{{2, "", urlInclude}}},
		{"file include", []string{`-r \`, "extra.txt"},
			[]entry{{1, "extra.txt", fileInclude}}},
		{"over three lines", []string{`--requirement \`, `\`, "more.txt"},
			[]entry{{1, "more.txt", fileInclude}}},
		{"CRLF line endings", []string{"-r \\\r", "extra.txt\r"},
			[]entry{{1, "extra.txt", fileInclude}}},
		{"editable install", []string{`-e \`, "git+https://example.invalid/repo.git#egg=x"},
			[]entry{{1, "", editable}}},
		{"name @ URL", []string{`paramiko @ \`, "https://example.invalid/p"},
			[]entry{{1, "paramiko", directRef}}},
		{"comment line ending in a backslash", []string{`# see below \`, "https://example.invalid/pkg.whl"},
			[]entry{{2, "", urlReq}}},
		{"comment line after a continued line", []string{`-r \`, "# a comment", "https://example.invalid/pkg.whl"},
			[]entry{{1, "", fileInclude}, {3, "", urlReq}}},
		{"backslash on the last line", []string{"cryptography==42.0.0", `-r \`},
			[]entry{{2, "", fileInclude}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "requirements.txt")
			if err := os.WriteFile(path, []byte(strings.Join(c.lines, "\n")+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			got := unreadLines(path)
			if len(got) != len(c.want) {
				t.Fatalf("unreadLines = %+v, want %d entries", got, len(c.want))
			}
			for i, w := range c.want {
				g := got[i]
				if g.Line != w.line || g.Name != w.name || !strings.HasPrefix(g.Reason, w.reason) {
					t.Errorf("unreadLines[%d] = %+v, want line %d name %q reason %q...", i, g, w.line, w.name, w.reason)
				}
				if strings.Contains(g.Name+g.Reason, "example.invalid") {
					t.Errorf("unreadLines[%d] copies a URL: %+v", i, g)
				}
			}
		})
	}
}

// pyproject.toml and Pipfile also go to the Python parser, which reads them
// with readers of their own, so a URL in either is not listed as an unread
// requirements line.
func TestUnreadLinesNotForPyprojectOrPipfile(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"pyproject.toml": "[project]\nname = \"x\"\ndependencies = [\"paramiko @ https://example.invalid/p.tar.gz\"]\n",
		"Pipfile":        "[packages]\nparamiko = {file = \"https://example.invalid/p.tar.gz\"}\n",
	})
	for _, name := range []string{"pyproject.toml", "Pipfile"} {
		if got := unreadLines(filepath.Join(dir, name)); got != nil {
			t.Errorf("unreadLines(%s) = %+v, want nil", name, got)
		}
	}
}

// writeFiles writes files, named relative to a new directory, and returns the
// directory.
func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// Other manifests report no unread lines.
func TestUnreadLinesOnlyForRequirementsTxt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package.json")
	if err := os.WriteFile(path, []byte(`{"name":"x","dependencies":{"a":"https://example.invalid/a.tgz"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := unreadLines(path); got != nil {
		t.Errorf("unreadLines(package.json) = %+v, want nil", got)
	}
}
