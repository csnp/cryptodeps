// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/csnp/qramm-cryptodeps/internal/analyzer"
	"github.com/csnp/qramm-cryptodeps/pkg/output"
)

// These tests hold the composite action in action.yml to one rule: an input
// reaches a run: script only through the step's env: block, and the script
// reads it as a quoted shell variable. The runner pastes a ${{ }} expression
// into the script text before bash parses it, so an input written that way is
// read as shell syntax rather than as a value.

type actionStep struct {
	Name  string            `yaml:"name"`
	ID    string            `yaml:"id"`
	Shell string            `yaml:"shell"`
	Run   string            `yaml:"run"`
	Env   map[string]string `yaml:"env"`
}

type actionFile struct {
	Inputs map[string]struct {
		Default string `yaml:"default"`
	} `yaml:"inputs"`
	Runs struct {
		Steps []actionStep `yaml:"steps"`
	} `yaml:"runs"`
}

func loadAction(t *testing.T) actionFile {
	t.Helper()
	var a actionFile
	if err := yaml.Unmarshal([]byte(readRepoFile(t, "action.yml")), &a); err != nil {
		t.Fatalf("parsing action.yml: %v", err)
	}
	if len(a.Runs.Steps) == 0 {
		t.Fatal("action.yml has no runs.steps")
	}
	return a
}

func TestActionRunScriptsHoldNoExpressions(t *testing.T) {
	a := loadAction(t)
	scripts := 0
	for _, step := range a.Runs.Steps {
		if step.Run == "" {
			continue
		}
		scripts++
		for i, line := range strings.Split(step.Run, "\n") {
			if strings.Contains(line, "${{") {
				t.Errorf("action.yml step %q, run line %d holds a ${{ }} expression; pass the value through env: instead: %s",
					step.Name, i+1, strings.TrimSpace(line))
			}
		}
	}
	if scripts == 0 {
		t.Fatal("action.yml has no run: scripts; the check above examined nothing")
	}
}

// inputRef is the only shape an env: value may take: one whole input.
var inputRef = regexp.MustCompile(`^\$\{\{\s*inputs\.([A-Za-z0-9_-]+)\s*\}\}$`)

func actionStepNamed(t *testing.T, a actionFile, name string) actionStep {
	t.Helper()
	for _, step := range a.Runs.Steps {
		if step.Name == name {
			return step
		}
	}
	t.Fatalf("action.yml has no step named %q", name)
	return actionStep{}
}

// stubTool writes an executable named name into dir. It records each argument
// it receives on its own NUL-terminated record in <dir>/<name>.args, so an
// argument that split or merged shows up as a different count.
func stubTool(t *testing.T, dir, name, body string) {
	t.Helper()
	script := "#!/usr/bin/env bash\n" +
		"for a in \"$@\"; do printf '%s\\0' \"$a\"; done > \"$(dirname \"$0\")/" + name + ".args\"\n" +
		body + "\n"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func stubArgs(t *testing.T, dir, name string) ([]string, bool) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name+".args"))
	if os.IsNotExist(err) {
		return nil, false
	}
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Split(string(b), "\x00")
	return args[:len(args)-1], true
}

type stepRun struct {
	exitCode int
	stdout   string
	outputs  map[string]string
}

// runActionStep runs one step's script the way a composite bash step runs:
// bash --noprofile --norc -eo pipefail, with the step's env: block resolved
// against inputs (falling back to the defaults in action.yml) and the stub
// tools in bin ahead of everything else on PATH.
func runActionStep(t *testing.T, a actionFile, step actionStep, inputs map[string]string, bin string) stepRun {
	t.Helper()
	if step.Shell != "bash" {
		t.Fatalf("step %q: shell is %q, these tests run bash steps", step.Name, step.Shell)
	}
	work := t.TempDir()
	scriptPath := filepath.Join(work, "step.sh")
	if err := os.WriteFile(scriptPath, []byte(step.Run), 0o644); err != nil {
		t.Fatal(err)
	}
	outputFile := filepath.Join(work, "github_output")
	if err := os.WriteFile(outputFile, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	env := []string{
		"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + work,
		"GITHUB_OUTPUT=" + outputFile,
	}
	for k, v := range step.Env {
		m := inputRef.FindStringSubmatch(v)
		if m == nil {
			t.Fatalf("step %q: env %s is %q; expected one whole ${{ inputs.<name> }}", step.Name, k, v)
		}
		in, declared := a.Inputs[m[1]]
		if !declared {
			t.Fatalf("step %q: env %s names input %q, which action.yml does not declare", step.Name, k, m[1])
		}
		val, given := inputs[m[1]]
		if !given {
			val = in.Default
		}
		env = append(env, k+"="+val)
	}

	cmd := exec.Command("bash", "--noprofile", "--norc", "-eo", "pipefail", scriptPath)
	cmd.Dir = work
	cmd.Env = env
	out, err := cmd.Output()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("step %q: running bash: %v", step.Name, err)
	}

	outputs := map[string]string{}
	b, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			outputs[k] = v
		}
	}
	return stepRun{exitCode: code, stdout: string(out), outputs: outputs}
}

func requireBash(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not on PATH")
	}
}

// awkwardValue is a value that bash would act on if it were pasted into the
// script text: spaces, quotes, a command substitution and a variable.
const awkwardValue = `dir with spaces/"q" $(echo pasted) ${HOME} 'x'`

func TestActionInstallStepPassesVersionAsOneArgument(t *testing.T) {
	requireBash(t)
	a := loadAction(t)
	step := actionStepNamed(t, a, "Install CryptoDeps")

	for _, tc := range []struct {
		version string
		want    string
	}{
		{"latest", "github.com/csnp/qramm-cryptodeps/cmd/cryptodeps@latest"},
		{"v1.3.0", "github.com/csnp/qramm-cryptodeps/cmd/cryptodeps@v1.3.0"},
		{awkwardValue, "github.com/csnp/qramm-cryptodeps/cmd/cryptodeps@" + awkwardValue},
	} {
		bin := t.TempDir()
		stubTool(t, bin, "go", "exit 0")
		r := runActionStep(t, a, step, map[string]string{"version": tc.version}, bin)
		if r.exitCode != 0 {
			t.Errorf("version %q: step exited %d", tc.version, r.exitCode)
		}
		got, _ := stubArgs(t, bin, "go")
		want := []string{"install", tc.want}
		if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
			t.Errorf("version %q: go received %q, want %q", tc.version, got, want)
		}
	}
}

func TestActionAnalyzeStepPassesInputsAsOneArgumentEach(t *testing.T) {
	requireBash(t)
	a := loadAction(t)
	step := actionStepNamed(t, a, "Run CryptoDeps Analysis")

	for _, code := range []int{0, 1, 2, 3} {
		bin := t.TempDir()
		stubTool(t, bin, "cryptodeps", "echo report\nexit "+strconv.Itoa(code))
		r := runActionStep(t, a, step, map[string]string{
			"path":    awkwardValue,
			"format":  "markdown",
			"fail-on": "partial",
		}, bin)
		if r.exitCode != code {
			t.Errorf("cryptodeps exit %d: step exited %d", code, r.exitCode)
		}
		if r.outputs["exit_code"] != strconv.Itoa(code) {
			t.Errorf("cryptodeps exit %d: exit_code output is %q", code, r.outputs["exit_code"])
		}
		if !strings.Contains(r.stdout, "report") {
			t.Errorf("cryptodeps exit %d: step did not print the report; stdout %q", code, r.stdout)
		}
		got, _ := stubArgs(t, bin, "cryptodeps")
		want := []string{"analyze", awkwardValue, "--format", "markdown", "--fail-on", "partial", "--offline"}
		if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
			t.Errorf("cryptodeps received %q, want %q", got, want)
		}
	}
}

// The action refuses a format or fail-on value before running the scan, so it
// must refuse exactly what the CLI refuses: a value the CLI runs must still
// run, and a value the CLI rejects must end in exit code 2, as it did when the
// CLI rejected it.
func TestActionAnalyzeStepAcceptsWhatTheCLIAccepts(t *testing.T) {
	requireBash(t)
	a := loadAction(t)
	step := actionStepNamed(t, a, "Run CryptoDeps Analysis")

	check := func(input, value string, cliAccepts bool) {
		t.Helper()
		bin := t.TempDir()
		stubTool(t, bin, "cryptodeps", "exit 0")
		r := runActionStep(t, a, step, map[string]string{input: value}, bin)
		_, ran := stubArgs(t, bin, "cryptodeps")
		switch {
		case cliAccepts && (!ran || r.exitCode != 0):
			t.Errorf("%s %q: the CLI accepts it, but the step exited %d (scan ran: %v)", input, value, r.exitCode, ran)
		case !cliAccepts && (ran || r.exitCode != 2 || r.outputs["exit_code"] != "2"):
			t.Errorf("%s %q: the CLI refuses it, but the step exited %d with exit_code output %q (scan ran: %v)",
				input, value, r.exitCode, r.outputs["exit_code"], ran)
		}
	}

	for _, v := range []string{"table", "json", "sarif", "cbom", "markdown", "md", "",
		"JSON", " json", "html", "json;", "json --offline", awkwardValue} {
		_, err := output.ParseFormat(v)
		check("format", v, err == nil)
	}
	for _, v := range []string{"vulnerable", "partial", "any", "none",
		"Partial", "  NONE ", "\tany\n", "", "all", "none;", "partial --format json", awkwardValue} {
		check("fail-on", v, analyzer.ValidateFailOn(v) == nil)
	}
}

func TestActionSarifStepWritesTheNamedFile(t *testing.T) {
	requireBash(t)
	a := loadAction(t)
	step := actionStepNamed(t, a, "Generate SARIF Report")

	out := t.TempDir()
	sarifFile := filepath.Join(out, `results with spaces $(echo x).sarif`)
	bin := t.TempDir()
	stubTool(t, bin, "cryptodeps", `echo '{"version":"2.1.0"}'`+"\nexit 2")
	r := runActionStep(t, a, step, map[string]string{
		"path":       awkwardValue,
		"sarif-file": sarifFile,
	}, bin)
	if r.exitCode != 0 {
		t.Errorf("step exited %d; a non-empty report must not fail the step", r.exitCode)
	}
	if !strings.Contains(r.stdout, "::warning::cryptodeps exited 2") {
		t.Errorf("step did not warn about exit 2; stdout %q", r.stdout)
	}
	b, err := os.ReadFile(sarifFile)
	if err != nil {
		t.Fatalf("SARIF file was not written at the named path: %v", err)
	}
	if !strings.Contains(string(b), `"2.1.0"`) {
		t.Errorf("SARIF file holds %q", b)
	}
	got, _ := stubArgs(t, bin, "cryptodeps")
	want := []string{"analyze", awkwardValue, "--format", "sarif", "--fail-on", "none", "--offline"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("cryptodeps received %q, want %q", got, want)
	}
}
