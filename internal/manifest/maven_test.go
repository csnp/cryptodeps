// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMavenPropertyInACoordinateIsResolved is the regression test for a
// dependency that was refused because its name still held a placeholder.
//
// Properties were resolved in the version and not in the groupId or artifactId,
// so ${project.groupId}, which is how a multi-module build names a sibling
// module, survived into the coordinate. Coordinate validation then refused it as
// a name that could steer a fetch, and the dependency was reported as
// unexaminable. Measured across 2,099 real poms from Maven Central: 81
// coordinates in 16 published artifacts, and on one real pom the tool analyzed 6
// dependencies where the same pom with the property expanded analyzed 11.
func TestMavenPropertyInACoordinateIsResolved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pom.xml")
	pom := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.springframework</groupId>
  <artifactId>spring-webmvc-struts</artifactId>
  <version>2.5.6</version>
  <properties>
    <bc.group>org.bouncycastle</bc.group>
    <bc.version>1.78.1</bc.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>${project.groupId}</groupId>
      <artifactId>spring-web</artifactId>
      <version>${project.version}</version>
    </dependency>
    <dependency>
      <groupId>${bc.group}</groupId>
      <artifactId>bcpkix-jdk18on</artifactId>
      <version>${bc.version}</version>
    </dependency>
    <dependency>
      <groupId>commons-codec</groupId>
      <artifactId>commons-codec</artifactId>
      <version>1.16.1</version>
    </dependency>
  </dependencies>
</project>`
	if err := os.WriteFile(path, []byte(pom), 0644); err != nil {
		t.Fatalf("write pom: %v", err)
	}

	deps, err := (&MavenParser{}).Parse(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	byName := make(map[string]string)
	for _, d := range deps {
		byName[d.Name] = d.Version
	}

	// Guard the fixture: the ordinary coordinate must parse, or a failure below
	// could just mean the file was never read.
	if _, ok := byName["commons-codec:commons-codec"]; !ok {
		t.Fatalf("the literal coordinate is missing, so the fixture was not parsed: %v", byName)
	}

	for _, want := range []struct{ name, version string }{
		{"org.springframework:spring-web", "2.5.6"},
		{"org.bouncycastle:bcpkix-jdk18on", "1.78.1"},
	} {
		got, ok := byName[want.name]
		if !ok {
			t.Errorf("%s is missing; an unresolved placeholder survived into the coordinate "+
				"and the dependency is refused as an invalid name. Parsed: %v",
				want.name, byName)
			continue
		}
		if got != want.version {
			t.Errorf("%s version = %q, want %q", want.name, got, want.version)
		}
	}
	for name := range byName {
		if strings.Contains(name, "${") {
			t.Errorf("coordinate %q still carries an unresolved property", name)
		}
	}
}
