// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"fmt"
	"math"
	"runtime"
	"strings"
	"testing"
	"time"
)

// npmManifest returns a package.json declaring n dependencies, one per line,
// the first of them on line 4.
func npmManifest(n int) []byte {
	var b strings.Builder
	b.WriteString("{\n  \"name\": \"big\",\n  \"dependencies\": {\n")
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(",\n")
		}
		fmt.Fprintf(&b, "    \"pkg-%d\": \"^1.0.0\"", i)
	}
	b.WriteString("\n  }\n}\n")
	return []byte(b.String())
}

// pomManifest returns a pom.xml declaring n dependencies in five lines each,
// the first artifactId on line 6.
func pomManifest(n int) []byte {
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\"?>\n<project>\n  <dependencies>\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "    <dependency>\n      <groupId>org.example</groupId>\n      <artifactId>art-%d</artifactId>\n      <version>1.0.%d</version>\n    </dependency>\n", i, i)
	}
	b.WriteString("  </dependencies>\n</project>\n")
	return []byte(b.String())
}

// fastestOf returns the shortest of runs timings of f. Garbage is collected
// before each run, so that one run's garbage is not charged to the next.
func fastestOf(runs int, f func()) time.Duration {
	best := time.Duration(math.MaxInt64)
	for i := 0; i < runs; i++ {
		runtime.GC()
		start := time.Now()
		f()
		if d := time.Since(start); d < best {
			best = d
		}
	}
	return best
}

// TestDeclarationLinesDoNotRecountTheFile is the regression test for the
// declaration line of each dependency being found by counting newlines from
// the start of the file, once per dependency. The manifest under scan is text
// anyone who can open a pull request can change, so its size and dependency
// count are the attacker's to choose.
//
// The test compares the walk of a manifest with the walk of one growthFactor
// times larger, rather than either with a fixed time, so that a slower machine
// or the race detector, which slow both walks alike, does not decide the
// result. A walk that reads the file once grows by about growthFactor; one
// that recounts the file per dependency grows by about its square.
func TestDeclarationLinesDoNotRecountTheFile(t *testing.T) {
	const (
		growthFactor = 8
		maxGrowth    = 20
		runs         = 3
	)

	t.Run("package.json", func(t *testing.T) {
		const small = 25000
		const large = small * growthFactor
		smallDoc, largeDoc := npmManifest(small), npmManifest(large)

		lines := npmDeclarationLines(largeDoc)["dependencies"]
		if len(lines) != large {
			t.Fatalf("%d dependency lines, want %d", len(lines), large)
		}
		for _, i := range []int{0, large / 2, large - 1} {
			name := fmt.Sprintf("pkg-%d", i)
			if got, want := lines[name], 4+i; got != want {
				t.Errorf("%s on line %d, want %d", name, got, want)
			}
		}

		smallTime := fastestOf(runs, func() { npmDeclarationLines(smallDoc) })
		largeTime := fastestOf(runs, func() { npmDeclarationLines(largeDoc) })
		growth := float64(largeTime) / float64(smallTime)
		t.Logf("%v for %d dependencies, %v for %d: %.1f times as long", smallTime, small, largeTime, large, growth)
		if growth > maxGrowth {
			t.Errorf("npmDeclarationLines took %v for %d dependencies (%d bytes) and %v for %d (%d bytes): %.1f times as long for %d times the input, want at most %d",
				smallTime, small, len(smallDoc), largeTime, large, len(largeDoc), growth, growthFactor, maxGrowth)
		}
	})

	t.Run("pom.xml", func(t *testing.T) {
		const small = 6250
		const large = small * growthFactor
		smallDoc, largeDoc := pomManifest(small), pomManifest(large)

		lines := mavenArtifactLines(largeDoc)
		if len(lines) != large {
			t.Fatalf("%d dependency lines, want %d", len(lines), large)
		}
		for _, i := range []int{0, large / 2, large - 1} {
			if got, want := lines[i], 6+5*i; got != want {
				t.Errorf("dependency %d on line %d, want %d", i, got, want)
			}
		}

		smallTime := fastestOf(runs, func() { mavenArtifactLines(smallDoc) })
		largeTime := fastestOf(runs, func() { mavenArtifactLines(largeDoc) })
		growth := float64(largeTime) / float64(smallTime)
		t.Logf("%v for %d dependencies, %v for %d: %.1f times as long", smallTime, small, largeTime, large, growth)
		if growth > maxGrowth {
			t.Errorf("mavenArtifactLines took %v for %d dependencies (%d bytes) and %v for %d (%d bytes): %.1f times as long for %d times the input, want at most %d",
				smallTime, small, len(smallDoc), largeTime, large, len(largeDoc), growth, growthFactor, maxGrowth)
		}
	})
}
