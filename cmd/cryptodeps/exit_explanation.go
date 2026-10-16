// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"strings"

	"github.com/csnp/qramm-cryptodeps/internal/analyzer"
	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// exitExplanation returns the line printed on stderr after the report when
// findings set the exit code, and "" when there is nothing to explain.
//
// The gate counts findings the report does not show (see exitCodeForSummary),
// so a summary reading "0 vulnerable" can sit above an exit code of 1, and a
// table listing one finding as used by your code can sit above an exit code
// produced by eight. Nothing on any stream said which findings failed the build.
// This line reads the same counts the gate reads, and splits the findings the
// report shows by reachability where that ran. Withheld findings are given as
// one count: the filters run before reachability, so none was computed for them.
//
// Exit 0 needs no explanation and exit 2 keeps its own messages. The line goes
// to stderr only, so JSON, SARIF and CBOM on stdout are unchanged.
func exitExplanation(code int, threshold string, s types.ScanSummary, projects []*types.ScanResult) string {
	threshold = analyzer.CanonicalFailOn(threshold)
	if threshold == "" {
		// The gate's default branch, which is the default policy.
		threshold = "vulnerable"
	}
	prefix := fmt.Sprintf("Exit code %d (--fail-on %s): ", code, threshold)

	switch code {
	case ExitVulnerable:
		if s.QuantumVulnerable+s.WithheldVulnerable > 0 {
			return prefix + explainFindings("quantum-vulnerable", types.RiskVulnerable,
				s.QuantumVulnerable, s.WithheldVulnerable, projects)
		}
	case ExitPartial:
		if s.QuantumPartial+s.WithheldPartial > 0 {
			return prefix + explainFindings("partial-risk", types.RiskPartial,
				s.QuantumPartial, s.WithheldPartial, projects)
		}
		if threshold == "any" && s.WithCrypto+s.WithheldWithCrypto > 0 {
			return prefix + explainAnyCrypto(s)
		}
	}
	return ""
}

// explainFindings describes the findings at one risk level that set the code:
// how many the scan made, how the ones in the report split by reachability, and
// how many a filter hid.
func explainFindings(label string, risk types.QuantumRisk, shown, withheld int, projects []*types.ScanResult) string {
	total := shown + withheld
	var b strings.Builder
	fmt.Fprintf(&b, "the scan found %d %s %s.", total, label, plural(total, "finding", "findings"))

	if shown == 0 {
		if total == 1 {
			b.WriteString(" It is not in the report: --risk or --min-severity hid it, and" +
				" hidden findings still count toward the exit code.")
		} else {
			b.WriteString(" None of them is in the report: --risk or --min-severity hid them, and" +
				" hidden findings still count toward the exit code.")
		}
		b.WriteString(" Run the same command without --risk and --min-severity to list them.")
		return b.String()
	}

	split := splitByReachability(projects, risk, shown)
	switch {
	case withheld == 0 && len(split) > 0:
		fmt.Fprintf(&b, " %s.", joinPhrases(split))
	case withheld > 0 && len(split) > 0:
		fmt.Fprintf(&b, " Of the %d in the report, %s.", shown, joinPhrases(split))
	case withheld > 0:
		fmt.Fprintf(&b, " %d %s in the report.", shown, plural(shown, "is", "are"))
	}

	if withheld == 1 {
		b.WriteString(" The other one was hidden by --risk or --min-severity and still counts" +
			" toward the exit code.")
	} else if withheld > 1 {
		fmt.Fprintf(&b, " The other %d were hidden by --risk or --min-severity and still count"+
			" toward the exit code.", withheld)
	}
	if withheld > 0 {
		b.WriteString(" Run the same command without --risk and --min-severity to list them.")
	}
	return b.String()
}

// splitByReachability counts the findings at one risk level that the report
// shows, by reachability, and returns one phrase per non-empty group. It
// returns nothing when reachability classified none of them, which is the case
// for every ecosystem it does not cover, and nothing when the findings it walks
// do not add up to the gate's count, so the line never states a split that
// disagrees with the number before it.
func splitByReachability(projects []*types.ScanResult, risk types.QuantumRisk, shown int) []string {
	var confirmed, reachable, available, unchecked int
	for _, p := range projects {
		if p == nil {
			continue
		}
		for _, dep := range p.Dependencies {
			if dep.Analysis == nil {
				continue
			}
			for _, c := range dep.Analysis.Crypto {
				if c.QuantumRisk != risk {
					continue
				}
				switch c.Reachability {
				case types.ReachabilityConfirmed:
					confirmed++
				case types.ReachabilityReachable:
					reachable++
				case types.ReachabilityAvailable:
					available++
				default:
					unchecked++
				}
			}
		}
	}

	if confirmed+reachable+available == 0 || confirmed+reachable+available+unchecked != shown {
		return nil
	}

	var phrases []string
	if confirmed > 0 {
		phrases = append(phrases, fmt.Sprintf("%d %s called from your code",
			confirmed, plural(confirmed, "is", "are")))
	}
	if reachable > 0 {
		phrases = append(phrases, fmt.Sprintf("%d %s reached from your code through other calls",
			reachable, plural(reachable, "is", "are")))
	}
	if available > 0 {
		phrases = append(phrases, fmt.Sprintf("%d %s where no call from your code was found",
			available, plural(available, "is in a dependency", "are in dependencies")))
	}
	if unchecked > 0 {
		phrases = append(phrases, fmt.Sprintf("%d %s not checked for calls from your code",
			unchecked, plural(unchecked, "was", "were")))
	}
	return phrases
}

// explainAnyCrypto describes an exit 3 under --fail-on any where nothing was
// vulnerable or partial: the policy fails on cryptography of any kind.
func explainAnyCrypto(s types.ScanSummary) string {
	deps := s.WithCrypto + s.WithheldWithCrypto
	line := fmt.Sprintf("the scan found cryptography in %d %s, and --fail-on any fails on"+
		" any cryptography, including quantum-safe algorithms.",
		deps, plural(deps, "dependency", "dependencies"))
	const still = " was hidden by --risk or --min-severity, and hidden findings still count" +
		" toward the exit code."
	switch n := s.WithheldWithCrypto; {
	case n == 0:
	case n == deps && deps == 1:
		line += " Every finding in it" + still
	case n == deps:
		line += " In all of them every finding" + still
	default:
		line += fmt.Sprintf(" In %d of them every finding", n) + still
	}
	return line
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// joinPhrases joins phrases as "a", "a and b" or "a, b and c".
func joinPhrases(phrases []string) string {
	switch len(phrases) {
	case 0:
		return ""
	case 1:
		return phrases[0]
	}
	return strings.Join(phrases[:len(phrases)-1], ", ") + " and " + phrases[len(phrases)-1]
}
