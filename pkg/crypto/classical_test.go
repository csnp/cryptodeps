// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"testing"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// The classically broken set holds only VULNERABLE algorithms, and the
// Shor-class ones stay out of it.
func TestIsClassicallyBroken(t *testing.T) {
	for _, algo := range []string{"MD5", "SHA-1", "sha1", "DES", "3DES", "RC4", "RC2"} {
		if !IsClassicallyBroken(algo) {
			t.Errorf("IsClassicallyBroken(%q) = false, want true", algo)
		}
		if risk := GetQuantumRisk(algo); risk != types.RiskVulnerable {
			t.Errorf("%s has risk %s, want VULNERABLE", algo, risk)
		}
	}
	for _, algo := range []string{"RSA", "ECDSA", "Ed25519", "X25519", "DSA", "AES", "SHA-256", "HMAC-MD5"} {
		if IsClassicallyBroken(algo) {
			t.Errorf("IsClassicallyBroken(%q) = true, want false", algo)
		}
	}
}
