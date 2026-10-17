// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

// Package netguard is the one place cryptodeps decides whether it may use the
// network.
//
// --offline used to be honoured by each caller that remembered to read it. The
// database auto-update and the source fetcher did; the GitHub fetch did not, and
// it was chosen before the flag was ever looked at, so a mistyped local path
// shaped like owner/repo was sent to api.github.com with --offline set. The
// module's HTTP clients and downloading subprocesses are now built here, so the
// check runs where a connection is made rather than at each call site.
//
// TestNetworkUseGoesThroughNetguard type-checks the non-test files elsewhere in
// the module and fails when one of them builds or holds an http.Client,
// http.Transport, net.Dialer, net.Resolver, tls.Dialer or exec.Cmd other than
// behind a pointer; uses a function or value the test lists from net/http, net,
// crypto/tls, os or syscall that connects, looks up a name or starts a program;
// or refers to exec.Command or exec.CommandContext anywhere but in a call that
// names tar or unzip by a constant. It reads this module's source only, so a
// client or program handed out by code in another module, or by a standard
// library function the test does not list, is not seen.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"sync/atomic"
	"time"
)

// ErrOffline is wrapped by every refusal, so a caller can tell a refused
// connection from a failed one.
var ErrOffline = errors.New("--offline is set")

var offline atomic.Bool

// SetOffline turns network use off or on for the whole process.
func SetOffline(v bool) {
	offline.Store(v)
}

// Offline reports whether network use is turned off.
func Offline() bool {
	return offline.Load()
}

// Check returns an error wrapping ErrOffline when network use is turned off.
// what describes the refused use for the error message.
func Check(what string) error {
	if offline.Load() {
		return fmt.Errorf("%w, so cryptodeps will not %s", ErrOffline, what)
	}
	return nil
}

// Client returns an HTTP client whose connections are dialled through Check.
// The check sits in the dialer rather than in front of the request, so it also
// covers the connection to a proxy, and it reads the policy when it dials, so a
// client built before --offline is parsed is held to it.
func Client(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	dial := transport.DialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if err := Check("connect to " + addr); err != nil {
			return nil, err
		}
		return dial(ctx, network, addr)
	}
	// TLS is dialled through DialContext only while DialTLSContext is unset.
	transport.DialTLSContext = nil
	return &http.Client{Timeout: timeout, Transport: transport}
}

// Command returns a command for a program that downloads, such as go mod
// download or npm pack, or an error wrapping ErrOffline when network use is
// turned off. Programs that only work on local files (tar, unzip) do not need
// it.
func Command(name string, args ...string) (*exec.Cmd, error) {
	if err := Check("run " + name); err != nil {
		return nil, err
	}
	return exec.Command(name, args...), nil
}
