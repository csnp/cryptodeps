// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package githubapi

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

// TokenRejectedNotice is printed when GitHub answers 401 to a request that
// carried GITHUB_TOKEN and the request is sent again without it.
const TokenRejectedNotice = "Note: GitHub refused the token in GITHUB_TOKEN (HTTP 401: expired, revoked or not a github.com token), so the request was sent again without it. Unset GITHUB_TOKEN or replace it to stop this notice."

// noticeWriter is where Do prints TokenRejectedNotice. It is a variable so
// that a test can capture it.
var noticeWriter io.Writer = os.Stderr

// Do sends req with client. The callers read public data (the release list of
// a public repository, a public repository's metadata), which GitHub serves
// without a token. When req carries an Authorization header and GitHub
// answers 401, the token itself was refused, so the request is sent once more
// without it and TokenRejectedNotice is printed. Before this, a stale token in
// the shell turned `cryptodeps update` and GitHub URL scans into a bare
// "HTTP 401", while the same command without the token succeeded.
//
// req must have no body.
func Do(client *http.Client, req *http.Request) (*http.Response, error) {
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusUnauthorized || req.Header.Get("Authorization") == "" {
		return resp, err
	}
	resp.Body.Close()

	anonymous := req.Clone(req.Context())
	anonymous.Header.Del("Authorization")
	fmt.Fprintln(noticeWriter, TokenRejectedNotice)
	return client.Do(anonymous)
}
