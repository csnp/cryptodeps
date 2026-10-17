// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package netguard

import (
	"errors"
	"fmt"
	"go/ast"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func setOffline(t *testing.T, v bool) {
	t.Helper()
	SetOffline(v)
	t.Cleanup(func() { SetOffline(false) })
}

// countingServer is a local HTTP server that counts the connections opened to
// it, so a test can tell a refused connection from a request that failed after
// connecting.
func countingServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var conns atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, &conns
}

func TestClientMakesNoConnectionWhenOffline(t *testing.T) {
	srv, conns := countingServer(t)
	client := Client(5 * time.Second)

	setOffline(t, true)
	resp, err := client.Get(srv.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("request succeeded with --offline set")
	}
	if !errors.Is(err, ErrOffline) {
		t.Errorf("error does not wrap ErrOffline, so a caller cannot tell it was refused: %v", err)
	}
	if n := conns.Load(); n != 0 {
		t.Errorf("%d connection(s) reached the server with --offline set, want 0", n)
	}

	// The same client connects once the policy allows it, so the zero above
	// was the policy and not a server that could not be reached.
	SetOffline(false)
	resp, err = client.Get(srv.URL)
	if err != nil {
		t.Fatalf("request failed with the network allowed: %v", err)
	}
	resp.Body.Close()
	if n := conns.Load(); n != 1 {
		t.Errorf("%d connection(s) reached the server with the network allowed, want 1", n)
	}
}

// The policy is read when a connection is dialled, not when the client is
// built, so a client created at package initialisation, before the flag is
// parsed, is still held to it.
func TestClientBuiltBeforeOfflineIsSetIsStillRefused(t *testing.T) {
	srv, conns := countingServer(t)
	client := Client(5 * time.Second)
	setOffline(t, true)

	if resp, err := client.Get(srv.URL); err == nil {
		resp.Body.Close()
		t.Fatal("request succeeded with --offline set")
	}
	if n := conns.Load(); n != 0 {
		t.Errorf("%d connection(s) reached the server, want 0", n)
	}
}

// The connection to a proxy is dialled through the same check, so a proxy
// named by HTTPS_PROXY sees nothing either.
func TestClientMakesNoConnectionToAProxyWhenOffline(t *testing.T) {
	proxy, conns := countingServer(t)
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := Client(5 * time.Second)
	client.Transport.(*http.Transport).Proxy = http.ProxyURL(proxyURL)

	setOffline(t, true)
	if resp, err := client.Get("http://example.invalid/"); err == nil {
		resp.Body.Close()
		t.Fatal("request succeeded with --offline set")
	} else if !errors.Is(err, ErrOffline) {
		t.Errorf("error does not wrap ErrOffline: %v", err)
	}
	if n := conns.Load(); n != 0 {
		t.Errorf("%d connection(s) reached the proxy with --offline set, want 0", n)
	}

	// With the network allowed, the request goes to the proxy, so the zero
	// above was the policy.
	SetOffline(false)
	resp, err := client.Get("http://example.invalid/")
	if err != nil {
		t.Fatalf("request through the proxy failed with the network allowed: %v", err)
	}
	resp.Body.Close()
	if n := conns.Load(); n != 1 {
		t.Errorf("%d connection(s) reached the proxy with the network allowed, want 1", n)
	}
}

func TestCommandIsRefusedWhenOffline(t *testing.T) {
	setOffline(t, true)
	cmd, err := Command("curl", "-sL", "https://example.invalid/")
	if err == nil {
		t.Fatalf("Command returned %v with --offline set, want an error", cmd)
	}
	if !errors.Is(err, ErrOffline) {
		t.Errorf("error does not wrap ErrOffline: %v", err)
	}
	if !strings.Contains(err.Error(), "curl") {
		t.Errorf("error does not name the program it refused: %v", err)
	}

	SetOffline(false)
	if _, err := Command("curl"); err != nil {
		t.Errorf("Command refused with the network allowed: %v", err)
	}
}

// localPrograms are the programs the tool runs that work on local files only.
// Any other program is assumed to download, and has to be started through
// Command.
var localPrograms = map[string]bool{"tar": true, "unzip": true}

// guardedTypes are the types whose values connect, or start a program, where
// Check never sees it. Client and Command hand them out as pointers, so the
// scan flags the type where it is named other than behind a pointer (in a
// composite literal, new(), a variable, field, parameter or result, a type
// alias or definition, or a type argument), a literal of it nested in another
// literal with its type left out, a generic call that infers it, and a value
// of it used other than as the operand of & or the left side of a selector,
// such as the *p in c := *p.
var guardedTypes = []string{
	"net/http.Client",
	"net/http.Transport",
	"net.Dialer",
	"net.Resolver",
	"crypto/tls.Dialer",
	"os/exec.Cmd",
}

// referenced are the package-level functions and values that connect, look up
// a name, or start a program, without a client or command built here.
var referenced = map[string]bool{
	"net/http.Get":              true,
	"net/http.Post":             true,
	"net/http.PostForm":         true,
	"net/http.Head":             true,
	"net/http.DefaultClient":    true,
	"net/http.DefaultTransport": true,
	"net.Dial":                  true,
	"net.DialTimeout":           true,
	"net.DialTCP":               true,
	"net.DialUDP":               true,
	"net.DialIP":                true,
	"net.DialUnix":              true,
	"net.LookupAddr":            true,
	"net.LookupCNAME":           true,
	"net.LookupHost":            true,
	"net.LookupIP":              true,
	"net.LookupMX":              true,
	"net.LookupNS":              true,
	"net.LookupPort":            true,
	"net.LookupSRV":             true,
	"net.LookupTXT":             true,
	"net.ResolveIPAddr":         true,
	"net.ResolveTCPAddr":        true,
	"net.ResolveUDPAddr":        true,
	"net.DefaultResolver":       true,
	"crypto/tls.Dial":           true,
	"crypto/tls.DialWithDialer": true,
	"os.StartProcess":           true,
	"syscall.Exec":              true,
	"syscall.ForkExec":          true,
	"syscall.StartProcess":      true,
}

// netScanner type-checks source against the standard library, so a guarded
// type or function is recognised when the source reaches it through an import
// name, a dot import, a type alias, a variable holding a function, or a zero
// value that no literal spells out.
type netScanner struct {
	fset    *token.FileSet
	std     types.Importer
	guarded map[string]types.Type
}

func newNetScanner(t *testing.T) *netScanner {
	t.Helper()
	fset := token.NewFileSet()
	s := &netScanner{fset: fset, std: importer.ForCompiler(fset, "gc", nil), guarded: map[string]types.Type{}}

	// Every package the scan matches against is loaded here, so a standard
	// library the scanner cannot read fails the test instead of passing it:
	// the checker would put an empty package in its place and find nothing.
	paths := map[string]bool{}
	for name := range referenced {
		paths[name[:strings.LastIndex(name, ".")]] = true
	}
	for _, name := range guardedTypes {
		paths[name[:strings.LastIndex(name, ".")]] = true
	}
	pkgs := map[string]*types.Package{}
	for p := range paths {
		pkg, err := s.std.Import(p)
		if err != nil {
			t.Fatalf("load %s: %v", p, err)
		}
		pkgs[p] = pkg
	}
	for _, name := range guardedTypes {
		dot := strings.LastIndex(name, ".")
		tn, ok := pkgs[name[:dot]].Scope().Lookup(name[dot+1:]).(*types.TypeName)
		if !ok {
			t.Fatalf("%s is not a type", name)
		}
		s.guarded[name] = tn.Type()
	}
	return s
}

// Import loads standard library packages and refuses any other path. The
// checker puts an empty package in place of a refused one and carries on, so
// third-party modules need not be downloaded, and a type or function defined
// in another package of this module is matched in that package, where it is
// written.
func (s *netScanner) Import(path string) (*types.Package, error) {
	if first, _, _ := strings.Cut(path, "/"); strings.Contains(first, ".") {
		return nil, fmt.Errorf("%s is not in the standard library", path)
	}
	return s.std.Import(path)
}

// byValue reports which guarded type t is, when t is one, or an alias of one,
// or a type defined from one, rather than a pointer to it.
func (s *netScanner) byValue(t types.Type) (string, bool) {
	if t == nil {
		return "", false
	}
	for _, name := range guardedTypes {
		if types.Identical(t.Underlying(), s.guarded[name].Underlying()) {
			return name, true
		}
	}
	return "", false
}

// scan type-checks files as one package and lists the guarded types,
// referenced functions and values, and os/exec commands in them that do not go
// through this package.
func (s *netScanner) scan(files []*ast.File) []string {
	info := &types.Info{
		Types:     map[ast.Expr]types.TypeAndValue{},
		Uses:      map[*ast.Ident]types.Object{},
		Instances: map[*ast.Ident]types.Instance{},
	}
	// Type errors are expected, since packages outside the standard library
	// are left empty. With Error set, the checker carries on past them.
	conf := types.Config{Importer: s, FakeImportC: true, Error: func(error) {}}
	_, _ = conf.Check("scanned/"+files[0].Name.Name, s.fset, files, info)

	type finding struct {
		pos  token.Pos
		what string
	}
	var found []finding
	report := func(pos token.Pos, what string) {
		found = append(found, finding{pos, what})
	}

	// pointees are the type expressions written behind a *, inPlace the
	// operands of & and the left sides of selectors, which are used where they
	// are without being copied, and callees the calls each called identifier
	// belongs to.
	pointees := map[ast.Expr]bool{}
	inPlace := map[ast.Expr]bool{}
	callees := map[*ast.Ident]*ast.CallExpr{}
	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.StarExpr:
				pointees[unparen(n.X)] = true
			case *ast.UnaryExpr:
				if n.Op == token.AND {
					inPlace[unparen(n.X)] = true
				}
			case *ast.SelectorExpr:
				inPlace[unparen(n.X)] = true
			case *ast.CallExpr:
				switch fun := unparen(n.Fun).(type) {
				case *ast.Ident:
					callees[fun] = n
				case *ast.SelectorExpr:
					callees[fun.Sel] = n
				}
			}
			return true
		})
	}

	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			e, ok := n.(ast.Expr)
			if !ok {
				return true
			}
			if _, ok := e.(*ast.ParenExpr); ok {
				return true
			}
			tv, ok := info.Types[e]
			if !ok {
				return true
			}
			if tv.IsType() {
				if name, ok := s.byValue(tv.Type); ok && !pointees[e] {
					report(e.Pos(), name+" built or held by value, not through netguard")
				}
			} else if lit, ok := e.(*ast.CompositeLit); ok {
				// A literal with its type written is flagged at the type.
				if lit.Type != nil {
					return true
				}
				// A literal elided from []*T{{}} has the type *T.
				t := tv.Type
				if p, ok := t.Underlying().(*types.Pointer); ok {
					t = p.Elem()
				}
				if name, ok := s.byValue(t); ok {
					report(e.Pos(), name+" constructed directly")
				}
			} else if tv.IsValue() && !inPlace[e] {
				// A value copied out of a pointer, as in c := *p, names no type.
				if name, ok := s.byValue(tv.Type); ok {
					report(e.Pos(), name+" copied by value, not through netguard")
				}
			}
			return true
		})
	}

	for id, obj := range info.Uses {
		pkg := obj.Pkg()
		if pkg == nil || pkg.Scope().Lookup(obj.Name()) != obj {
			continue
		}
		name := pkg.Path() + "." + obj.Name()
		switch {
		case referenced[name]:
			report(id.Pos(), name+" used directly")
		case name == "os/exec.Command" || name == "os/exec.CommandContext":
			prog := 0
			if name == "os/exec.CommandContext" {
				prog = 1
			}
			if !localProgram(info, callees[id], prog) {
				report(id.Pos(), name+" for a program not known to be local; start it with netguard.Command")
			}
		}
	}

	for id, inst := range info.Instances {
		for i := 0; i < inst.TypeArgs.Len(); i++ {
			if name, ok := s.byValue(inst.TypeArgs.At(i)); ok {
				report(id.Pos(), id.Name+" instantiated with "+name+" by value, not through netguard")
			}
		}
	}

	sort.Slice(found, func(i, j int) bool {
		if found[i].pos != found[j].pos {
			return found[i].pos < found[j].pos
		}
		return found[i].what < found[j].what
	})
	var out []string
	for _, f := range found {
		line := fmt.Sprintf("%s: %s", s.fset.Position(f.pos), f.what)
		if len(out) == 0 || out[len(out)-1] != line {
			out = append(out, line)
		}
	}
	return out
}

// localProgram reports whether call starts tar or unzip, named by a constant
// in argument prog. A nil call is a reference to the function that is not a
// call, so the program it will start is unknown.
func localProgram(info *types.Info, call *ast.CallExpr, prog int) bool {
	if call == nil || len(call.Args) <= prog {
		return false
	}
	v := info.Types[call.Args[prog]].Value
	return v != nil && v.Kind() == constant.String && localPrograms[constant.StringVal(v)]
}

func unparen(e ast.Expr) ast.Expr {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = p.X
	}
}

// scanSource parses each source as one file of the same package and scans
// them together.
func scanSource(t *testing.T, s *netScanner, srcs ...string) []string {
	t.Helper()
	var files []*ast.File
	for i, src := range srcs {
		file, err := parser.ParseFile(s.fset, fmt.Sprintf("case%d.go", i), src, 0)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		files = append(files, file)
	}
	return s.scan(files)
}

// The scan below is only as good as its detector, so the detector is held to
// cases on both sides of the line.
func TestDirectNetworkUseDetector(t *testing.T) {
	s := newNetScanner(t)
	flagged := map[string]string{
		"client literal":    `package p; import "net/http"; var c = &http.Client{}`,
		"transport literal": `package p; import "net/http"; var tr = http.Transport{}`,
		"new client":        `package p; import "net/http"; var c = new(http.Client)`,
		"http.Get":          `package p; import "net/http"; func f() { http.Get("u") }`,
		"aliased default":   `package p; import h "net/http"; var c = h.DefaultClient`,
		"net.Dial":          `package p; import "net"; func f() { net.Dial("tcp", "a") }`,
		"dialer literal":    `package p; import "net"; var d = net.Dialer{}`,
		"tls.Dial":          `package p; import "crypto/tls"; func f() { tls.Dial("tcp", "a", nil) }`,
		"downloader":        `package p; import "os/exec"; func f() { exec.Command("curl", "u") }`,
		"variable program":  `package p; import "os/exec"; func f(n string) { exec.Command(n) }`,
		"command context":   `package p; import ("context"; "os/exec"); func f() { exec.CommandContext(context.TODO(), "npm") }`,
		"zero-value client": `package p; import "net/http"; func f(u string) { var c http.Client; c.Get(u) }`,
		"zero-value dialer": `package p; import "net"; func f(a string) { var d net.Dialer; d.Dial("tcp", a) }`,
		"tls dialer":        `package p; import "crypto/tls"; var d = &tls.Dialer{}`,
		"net.LookupHost":    `package p; import "net"; func f(h string) { net.LookupHost(h) }`,
		"default resolver":  `package p; import ("context"; "net"); func f(ctx context.Context, h string) { net.DefaultResolver.LookupHost(ctx, h) }`,
		"cmd literal":       `package p; import "os/exec"; var c = &exec.Cmd{Path: "/usr/bin/curl"}`,
		"command as value":  `package p; import "os/exec"; func f(u string) { run := exec.Command; run("curl", u) }`,
		"os.StartProcess":   `package p; import "os"; func f() { os.StartProcess("/usr/bin/curl", nil, nil) }`,
		"dot import":        `package p; import . "net/http"; func f(u string) { Get(u) }`,
		"client field":      `package p; import "net/http"; type T struct{ c http.Client }; func (t *T) f(u string) { t.c.Get(u) }`,
		"type alias":        `package p; import "net/http"; type C = http.Client; var c = &C{}`,
		"defined type":      `package p; import "net/http"; type C http.Client; var c = &C{}`,
		"resolver literal":  `package p; import "net"; var r = &net.Resolver{PreferGo: true}`,
		"net.ResolveTCP":    `package p; import "net"; func f(a string) { net.ResolveTCPAddr("tcp", a) }`,
		"syscall process":   `package p; import "syscall"; func f() { syscall.StartProcess("/usr/bin/curl", nil, nil) }`,
		"client slice":      `package p; import "net/http"; var cs = make([]http.Client, 1)`,
		"elided literal":    `package p; import "net/http"; var cs = []*http.Client{{}}`,
		"inferred generic":  `package p; import "net/http"; func zero[T any](*T) T { var t T; return t }; func f(c *http.Client) { z := zero(c); z.Get("u") }`,
		"parenthesised":     `package p; import "net/http"; var c (http.Client)`,
		"third-party call":  `package p; import ("example.com/cli"; "net/http"); var c = cli.Command{Run: func() { http.Get("u") }}`,
		"parameter":         `package p; import "net/http"; func f(c http.Client, u string) { c.Get(u) }`,
		"result":            `package p; import "net/http"; func f() (tr http.Transport) { return }`,
		"type argument":     `package p; import "net"; func zero[T any]() T { var t T; return t }; var d = zero[net.Dialer]()`,
		"dereferenced copy": `package p; import "net/http"; func f(p *http.Client, u string) { c := *p; c.Get(u) }`,
	}
	for name, src := range flagged {
		t.Run("flags "+name, func(t *testing.T) {
			if got := scanSource(t, s, src); len(got) == 0 {
				t.Errorf("not flagged: %s", src)
			}
		})
	}

	allowed := map[string]string{
		"client type":          `package p; import "net/http"; type T struct{ c *http.Client }; func f(r *http.Request) {}`,
		"request":              `package p; import "net/http"; func f() { http.NewRequest("GET", "u", nil) }`,
		"local program":        `package p; import "os/exec"; func f() { exec.Command("tar", "-xzf", "a") }`,
		"other package":        `package p; import "example.com/http"; var c = http.Get`,
		"client pointer":       `package p; import "net/http"; func f(c *http.Client, u string) { c.Get(u) }`,
		"command pointer":      `package p; import "os/exec"; func f(c *exec.Cmd) error { return c.Run() }`,
		"type assertion":       `package p; import "net/http"; func f(rt http.RoundTripper) { _ = rt.(*http.Transport) }`,
		"local constant":       `package p; import "os/exec"; const prog = "unzip"; func f() { exec.Command(prog, "a") }`,
		"parsing only":         `package p; import "net"; var ip = net.ParseIP("127.0.0.1")`,
		"other dot import":     `package p; import . "example.com/http"; func f() { Get("u") }`,
		"own Dial":             `package p; func Dial() {}; func f() { Dial() }`,
		"pointer (parens)":     `package p; import "net/http"; var c *(http.Client)`,
		"dereferenced call":    `package p; import "net/http"; func f(p *http.Client, u string) { (*p).Get(u) }`,
		"dereferenced address": `package p; import "net/http"; func f(p *http.Client) *http.Client { return &*p }`,
	}
	for name, src := range allowed {
		t.Run("allows "+name, func(t *testing.T) {
			if got := scanSource(t, s, src); len(got) != 0 {
				t.Errorf("flagged %v in: %s", got, src)
			}
		})
	}

	// The files of a package are checked together, so a constant from one
	// file is known in another.
	t.Run("allows a local program named in another file", func(t *testing.T) {
		got := scanSource(t, s,
			`package p; const prog = "tar"`,
			`package p; import "os/exec"; func f() { exec.Command(prog, "-xzf", "a") }`)
		if len(got) != 0 {
			t.Errorf("flagged %v", got)
		}
	})
}

// moduleRoot is the directory holding this module's go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test directory")
		}
		dir = parent
	}
}

// TestNetworkUseGoesThroughNetguard is what makes netguard the one check: in a
// non-test file of this module, a guarded type held or built by value, a
// function or value listed in referenced, or an os/exec command for a program
// other than tar or unzip fails here until it goes through this package, so a
// fetch added later in one of those forms cannot skip --offline.
func TestNetworkUseGoesThroughNetguard(t *testing.T) {
	root := moduleRoot(t)
	self, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	s := newNetScanner(t)
	var scanned []string
	packages := map[string][]*ast.File{} // directory and package name -> files
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if p != root && (strings.HasPrefix(name, ".") || name == "testdata" || name == "vendor" || name == "node_modules") {
				return filepath.SkipDir
			}
			// A nested module is not part of this build.
			if p != root {
				if _, err := os.Stat(filepath.Join(p, "go.mod")); err == nil {
					return filepath.SkipDir
				}
			}
			if p == self {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(s.fset, p, nil, 0)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		scanned = append(scanned, filepath.ToSlash(rel))
		// Files are checked in packages, so a name defined in one file is
		// known in the others.
		key := filepath.Dir(p) + " " + file.Name.Name
		packages[key] = append(packages[key], file)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	keys := make([]string, 0, len(packages))
	for k := range packages {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var violations []string
	for _, k := range keys {
		violations = append(violations, s.scan(packages[k])...)
	}

	// Guard the walk: the files that make network connections today have to be
	// among those read, or an empty walk would pass.
	sort.Strings(scanned)
	for _, want := range []string{
		"cmd/cryptodeps/main.go",
		"internal/analyzer/github.go",
		"internal/analyzer/source/fetcher.go",
		"internal/database/updater.go",
		"internal/registry/npm.go",
	} {
		if i := sort.SearchStrings(scanned, want); i == len(scanned) || scanned[i] != want {
			t.Errorf("%s was not scanned", want)
		}
	}

	for _, v := range violations {
		t.Errorf("network use outside netguard: %s", v)
	}
}
