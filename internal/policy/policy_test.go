// Package policy holds architecture tests: rules from the design's threat
// model (report section 7) enforced on the source tree itself, so a change
// that breaks one fails CI rather than waiting for a reviewer to notice.
package policy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type file struct {
	rel  string // slash-separated, relative to the module root
	ast  *ast.File
	fset *token.FileSet
}

func sources(t *testing.T) []file {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root not found at %s", root)
	}
	var out []file
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) && p != root {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		out = append(out, file{rel: filepath.ToSlash(rel), ast: f, fset: fset})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) < 20 {
		t.Fatalf("found only %d source files; the walk is broken", len(out))
	}
	return out
}

func imports(f file) []string {
	var out []string
	for _, imp := range f.ast.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		out = append(out, p)
	}
	return out
}

// No shell, no templates that execute, no plugins, no reflection-driven
// calls, no unsafe memory: content from a technique file must never be able
// to become code.
func TestForbiddenImports(t *testing.T) {
	forbidden := map[string]string{
		"os/exec":       "no shell or subprocess (only the future exec detection adapter may, behind one reviewed file)",
		"text/template": "no template engine: substitution is the fixed {{scope.field}} syntax",
		"html/template": "no template engine",
		"plugin":        "no runtime plugins: providers are compiled in",
		"reflect":       "no reflection-driven dispatch",
		"unsafe":        "no unsafe memory access",
		"net/rpc":       "no RPC surface",
	}
	for _, f := range sources(t) {
		for _, imp := range imports(f) {
			if why, bad := forbidden[imp]; bad {
				t.Errorf("%s imports %s: %s", f.rel, imp, why)
			}
		}
	}
}

// The core and the simulated provider never touch the network. Real
// providers (providers/<name>/, not fake) are the only code that may.
func TestNoNetworkOutsideRealProviders(t *testing.T) {
	for _, f := range sources(t) {
		realProvider := strings.HasPrefix(f.rel, "providers/") && !strings.HasPrefix(f.rel, "providers/fake/")
		if realProvider {
			continue
		}
		for _, imp := range imports(f) {
			if imp == "net" || (strings.HasPrefix(imp, "net/") && imp != "net/netip" && imp != "net/url") {
				t.Errorf("%s imports %s: only real provider packages may use the network", f.rel, imp)
			}
		}
	}
}

// The tool listens on nothing, ever.
func TestNoListener(t *testing.T) {
	banned := map[string]bool{"Listen": true, "ListenTCP": true, "ListenUDP": true, "ListenUnix": true, "ListenPacket": true,
		"ListenAndServe": true, "ListenAndServeTLS": true, "Serve": true, "ServeTLS": true}
	for _, f := range sources(t) {
		names := map[string]string{}
		for _, imp := range f.ast.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			name := p[strings.LastIndex(p, "/")+1:]
			if imp.Name != nil {
				name = imp.Name.Name
			}
			names[name] = p
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && banned[sel.Sel.Name] {
				if p := names[id.Name]; p == "net" || p == "net/http" {
					t.Errorf("%s: %s.%s: the tool must not listen on anything", f.fset.Position(sel.Pos()), id.Name, sel.Sel.Name)
				}
			}
			return true
		})
	}
}

// A raw credential is readable in exactly one kind of place: a provider's
// transport, which sets the Authorization header.
func TestRevealOnlyInTransports(t *testing.T) {
	calls := 0
	for _, f := range sources(t) {
		allowed := strings.HasPrefix(f.rel, "internal/secret/") ||
			(strings.HasPrefix(f.rel, "providers/") && strings.HasSuffix(f.rel, "/transport.go"))
		ast.Inspect(f.ast, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Reveal" {
				calls++
				if !allowed {
					t.Errorf("%s: Reveal() outside a provider transport", f.fset.Position(sel.Pos()))
				}
			}
			return true
		})
	}
	if calls == 0 {
		t.Fatal("no Reveal calls found at all; the check is not looking at the right files")
	}
}

// Ops must not be able to see a credential: the op-facing types carry none.
func TestOpFacingTypesHoldNoSecrets(t *testing.T) {
	for _, f := range sources(t) {
		if f.rel != "internal/provider/op.go" && f.rel != "internal/journal/journal.go" && f.rel != "internal/report/record.go" {
			continue
		}
		for _, imp := range imports(f) {
			if strings.HasSuffix(imp, "/internal/secret") {
				t.Errorf("%s imports the secret package: calls, journal records and output records must never hold a secret", f.rel)
			}
		}
	}
}
