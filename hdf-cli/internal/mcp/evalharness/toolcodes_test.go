package evalharness

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Derive, per tool, the taxonomy codes its handler can raise.
//
// Why this is derivable at all: every mcperr code in this repository is raised inside the
// one package internal/mcp/tools — nothing in loader, handle or elsewhere raises one — so
// reachability is an intra-package question and needs no cross-module call graph. The
// alternative was a hand-kept list per tool, which is the "API in disguise" ADR-0008 §2's
// closed grammar exists to prevent, and which rots the first time a handler gains an error
// path.
//
// The walk OVER-approximates on purpose. An intra-package call is resolved by the callee's
// identifier alone, so a method call matches every declaration of that name. Over-
// declaring costs a client an error branch that cannot fire; under-declaring means it meets
// an error the document never described.

const toolsPackageDir = "../tools"

// handlerFor maps an advertised tool name to the handler function that serves it:
// hdf_apply_amendment -> hdfApplyAmendment. A name that resolves to no declaration is a
// FAILURE rather than an empty code set, because silently deriving nothing is exactly the
// under-declaration this exists to prevent.
func handlerFor(tool string) string {
	parts := strings.Split(strings.TrimPrefix(tool, "hdf_"), "_")
	name := "hdf"
	for _, p := range parts {
		if p == "" {
			continue
		}
		name += strings.ToUpper(p[:1]) + p[1:]
	}
	return name
}

type packageGraph struct {
	// codes[fn] is the set of mcperr codes named directly in fn's body.
	codes map[string]map[string]bool
	// calls[fn] is the set of intra-package identifiers fn invokes.
	calls map[string]map[string]bool
	// declared is every function and method name the package declares.
	declared map[string]bool
	// constants maps an mcperr Go identifier to its wire code, e.g. WrongDocType ->
	// WRONG_DOC_TYPE, read from the taxonomy rather than restated here.
	constants map[string]string
}

func parseToolsPackage(t *testing.T, constants map[string]string) *packageGraph {
	t.Helper()
	// Read the directory and parse each file, rather than parser.ParseDir, which is
	// deprecated for not honouring build tags. The only build-tagged file in the tools
	// package is a _test.go, which this skips either way, so nothing a tag would hide is
	// in scope here.
	entries, err := os.ReadDir(toolsPackageDir)
	if err != nil {
		t.Fatalf("reading %s: %v", toolsPackageDir, err)
	}
	g := &packageGraph{
		codes:     map[string]map[string]bool{},
		calls:     map[string]map[string]bool{},
		declared:  map[string]bool{},
		constants: constants,
	}
	fset := token.NewFileSet()
	parsed := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(toolsPackageDir, name), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		parsed++
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			g.declared[fn.Name.Name] = true
			g.walkBody(fn.Name.Name, fn.Body)
		}
	}
	if parsed == 0 {
		t.Fatalf("parsed no files from %s, so every derived code set would be empty", toolsPackageDir)
	}
	return g
}

func (g *packageGraph) walkBody(owner string, body *ast.BlockStmt) {
	if g.codes[owner] == nil {
		g.codes[owner] = map[string]bool{}
	}
	if g.calls[owner] == nil {
		g.calls[owner] = map[string]bool{}
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			// mcperr.WrongDocType — the taxonomy reference that names a code.
			if pkg, ok := node.X.(*ast.Ident); ok && pkg.Name == "mcperr" {
				if wire, ok := g.constants[node.Sel.Name]; ok {
					g.codes[owner][wire] = true
				}
			}
		case *ast.CallExpr:
			switch callee := node.Fun.(type) {
			case *ast.Ident:
				g.calls[owner][callee.Name] = true
			case *ast.SelectorExpr:
				// A method call. Resolved by name alone, which over-approximates.
				g.calls[owner][callee.Sel.Name] = true
			}
		}
		return true
	})
}

// reachable is the transitive closure of codes raised from fn.
func (g *packageGraph) reachable(fn string) []string {
	seen := map[string]bool{}
	found := map[string]bool{}
	var walk func(string)
	walk = func(name string) {
		if seen[name] || !g.declared[name] {
			return
		}
		seen[name] = true
		for code := range g.codes[name] {
			found[code] = true
		}
		for callee := range g.calls[name] {
			walk(callee)
		}
	}
	walk(fn)
	codes := make([]string, 0, len(found))
	for code := range found {
		codes = append(codes, code)
	}
	slices.Sort(codes)
	return codes
}

// mcperrConstants reads the taxonomy's Go identifier -> wire code mapping from its own
// source, so the walk never carries a second copy of the taxonomy to drift from.
func mcperrConstants(t *testing.T) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join("..", "mcperr", "mcperr.go"), nil, 0)
	if err != nil {
		t.Fatalf("parsing the taxonomy: %v", err)
	}
	constants := map[string]string{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || len(value.Values) != 1 {
				continue
			}
			lit, ok := value.Values[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			constants[value.Names[0].Name] = strings.Trim(lit.Value, `"`)
		}
	}
	if len(constants) == 0 {
		t.Fatal("no taxonomy constants parsed, so every derived code set would be empty")
	}
	return constants
}

// toolErrorCodes is what the golden records: tool name -> the codes it can raise.
func toolErrorCodes(t *testing.T, tools []string) map[string][]string {
	t.Helper()
	graph := parseToolsPackage(t, mcperrConstants(t))
	perTool := map[string][]string{}
	for _, tool := range tools {
		handler := handlerFor(tool)
		if !graph.declared[handler] {
			t.Fatalf("tool %s resolves to handler %s, which the tools package does not declare; "+
				"the naming convention changed and deriving nothing would silently under-declare",
				tool, handler)
		}
		perTool[tool] = graph.reachable(handler)
	}
	return perTool
}

// The walk resolves an intra-package call by the callee's identifier, which means two
// shapes are invisible to it: a function literal in a package-level `var` declaration, and
// dispatch through an index expression (`table[key](...)`), where the callee is neither an
// Ident nor a SelectorExpr. Neither shape carries a code today.
//
// This is the guard for that, and it is deliberately not a list of the shapes: it asserts
// that every code raised ANYWHERE in the package is reachable from some handler, so a code
// that drifts into an invisible shape stops being reachable and fails here.
//
// Its bound, stated because the comparison is a UNION: a code whose every reachable raise
// site becomes invisible is caught, but one that drifts out of a single handler's path
// while still raised visibly elsewhere is not — the union stays complete and that tool's
// set silently loses it.
func TestToolErrorCodes_EveryRaisedCodeIsReachableFromSomeHandler(t *testing.T) {
	constants := mcperrConstants(t)
	entries, err := os.ReadDir(toolsPackageDir)
	if err != nil {
		t.Fatalf("reading %s: %v", toolsPackageDir, err)
	}
	raisedAnywhere := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(toolsPackageDir, name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		for ident, wire := range constants {
			if strings.Contains(string(body), "mcperr."+ident) {
				raisedAnywhere[wire] = true
			}
		}
	}
	if len(raisedAnywhere) == 0 {
		t.Fatal("found no raised code in the package, so this comparison is vacuous")
	}

	reachable := map[string]bool{}
	for _, codes := range toolErrorCodes(t, toolNamesFromGolden(t)) {
		for _, code := range codes {
			reachable[code] = true
		}
	}

	for code := range raisedAnywhere {
		if !reachable[code] {
			t.Errorf("%s is raised in the tools package and is reachable from no handler: it has "+
				"moved into a shape the call walk cannot see (a package-level func literal, or "+
				"dispatch through an index expression), so the API document would silently stop "+
				"declaring it", code)
		}
	}
}
