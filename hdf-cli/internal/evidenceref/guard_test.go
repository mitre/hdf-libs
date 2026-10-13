package evidenceref_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// referenceFields are the document members that hold a reference. Taken from the schema's
// own reference-bearing fields rather than from memory, and the one place to add to if the
// schema grows another.
var referenceFields = map[string]bool{
	"uri":                true,
	"href":               true,
	"contents":           true,
	"externalEvidence":   true,
	"externalReferences": true,
	"systemRef":          true,
	"planRef":            true,
}

// Nothing outside the reference seam may reach into a document for a reference field.
//
// WHY A GUARD AND NOT A CONVENTION: hdf-libs-52n0c.31 fixed FIVE sites that each reached
// in and did their own thing — update's duplicate check, bundle's -o guard (which let an
// archive overwrite the evidence it was packaging), add-evidence's duplicate index (which
// recorded one artifact twice, once unchecksummed), add-reference's href write, and set's
// relative branch. Four review rounds found them, one at a time, each by reading a file
// nobody had re-examined. The method that kept failing was enumerating the consumers by
// recall, and no amount of care fixes that: a grep finds what you name.
//
// WHY go/ast AND NOT grep: a grep for `entry["uri"]` misses `m["uri"]`, `c["uri"]`, and
// every other receiver spelling. The parser does not care what the map variable is called.
//
// WHAT IS PERMITTED IS AN EXACT SET, NOT AN ALLOW-LIST OF FILES. hdf-libs-52n0c.30 took
// five attempts because each fix excluded the case just demonstrated and grew a new hole;
// the shape that finally held was permitting one thing and rejecting everything else. So
// one file may do this, and a new bypass anywhere fails here NAMING ITS LINE — it does not
// have to be anticipated to be caught.
func TestNoConsumerResolvesAReferenceOutsideTheSeam(t *testing.T) {
	root := filepath.Join("..", "..")
	const seam = "internal/evidenceref"

	// Turning a reference into something readable. A function that reads a reference field
	// AND calls one of these is resolving — and resolving is what must go through the seam,
	// because it is where the decode has to happen and where containment has to see the
	// decoded form.
	resolvers := map[string]bool{
		"Join": true, "SafePath": true, "Open": true, "Stat": true,
		"ReadFile": true, "readFromFile": true, "readInputFile": true,
		"readInputFileAndRaw": true, "Abs": true, "EvalSymlinks": true,
	}

	var offenders []string
	inspected := 0
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if d.Name() == "testdata" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		if strings.HasPrefix(filepath.ToSlash(rel), seam) {
			return nil
		}

		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		fset := token.NewFileSet()
		file, parseErr := parser.ParseFile(fset, path, src, 0)
		if parseErr != nil {
			return parseErr
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			inspected++
			// Assignment TARGETS are writes, not reads. pkg["systemRef"] = ... is recording a
			// reference, which needs Encode — a different invariant from resolving one, and
			// counting it here produced a false positive on evidence build.
			written := map[ast.Node]bool{}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if as, ok := n.(*ast.AssignStmt); ok {
					for _, lhs := range as.Lhs {
						written[lhs] = true
					}
				}
				return true
			})

			var readsRef *ast.BasicLit
			callsResolver := ""
			usesSeam := false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.IndexExpr:
					if written[node] {
						return true
					}
					if lit, isLit := node.Index.(*ast.BasicLit); isLit && lit.Kind == token.STRING {
						if referenceFields[strings.Trim(lit.Value, `"`+"`")] && readsRef == nil {
							readsRef = lit
						}
					}
				case *ast.CallExpr:
					switch f := node.Fun.(type) {
					case *ast.SelectorExpr:
						// Going through the seam is what compliance looks like.
						if pkg, isIdent := f.X.(*ast.Ident); isIdent && pkg.Name == "evidenceref" {
							usesSeam = true
						}
						if resolvers[f.Sel.Name] && callsResolver == "" {
							callsResolver = f.Sel.Name
						}
					case *ast.Ident:
						if resolvers[f.Name] && callsResolver == "" {
							callsResolver = f.Name
						}
					}
				}
				return true
			})
			if readsRef != nil && callsResolver != "" && !usesSeam {
				pos := fset.Position(readsRef.Pos())
				offenders = append(offenders, filepath.ToSlash(rel)+":"+strconv.Itoa(pos.Line)+
					"  func "+fn.Name.Name+" reads "+readsRef.Value+" and calls "+callsResolver)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk the source: %v", err)
	}

	// WHAT THIS DOES NOT HOLD, stated because every guard in this epic that claimed
	// completeness was wrong: it asks whether a function that resolves a reference ALSO
	// goes through the seam. A function doing both — seam for one reference, raw for
	// another — satisfies it. That is narrower than "no reference is ever resolved raw",
	// and the honest claim is that a NEW function resolving references without the seam
	// at all cannot be added silently.
	//
	// A pass must not mean the walk read nothing.
	if inspected < 100 {
		t.Fatalf("only %d functions inspected; the walk is not reaching the source", inspected)
	}
	if len(offenders) > 0 {
		t.Errorf("%d function(s) resolve a reference without going through %s. Each is a place "+
			"the decode can be forgotten, which is how 52n0c.31 shipped five of them — including "+
			"one that let an archive overwrite the evidence it was packaging:\n  %s",
			len(offenders), seam, strings.Join(offenders, "\n  "))
	}
}
