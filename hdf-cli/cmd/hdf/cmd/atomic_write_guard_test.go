package cmd

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

// No command writes a file with os.WriteFile. Every writer here may be handed the user's
// own input as its destination, and os.WriteFile truncates before it writes, so a crash
// or a full disk mid-write destroys it; atomicfile.WriteFile stages and renames instead.
// Parsed rather than grepped so an aliased import of os is caught too.
func TestNoCommandWritesWithATruncatingOsWriteFile(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the package directory: %v", err)
	}
	var offenders []string
	inspected := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, parseErr := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", name, parseErr)
		}
		inspected++
		osNames := map[string]bool{}
		for _, imp := range file.Imports {
			if path, _ := strconv.Unquote(imp.Path.Value); path == "os" {
				alias := "os"
				if imp.Name != nil {
					alias = imp.Name.Name
				}
				osNames[alias] = true
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "WriteFile" {
				return true
			}
			if pkg, isIdent := sel.X.(*ast.Ident); isIdent && osNames[pkg.Name] {
				offenders = append(offenders, filepath.ToSlash(fset.Position(call.Pos()).String()))
			}
			return true
		})
	}
	// A pass must not mean the scan read nothing.
	if inspected < 50 {
		t.Fatalf("only %d source files inspected; the scan is not reaching the package", inspected)
	}
	if len(offenders) > 0 {
		t.Errorf("%d os.WriteFile call(s) in a command; use atomicfile.WriteFile so an "+
			"interrupted write cannot destroy the file it replaces:\n  %s",
			len(offenders), strings.Join(offenders, "\n  "))
	}
}
