//go:build ignore

// Reports comment groups in the named Go files that exceed the thresholds it is
// given, as JSON on stdout.
//
// go/ast rather than a line scanner: a "//" inside a string literal is not a
// comment, and a line-based reader would report one.
//
// "doc" is positional, as godoc is: a declaration's own comment, or one above the
// package clause. A file overview placed BELOW the package clause is attached to
// nothing and is judged as any other comment run — which is also where godoc
// would decline to show it.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
)

type violation struct {
	File  string `json:"file"`
	Line  int    `json:"line"`
	Kind  string `json:"kind"`
	Count int    `json:"count"`
}

func main() {
	cfgPath := flag.String("config", "", "path to comment-length.config.json (required)")
	flag.Parse()
	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "comment-length: -config is required; the thresholds have one source")
		os.Exit(2)
	}
	cfg, err := readConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "comment-length: %v\n", err)
		os.Exit(2)
	}
	doc, inline, line := &cfg.Doc, &cfg.Inline, &cfg.Line

	out := []violation{}
	for _, path := range flag.Args() {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			fmt.Fprintf(os.Stderr, "comment-length: %s: %v\n", path, err)
			os.Exit(2)
		}
		// go/ast has already done the attaching; these are the groups it chose.
		docs := map[*ast.CommentGroup]bool{}
		ast.Inspect(f, func(n ast.Node) bool {
			switch d := n.(type) {
			case *ast.FuncDecl:
				mark(docs, d.Doc)
			case *ast.GenDecl:
				mark(docs, d.Doc)
			case *ast.TypeSpec:
				mark(docs, d.Doc)
			case *ast.ValueSpec:
				mark(docs, d.Doc)
			case *ast.Field:
				mark(docs, d.Doc)
			}
			return true
		})
		mark(docs, f.Doc)
		pkgLine := fset.Position(f.Package).Line

		for _, cg := range f.Comments {
			start := fset.Position(cg.Pos()).Line
			// A header sits above the package clause and documents the file.
			isDoc := docs[cg] || start < pkgLine
			kind := "inline"
			limit := *inline
			if isDoc {
				kind, limit = "doc", *doc
			}
			if n := countLines(cg); n > limit {
				out = append(out, violation{path, start, kind, n})
			}
			for _, c := range cg.List {
				for i, l := range strings.Split(c.Text, "\n") {
					if len([]rune(l)) > *line {
						out = append(out, violation{path, fset.Position(c.Pos()).Line + i, "line", len([]rune(l))})
					}
				}
			}
		}
	}
	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "comment-length: %v\n", err)
		os.Exit(2)
	}
}

type thresholds struct {
	Doc    int `json:"doc"`
	Inline int `json:"inline"`
	Line   int `json:"line"`
}

func readConfig(path string) (thresholds, error) {
	var t thresholds
	b, err := os.ReadFile(path)
	if err != nil {
		return t, err
	}
	if err := json.Unmarshal(b, &t); err != nil {
		return t, fmt.Errorf("%s: %w", path, err)
	}
	if t.Doc <= 0 || t.Inline <= 0 || t.Line <= 0 {
		return t, fmt.Errorf("%s: doc, inline and line must all be positive", path)
	}
	return t, nil
}

func mark(m map[*ast.CommentGroup]bool, cg *ast.CommentGroup) {
	if cg != nil {
		m[cg] = true
	}
}

// countLines counts rendered lines, so a /* */ block counts every line it spans.
func countLines(cg *ast.CommentGroup) int {
	n := 0
	for _, c := range cg.List {
		n += strings.Count(c.Text, "\n") + 1
	}
	return n
}
