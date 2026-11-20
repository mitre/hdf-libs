package datasets_test

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Datasets a program cannot reach must not reach its binary. Aliasing an
// embedded var at package scope defeats that: the load runs in package init,
// which is always reachable, so the linker keeps the bytes. Reading the var
// inside the loader leaves it strippable. Only a linked binary shows the
// difference, so this builds one.
var reachableFromProbe = map[string]bool{
	"mappings/owasp-nist-mappings.json":     true, // the table it looks up
	"mappings/nist-revision-crosswalk.json": true, // NISTControl translates revisions
}

func TestAConsumerLinksOnlyTheDatasetsItCanReach(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "deadstrip")
	if out, err := exec.Command("go", "build", "-o", bin, "./testdata/deadstrip").CombinedOutput(); err != nil {
		t.Fatalf("building the probe: %v\n%s", err, out)
	}
	linked, err := os.ReadFile(bin)
	if err != nil {
		t.Fatalf("reading the probe binary: %v", err)
	}

	corpus := readCorpus(t)
	for rel := range reachableFromProbe {
		if _, ok := corpus[rel]; !ok {
			t.Fatalf("reachableFromProbe names %q, which is not in the corpus; the "+
				"expectation cannot be matched and every verdict below would be inverted", rel)
		}
	}
	for rel, data := range corpus {
		marker := uniqueMarker(t, rel, data, corpus)
		switch present := bytes.Contains(linked, marker); {
		case reachableFromProbe[rel] && !present:
			t.Errorf("%s is absent from the probe binary, but the probe reads it", rel)
		case !reachableFromProbe[rel] && present:
			t.Errorf("%s (%d B) is linked into a program that cannot reach it; "+
				"something aliases it at package scope instead of reading it in a loader", rel, len(data))
		}
	}
}

// readCorpus returns every dataset keyed by its path relative to the package.
func readCorpus(t *testing.T) map[string][]byte {
	t.Helper()
	corpus := make(map[string][]byte)
	for dir, files := range wantFiles {
		for _, f := range files {
			rel := filepath.Join(dir, f)
			data, err := os.ReadFile(rel)
			if err != nil {
				t.Fatalf("reading %s: %v", rel, err)
			}
			// Keyed with forward slashes so reachableFromProbe matches on
			// Windows, where filepath.Join yields a backslash.
			corpus[filepath.ToSlash(rel)] = data
		}
	}
	return corpus
}

// uniqueMarker returns the shortest central slice of data that occurs in no
// other dataset. These files share repeated row structure, so a fixed-size
// slice can collide and report an unrelated dataset as linked.
func uniqueMarker(t *testing.T, rel string, data []byte, corpus map[string][]byte) []byte {
	t.Helper()
	for size := 64; size <= 4096 && size <= len(data); size *= 2 {
		marker := data[len(data)/2 : len(data)/2+size]
		if !occursElsewhere(marker, rel, corpus) {
			return marker
		}
	}
	t.Fatalf("no slice of %s up to 4096 B is unique to it; the test cannot tell it apart", rel)
	return nil
}

func occursElsewhere(marker []byte, rel string, corpus map[string][]byte) bool {
	for other, data := range corpus {
		if other != rel && bytes.Contains(data, marker) {
			return true
		}
	}
	return false
}

// The binary probe proves the mechanism, but only for the packages in its own
// import graph. This one covers every sibling package by reading their source:
// a dataset read inside a loader is strippable, while an initialised package
// var moves the load into init, which is always reachable.
func TestNoPackageScopeAliasOfADataset(t *testing.T) {
	entries, err := os.ReadDir("..")
	if err != nil {
		t.Fatalf("reading the module directory: %v", err)
	}
	checked := 0
	for _, e := range entries {
		if !e.IsDir() || e.Name() == "datasets" {
			continue
		}
		sources, err := filepath.Glob(filepath.Join("..", e.Name(), "*.go"))
		if err != nil {
			t.Fatalf("listing %s: %v", e.Name(), err)
		}
		for _, src := range sources {
			if strings.HasSuffix(src, "_test.go") {
				continue
			}
			checked++
			for _, name := range packageScopeDatasetAliases(t, src) {
				t.Errorf("%s declares package-scope var %q from datasets; read the dataset "+
					"inside the loader instead, or the linker can never drop it", src, name)
			}
		}
	}
	if checked == 0 {
		t.Fatal("found no sibling package sources to check; the walk is not looking where it should")
	}
}

// packageScopeDatasetAliases returns the names of top-level vars in src whose
// initialiser mentions the datasets package.
func packageScopeDatasetAliases(t *testing.T, src string) []string {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), src, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", src, err)
	}
	var found []string
	for _, decl := range parsed.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, expr := range value.Values {
				if i < len(value.Names) && mentionsDatasets(expr) {
					found = append(found, value.Names[i].Name)
				}
			}
		}
	}
	return found
}

func mentionsDatasets(expr ast.Expr) bool {
	mentions := false
	ast.Inspect(expr, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "datasets" {
			mentions = true
			return false
		}
		return true
	})
	return mentions
}
