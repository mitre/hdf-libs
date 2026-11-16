package legacyhdf

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// The version-baked names were renamed to Legacy*; this pins that they stay gone.
var removedV1Names = []string{
	"ConvertV1ToV2", "IsHDFV1", "IsHDFV1FromMap", "HDFV1Results",
	"V1Result", "V1SourceLocation", "V1Description", "V1Control", "V1Group",
	"V1Dependency", "V1Profile", "V1Platform", "V1Statistics",
}

func TestRemovedV1NamesAreNotDeclared(t *testing.T) {
	declared := packageTopLevelNames(t)
	for _, name := range removedV1Names {
		if declared[name] {
			t.Errorf("legacyhdf still declares removed name %s", name)
		}
	}
	current := []string{"ConvertLegacyHDF", "IsLegacyHDF", "IsLegacyHDFFromMap", "LegacyHDFResults"}
	for _, name := range current {
		if !declared[name] {
			t.Errorf("legacyhdf no longer declares current name %s", name)
		}
	}
}

func packageTopLevelNames(t *testing.T) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	names := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			addDeclNames(names, d)
		}
	}
	return names
}

func addDeclNames(names map[string]bool, d ast.Decl) {
	switch d := d.(type) {
	case *ast.FuncDecl:
		if d.Recv == nil {
			names[d.Name.Name] = true
		}
	case *ast.GenDecl:
		for _, s := range d.Specs {
			switch s := s.(type) {
			case *ast.TypeSpec:
				names[s.Name.Name] = true
			case *ast.ValueSpec:
				for _, n := range s.Names {
					names[n.Name] = true
				}
			}
		}
	}
}
