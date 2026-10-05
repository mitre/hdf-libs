package contract

import (
	"slices"
	"strings"
	"testing"
)

type probeRow struct {
	Ref   string `json:"ref"`
	Count int    `json:"count"`
}

type otherRow struct {
	Other bool `json:"other"`
}

// The panics are this package's stated contract, so they are tested rather than asserted in
// a doc comment. Both fire at init, where a wrong contract must stop the server rather than
// be served.
func TestRegister_RefusesADuplicateName(t *testing.T) {
	r := NewRegistry()
	r.Register("a.row", probeRow{})

	defer func() {
		rec := recover()
		if rec == nil {
			t.Fatal("re-registering a name must panic; otherwise one of the two shapes is " +
				"silently dropped and the contract describes the wrong body")
		}
		if got := toString(rec); !strings.Contains(got, "a.row") || !strings.Contains(got, "already registered") {
			t.Errorf("the panic must name the colliding shape, got: %v", rec)
		}
	}()
	r.Register("a.row", otherRow{})
}

func TestRegister_RefusesANilExample(t *testing.T) {
	r := NewRegistry()
	defer func() {
		rec := recover()
		if rec == nil {
			t.Fatal("a nil example must panic; reflect.TypeOf(nil) is nil and would reach " +
				"Shapes as an unreflectable entry")
		}
		if got := toString(rec); !strings.Contains(got, "nil example") {
			t.Errorf("the panic must say the example was nil, got: %v", rec)
		}
	}()
	r.Register("b.row", nil)
}

func TestNames_AreSortedAndComplete(t *testing.T) {
	r := NewRegistry()
	// Registered out of order, so a sorted result cannot be an accident of insertion.
	for _, name := range []string{"z.row", "a.row", "m.row"} {
		r.Register(name, probeRow{})
	}
	got := r.Names()
	want := []string{"a.row", "m.row", "z.row"}
	if !slices.Equal(got, want) {
		t.Errorf("Names() = %v, want %v sorted", got, want)
	}
}

func TestShapes_ReflectsEveryRegisteredType(t *testing.T) {
	r := NewRegistry()
	r.Register("probe", probeRow{})
	r.Register("other", otherRow{})

	shapes, err := r.Shapes()
	if err != nil {
		t.Fatalf("reflecting: %v", err)
	}
	if len(shapes) != 2 {
		t.Fatalf("expected 2 shapes, got %d", len(shapes))
	}
	probe := shapes["probe"]
	if probe == nil {
		t.Fatal("the probe shape is missing")
	}
	// The json tags, not the Go field names: the tags are what a client sees.
	for _, field := range []string{"ref", "count"} {
		if _, present := probe.Properties[field]; !present {
			t.Errorf("the reflected shape must describe %q by its json tag", field)
		}
	}
}

// An empty registry must reflect to an empty map rather than nil, so a caller can range
// over it without a check and a contract built from it carries `{}` not `null`.
func TestShapes_EmptyRegistryIsNotNil(t *testing.T) {
	shapes, err := NewRegistry().Shapes()
	if err != nil {
		t.Fatalf("reflecting an empty registry: %v", err)
	}
	if shapes == nil {
		t.Error("an empty registry must reflect to an empty map, not nil")
	}
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if e, ok := v.(error); ok {
		return e.Error()
	}
	return ""
}

// The package-level functions are the hook another module actually calls, so they are
// tested rather than assumed to delegate. A unique name keeps this from colliding with the
// real registrations if this package is ever tested alongside a populated default.
func TestPackageLevelHookDelegatesToTheDefaultRegistry(t *testing.T) {
	const name = "contract.test.delegate"

	RegisterShape(name, probeRow{})

	if !slices.Contains(Names(), name) {
		t.Errorf("RegisterShape must reach the default registry; Names() = %v", Names())
	}
	shapes, err := Shapes()
	if err != nil {
		t.Fatalf("reflecting the default registry: %v", err)
	}
	shape, present := shapes[name]
	if !present {
		t.Fatal("a shape registered through the package-level hook must appear in Shapes()")
	}
	if _, described := shape.Properties["ref"]; !described {
		t.Errorf("the delegated shape must be reflected, not just named; got %v", shape)
	}
}

// Shapes must not fail on a type jsonschema-go cannot describe without saying which shape
// it was — a bare reflection error names a Go type, not the contract key a reader can act
// on.
func TestShapes_NamesTheShapeItCouldNotReflect(t *testing.T) {
	r := NewRegistry()
	// A channel has no JSON representation, so reflection must refuse it.
	r.Register("unreflectable", make(chan int))

	_, err := r.Shapes()
	if err == nil {
		t.Fatal("reflecting a channel must fail; a contract cannot describe it")
	}
	if !strings.Contains(err.Error(), "unreflectable") {
		t.Errorf("the error must name the shape, got: %v", err)
	}
}
