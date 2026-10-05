// Package contract collects the MCP surface the ADR-0008 API generator reads: the response
// shapes a tool returns, keyed by name.
//
// It exists so a generator has ONE typed source instead of inferring HTTP response bodies
// from prose. A shape is registered by the package that owns the Go type, which means an
// unexported row type contributes its shape without its package exporting it — the
// generator consumes the reflected schema from the tracked golden and never needs the Go
// type itself.
//
// The dependency edge is one-way: packages that own shapes import this, and this imports
// none of them.
package contract

import (
	"fmt"
	"reflect"
	"sort"
	"sync"

	"github.com/google/jsonschema-go/jsonschema"
)

// Registry holds named response shapes. The package-level functions delegate to a default
// registry that packages populate from init.
//
// A test builds its own with NewRegistry, because Register panics on a duplicate name: a
// test that needs to re-register an existing shape under its real name cannot use the
// default registry at all.
type Registry struct {
	mu     sync.RWMutex
	shapes map[string]reflect.Type
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{shapes: map[string]reflect.Type{}}
}

var defaultRegistry = NewRegistry()

// Register records the Go type of one named response shape, panicking on a duplicate name
// or a nil example.
//
// Panics rather than returning an error because registration happens at init: a duplicate
// name means two shapes would collide in the contract, and serving a contract that silently
// lost one is worse than not starting. The name is the generator's key, so it is stable
// API — `query.concise`, `diff.temporal.full`, and so on.
func (r *Registry) Register(name string, example any) {
	if example == nil {
		panic("contract: shape " + name + " registered with a nil example")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, dup := r.shapes[name]; dup {
		panic(fmt.Sprintf("contract: shape %q already registered as %s", name, existing))
	}
	r.shapes[name] = reflect.TypeOf(example)
}

// Names lists the registered shape names, sorted.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.shapes))
	for name := range r.shapes {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Shapes reflects every registered type to a JSON Schema.
//
// Reflected rather than hand-written so the contract cannot drift from the struct: a field
// added to a row appears here without anyone remembering to describe it.
func (r *Registry) Shapes() (map[string]*jsonschema.Schema, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]*jsonschema.Schema, len(r.shapes))
	for name, typ := range r.shapes {
		s, err := jsonschema.ForType(typ, nil)
		if err != nil {
			return nil, fmt.Errorf("reflecting the %s shape (%s): %w", name, typ, err)
		}
		out[name] = s
	}
	return out, nil
}

// RegisterShape records a shape in the default registry. This is the hook another module
// calls from its own init to contribute a shape it owns.
func RegisterShape(name string, example any) { defaultRegistry.Register(name, example) }

// Names lists the default registry's shape names, sorted.
func Names() []string { return defaultRegistry.Names() }

// Shapes reflects the default registry's types to JSON Schemas.
func Shapes() (map[string]*jsonschema.Schema, error) { return defaultRegistry.Shapes() }
