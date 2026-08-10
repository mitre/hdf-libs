//go:build !windows

// Package xsdvalidate provides XML-against-XSD validation for converter output
// tests, for formats whose authoritative schema is an XSD rather than JSON
// Schema (e.g. XCCDF).
//
// It wraps terminalstatic/go-xsd-validate (libxml2 via cgo), so importing this
// package pulls in a cgo + libxml2 build dependency. It lives in its own package
// precisely so that dependency stays isolated to the XSD-validating tests — the
// main shared/go package (imported by every converter) stays cgo-free.
//
// The real implementation builds only where libxml2 is available (Linux CI,
// local macOS); Windows gets the skipping stub in xsdvalidate_windows.go, since
// libxml2 headers are absent on Windows runners and the validated output is
// platform-independent.
package xsdvalidate

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	xsd "github.com/terminalstatic/go-xsd-validate"
)

// libxml2's parser is initialized once per process; tests share it.
var (
	initOnce sync.Once
	errInit  error
)

// Validator validates XML documents against an XSD, compiled once for reuse.
type Validator struct {
	handler *xsd.XsdHandler
}

// New compiles an XSD from a file path. Any companion XSDs it <xsd:import>s must
// sit alongside it with schemaLocations pointing to local relative paths, so the
// schema compiles offline (see the vendored XCCDF chain + its PROVENANCE.md).
func New(t *testing.T, xsdPath string) *Validator {
	t.Helper()
	initOnce.Do(func() { errInit = xsd.Init() })
	require.NoError(t, errInit, "initialize libxml2 (go-xsd-validate)")
	abs, err := filepath.Abs(xsdPath)
	require.NoError(t, err, "resolve XSD path %s", xsdPath)
	handler, err := xsd.NewXsdHandlerUrl(abs, xsd.ParsErrDefault)
	require.NoError(t, err, "compile XSD %s", xsdPath)
	return &Validator{handler: handler}
}

// RequireValid asserts doc satisfies the XSD, reporting the violation detail on
// failure so a red run pinpoints exactly what is wrong.
func (v *Validator) RequireValid(t *testing.T, label string, doc []byte) {
	t.Helper()
	if err := v.handler.ValidateMem(doc, xsd.ValidErrDefault); err != nil {
		t.Fatalf("%s: XML does not satisfy the XSD:\n%v", label, err)
	}
}
