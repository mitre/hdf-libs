//go:build windows

// Package xsdvalidate's Windows build is a skipping stub. The real validator
// (xsdvalidate.go) wraps go-xsd-validate → libxml2 via cgo, and libxml2 headers
// are unavailable on Windows CI runners. Converter output is platform-
// independent, so XSD validation on Linux/macOS provides sufficient coverage;
// on Windows the calling test skips instead of failing the build.
package xsdvalidate

import "testing"

// Validator mirrors the real type so importing tests compile on Windows.
type Validator struct{}

// New skips the calling test on Windows, where libxml2 is unavailable.
func New(t *testing.T, xsdPath string) *Validator {
	t.Helper()
	t.Skipf("XSD validation requires libxml2 via cgo, unavailable on Windows (%s)", xsdPath)
	return nil
}

// RequireValid is unreachable in practice (New skips first) but present so the
// package API matches the real build.
func (v *Validator) RequireValid(t *testing.T, label string, doc []byte) {
	t.Helper()
	t.Skip("XSD validation unavailable on Windows")
}
