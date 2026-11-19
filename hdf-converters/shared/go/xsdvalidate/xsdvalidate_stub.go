//go:build windows || !cgo

// Package xsdvalidate's cgo-less build is a skipping stub. The real validator
// (xsdvalidate.go) wraps go-xsd-validate → libxml2 via cgo, which Windows CI
// runners have no headers for and a cross-compile has no toolchain for.
// Converter output is platform-independent, so XSD validation on Linux and
// macOS provides sufficient coverage; elsewhere the calling test skips instead
// of failing the build.
package xsdvalidate

import "testing"

// Validator mirrors the real type so importing tests still compile.
type Validator struct{}

// New skips the calling test where libxml2 is out of reach.
func New(t *testing.T, xsdPath string) *Validator {
	t.Helper()
	t.Skipf("XSD validation requires libxml2 via cgo, which this build cannot reach (%s)", xsdPath)
	return nil
}

// RequireValid is unreachable in practice (New skips first) but present so the
// package API matches the real build.
func (v *Validator) RequireValid(t *testing.T, label string, doc []byte) {
	t.Helper()
	t.Skip("XSD validation requires libxml2 via cgo, which this build cannot reach")
}

// Validate is unreachable in practice (New skips first) but present so the
// package API matches the real build.
func (v *Validator) Validate(doc []byte) error {
	return nil
}
