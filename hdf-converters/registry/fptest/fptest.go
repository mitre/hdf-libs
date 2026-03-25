// Package fptest provides a table-driven test runner for converter fingerprints.
// Each converter defines a FingerprintSpec and calls RunFingerprintTests to get
// standard metadata, positive detection, and negative rejection tests.
package fptest

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// DetectionCase defines an input and expected confidence for a positive or
// negative fingerprint detection test.
type DetectionCase struct {
	Name       string
	Input      any     // map[string]any for JSON, string for XML/text
	Confidence float64 // expected confidence (0.0 for negative cases)
}

// FingerprintSpec defines the expected metadata and test cases for a fingerprint.
type FingerprintSpec struct {
	// ID is the fingerprint ID, e.g. "gosec-to-hdf".
	ID string
	// Label is the human-readable label, e.g. "GoSec".
	Label string
	// Direction is the expected direction (usually DirectionIngest).
	Direction registry.Direction
	// InputFamily is the expected input family (FamilyJSON, FamilyXML, FamilyText).
	InputFamily registry.InputFamily
	// OutputType is the expected output type.
	OutputType registry.OutputType
	// Positive contains inputs that should match with the given confidence.
	Positive []DetectionCase
	// Negative contains inputs that should not match (confidence must be 0.0).
	Negative []DetectionCase
}

// RunFingerprintTests runs a standard suite of fingerprint tests from a spec.
// It tests metadata registration, positive detection cases, negative rejection
// cases, and standard edge cases (nil input, string input for JSON fingerprints).
func RunFingerprintTests(t *testing.T, spec FingerprintSpec) {
	t.Helper()

	t.Run("is registered with correct metadata", func(t *testing.T) {
		fp := registry.GetFingerprint(spec.ID)
		require.NotNil(t, fp, "%s should be registered via init()", spec.ID)
		assert.Equal(t, spec.Label, fp.Label)
		assert.Equal(t, spec.Direction, fp.Direction)
		assert.Equal(t, spec.InputFamily, fp.InputFamily)
		assert.Equal(t, spec.OutputType, fp.OutputType)
	})

	for _, tc := range spec.Positive {
		t.Run(tc.Name, func(t *testing.T) {
			fp := registry.GetFingerprint(spec.ID)
			require.NotNil(t, fp)
			assert.Equal(t, tc.Confidence, fp.Fingerprint(tc.Input))
		})
	}

	for _, tc := range spec.Negative {
		t.Run(tc.Name, func(t *testing.T) {
			fp := registry.GetFingerprint(spec.ID)
			require.NotNil(t, fp)
			assert.Equal(t, 0.0, fp.Fingerprint(tc.Input))
		})
	}

	t.Run("does not match nil input", func(t *testing.T) {
		fp := registry.GetFingerprint(spec.ID)
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(nil))
	})

	t.Run("does not match string input", func(t *testing.T) {
		fp := registry.GetFingerprint(spec.ID)
		require.NotNil(t, fp)
		if spec.InputFamily == registry.FamilyJSON {
			assert.Equal(t, 0.0, fp.Fingerprint("not a map"))
		}
	})
}
