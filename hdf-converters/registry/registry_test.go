package registry

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeFP(id string) ConverterFingerprint {
	return ConverterFingerprint{
		ID:          id,
		Label:       "Test",
		Direction:   DirectionIngest,
		InputFamily: FamilyJSON,
		OutputType:  OutputResults,
		Fingerprint: func(input any) float64 { return 1.0 },
	}
}

func TestRegister(t *testing.T) {
	t.Run("registers a fingerprint", func(t *testing.T) {
		ResetRegistry()
		Register(makeFP("test-a"))
		assert.Len(t, GetFingerprints(), 1)
	})

	t.Run("registers multiple fingerprints", func(t *testing.T) {
		ResetRegistry()
		Register(makeFP("a"))
		Register(makeFP("b"))
		assert.Len(t, GetFingerprints(), 2)
	})

	t.Run("panics on duplicate ID", func(t *testing.T) {
		ResetRegistry()
		Register(makeFP("dup"))
		assert.PanicsWithValue(t, "duplicate fingerprint: dup", func() {
			Register(makeFP("dup"))
		})
	})
}

func TestGetFingerprints(t *testing.T) {
	t.Run("returns empty slice when none registered", func(t *testing.T) {
		ResetRegistry()
		assert.Empty(t, GetFingerprints())
	})

	t.Run("returns all registered", func(t *testing.T) {
		ResetRegistry()
		Register(makeFP("a"))
		Register(makeFP("b"))
		assert.Len(t, GetFingerprints(), 2)
	})
}

func TestGetIngestFingerprints(t *testing.T) {
	ResetRegistry()
	Register(makeFP("in"))
	fp := makeFP("out")
	fp.Direction = DirectionExport
	Register(fp)

	ingest := GetIngestFingerprints()
	assert.Len(t, ingest, 1)
	assert.Equal(t, "in", ingest[0].ID)
}

func TestGetFingerprint(t *testing.T) {
	t.Run("finds by ID", func(t *testing.T) {
		ResetRegistry()
		Register(makeFP("sarif-to-hdf"))
		fp := GetFingerprint("sarif-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, "Test", fp.Label)
	})

	t.Run("returns nil for unknown ID", func(t *testing.T) {
		ResetRegistry()
		assert.Nil(t, GetFingerprint("nonexistent"))
	})
}

func TestOutputType(t *testing.T) {
	ResetRegistry()
	fp1 := makeFP("oscal-sar")
	fp1.OutputType = OutputResults
	fp2 := makeFP("oscal-poam")
	fp2.OutputType = OutputAmendments
	Register(fp1)
	Register(fp2)

	assert.Equal(t, OutputResults, GetFingerprint("oscal-sar").OutputType)
	assert.Equal(t, OutputAmendments, GetFingerprint("oscal-poam").OutputType)
}

func TestResetRegistry(t *testing.T) {
	ResetRegistry()
	Register(makeFP("a"))
	Register(makeFP("b"))
	assert.Len(t, GetFingerprints(), 2)
	ResetRegistry()
	assert.Empty(t, GetFingerprints())
}
