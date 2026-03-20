package prisma

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrismaFingerprint(t *testing.T) {
	t.Run("is registered with correct metadata", func(t *testing.T) {
		fp := registry.GetFingerprint("prisma-to-hdf")
		require.NotNil(t, fp, "prisma-to-hdf should be registered via init()")
		assert.Equal(t, "Prisma Cloud CSV", fp.Label)
		assert.Equal(t, registry.DirectionIngest, fp.Direction)
		assert.Equal(t, registry.FamilyText, fp.InputFamily)
		assert.Equal(t, registry.OutputResults, fp.OutputType)
	})

	t.Run("detects full Prisma CSV header at confidence 0.85", func(t *testing.T) {
		input := "Hostname,Compliance ID,Severity,Type,Description\nhost1,CIS-1.1,High,Container,Some finding\n"
		fp := registry.GetFingerprint("prisma-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.85, fp.Fingerprint(input))
	})

	t.Run("detects partial Prisma CSV header (3 of 5) at confidence 0.4", func(t *testing.T) {
		input := "Hostname,Severity,Type,OtherCol\nhost1,High,Container,extra\n"
		fp := registry.GetFingerprint("prisma-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.4, fp.Fingerprint(input))
	})

	t.Run("does not match CSV with fewer than 3 matching columns", func(t *testing.T) {
		input := "Hostname,Severity,OtherCol,AnotherCol\nhost1,High,val1,val2\n"
		fp := registry.GetFingerprint("prisma-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match unrelated text", func(t *testing.T) {
		input := "This is just some plain text content without any CSV structure."
		fp := registry.GetFingerprint("prisma-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match empty string", func(t *testing.T) {
		fp := registry.GetFingerprint("prisma-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(""))
	})

	t.Run("does not match nil input", func(t *testing.T) {
		fp := registry.GetFingerprint("prisma-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(nil))
	})

	t.Run("does not match non-string input", func(t *testing.T) {
		fp := registry.GetFingerprint("prisma-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(map[string]any{"Hostname": "host1"}))
	})
}
