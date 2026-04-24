package prisma

import (
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	"github.com/mitre/hdf-libs/hdf-converters/v3/registry/fptest"
)

func TestPrismaFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "prisma-to-hdf",
		Label:       "Prisma Cloud CSV",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyText,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{Name: "detects full Prisma CSV header at confidence 0.85", Input: "Hostname,Compliance ID,Severity,Type,Description\nhost1,CIS-1.1,High,Container,Some finding\n", Confidence: 0.85},
			{Name: "detects partial Prisma CSV header (3 of 5) at confidence 0.4", Input: "Hostname,Severity,Type,OtherCol\nhost1,High,Container,extra\n", Confidence: 0.4},
		},
		Negative: []fptest.DetectionCase{
			{Name: "does not match CSV with fewer than 3 matching columns", Input: "Hostname,Severity,OtherCol,AnotherCol\nhost1,High,val1,val2\n"},
			{Name: "does not match unrelated text", Input: "This is just some plain text content without any CSV structure."},
			{Name: "does not match empty string", Input: ""},
			{Name: "does not match non-string input", Input: map[string]any{"Hostname": "host1"}},
		},
	})
}
