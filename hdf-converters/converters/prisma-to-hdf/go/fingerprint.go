package prisma

import (
	"strings"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
)

// prismaColumns are the CSV headers that uniquely identify Prisma Cloud output.
var prismaColumns = []string{"Hostname", "Compliance ID", "Severity", "Type", "Description"}

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "prisma-to-hdf",
		Label:       "Prisma Cloud CSV",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyText,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			s, ok := input.(string)
			if !ok {
				return 0
			}
			// Get the first line (header row) from the CSV
			headerLine := s
			if idx := strings.Index(s, "\n"); idx != -1 {
				headerLine = s[:idx]
			}
			headerLine = strings.TrimSpace(headerLine)
			if headerLine == "" {
				return 0
			}

			// Check how many required Prisma columns are present
			matchCount := 0
			for _, col := range prismaColumns {
				if strings.Contains(headerLine, col) {
					matchCount++
				}
			}
			if matchCount == len(prismaColumns) {
				return 0.85
			}
			// Partial match — at least 3 of 5 columns suggests Prisma-like CSV
			if matchCount >= 3 {
				return 0.4
			}
			return 0
		},
	})
}
