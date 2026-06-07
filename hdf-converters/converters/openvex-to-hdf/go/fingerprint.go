package openvex

import (
	"strings"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
)

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "openvex-to-hdf",
		Label:       "OpenVEX",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputAmendments,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			ctx, hasCtx := obj["@context"].(string)
			if !hasCtx || !strings.Contains(ctx, "openvex.dev") {
				return 0
			}
			if _, hasStmts := obj["statements"]; !hasStmts {
				return 0
			}
			return 1.0
		},
	})
}
