// Self-contained validation gate for the hdf-fixtures corpus. Every fixture
// in results/ must validate as HDF Results, baseline/* as HDF Baseline,
// amendments/* as HDF Amendments.
// inspec/* is exempt — those files are InSpec runner output (NOT
// HDF), kept here as input for the legacyhdf-to-hdf converter and as the
// negative-case feed for the cross-language parser parity test.
package fixtures

import (
	"regexp"
	"strings"
	"testing"

	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
)

// Inlined to avoid a dependency cycle: hdf-parsers' tests consume
// hdf-fixtures, so hdf-fixtures can't import hdf-parsers back. Mirrors
// hdf-parsers/go/parsers.go NormalizeTimestamps — kept narrow because it
// only feeds this gate test, not consumers.
var noTzTimestamp = regexp.MustCompile(`"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)"`)

func normalizeTimestamps(input []byte) []byte {
	return noTzTimestamp.ReplaceAll(input, []byte(`"${1}Z"`))
}

func TestEveryFixtureValidatesAgainstItsSchema(t *testing.T) {
	type group struct {
		name     string
		schema   validators.SchemaType
		fixtures map[string][]byte
	}
	groups := []group{
		{
			name:   "results",
			schema: validators.TypeResults,
			fixtures: map[string][]byte{
				"inspec-multilayered.json": Results.InspecMultilayered,
				"minimal.json":             Results.Minimal,
			},
		},
		{
			name:   "baseline",
			schema: validators.TypeBaseline,
			fixtures: map[string][]byte{
				"win2022-stig.json": Baseline.Win2022Stig,
			},
		},
		{
			name:   "amendments",
			schema: validators.TypeAmendments,
			fixtures: map[string][]byte{
				"uc-01-fixed-amendments.json": Amendments.UC01Fixed,
				"multi-cve-amendments.json":   Amendments.MultiCVE,
			},
		},
	}

	for _, g := range groups {
		for name, data := range g.fixtures {
			t.Run(g.name+"/"+name, func(t *testing.T) {
				// Real producers (notably InSpec) emit bare timestamps that
				// the schema's `date-time` format rejects. Consumer-side code
				// (hdf-parsers, hdf-cli's validate command) normalizes before
				// validating; mirror that here so the gate tests the schema
				// shape rather than the producer's RFC3339 conformance.
				result := validators.Validate(normalizeTimestamps(data), g.schema)
				if !result.Valid {
					var msgs []string
					for _, e := range result.Errors {
						msgs = append(msgs, e.Field+": "+e.Description)
					}
					t.Fatalf("fixture %s/%s failed %s schema validation:\n  %s",
						g.name, name, g.schema, strings.Join(msgs, "\n  "))
				}
			})
		}
	}
}
