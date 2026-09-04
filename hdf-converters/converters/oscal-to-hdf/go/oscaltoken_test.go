package oscal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

// tokenRe is OSCAL's TokenDatatype pattern, transcribed from the vendored
// schemas so this test fails if the encoding ever stops satisfying it.
var tokenRe = regexp.MustCompile(`^(\p{L}|_)(\p{L}|\p{N}|[.\-_])*$`)

// TestOSCALToken_MatchesSharedTable reads the same table the TypeScript peer
// reads, so the two implementations are asserted against ONE definition. Written
// after the first cut used Go's unicode.IsDigit against TypeScript's \p{N}, which
// disagreed on superscripts, fractions and Roman numerals — a divergence two
// hand-written test lists would never have surfaced.
func TestOSCALToken_MatchesSharedTable(t *testing.T) {
	type tokenCase struct {
		Name string `json:"name"`
		In   string `json:"in"`
		Want string `json:"want"`
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "shared", "oscal-token-cases.json"))
	require.NoError(t, err)
	var doc struct {
		Cases []tokenCase `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc))
	require.NotEmpty(t, doc.Cases, "shared table is empty — the run would pass vacuously")

	for _, tc := range doc.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			got := OSCALToken(tc.In)
			require.Equal(t, tc.Want, got)
			if got != "" {
				require.True(t, tokenRe.MatchString(got), "%q is not a valid OSCAL token", got)
			}
		})
	}
}

// TestOSCALToken_NoCollisionsAcrossRealFixtureIDs is the evidence behind the
// claim that this encoding preserves distinctness in practice. It is not
// injective in principle — "a/b" and "a:b" both yield "a_b" — so rather than
// assert a property that is false, this walks every requirement id in the repo's
// real converter fixtures and proves no two of them collide. If a future fixture
// introduces a collision this fails loudly, and the source id is still
// recoverable from the finding's hdf-requirement-id prop.
func TestOSCALToken_NoCollisionsAcrossRealFixtureIDs(t *testing.T) {
	root := filepath.Join("..", "..", "..", "converters")
	entries, err := filepath.Glob(filepath.Join(root, "*", "fixtures", "expected", "*.hdf.json"))
	require.NoError(t, err)
	require.NotEmpty(t, entries, "no HDF fixtures found — the scan would prove nothing")

	seen := map[string]string{}
	ids := 0
	for _, f := range entries {
		// These are repo fixtures found by glob; a read or parse failure is a
		// real problem that must fail the test, not silently shrink the scan.
		// Fixtures that legitimately carry no baselines/requirements (e.g.
		// amendments docs) are skipped by the loops below producing no ids.
		raw, err := os.ReadFile(f)
		require.NoError(t, err, "read fixture %s", f)
		var doc struct {
			Baselines []struct {
				Requirements []struct {
					ID string `json:"id"`
				} `json:"requirements"`
			} `json:"baselines"`
		}
		require.NoError(t, json.Unmarshal(raw, &doc), "parse fixture %s", f)
		for _, b := range doc.Baselines {
			for _, r := range b.Requirements {
				if r.ID == "" {
					continue
				}
				ids++
				// The shipped composition, not OSCALToken alone: the converter
				// always encodes what NistTagToControlID returns, and testing the
				// bare encoder would pin a function no caller uses.
				tok := OSCALToken(NistTagToControlID(r.ID))
				require.True(t, tokenRe.MatchString(tok), "%q encoded to %q, not a token", r.ID, tok)
				if prev, ok := seen[tok]; ok && prev != r.ID {
					t.Fatalf("collision: %q and %q both encode to %q", prev, r.ID, tok)
				}
				seen[tok] = r.ID
			}
		}
	}
	require.Greater(t, ids, 1000, "scanned too few ids to be meaningful")
	t.Logf("scanned %d requirement ids, %d distinct encodings, no collisions", ids, len(seen))
}
