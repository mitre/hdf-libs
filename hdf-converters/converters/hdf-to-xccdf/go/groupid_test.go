package hdftoxccdf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type groupIDCase struct {
	GID         string `json:"gid"`
	ID          string `json:"id"`
	Passthrough bool   `json:"passthrough"`
	Why         string `json:"why"`
}

func loadGroupIDCases(t *testing.T) []groupIDCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "shared", "xccdf-group-id-cases.json"))
	require.NoError(t, err)

	var table struct {
		Cases []groupIDCase `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &table))
	require.NotEmpty(t, table.Cases, "an empty table would pass vacuously")
	return table.Cases
}

// The encoder is implemented twice, so the expectations live in one shared file
// both languages read rather than in two hand-kept copies.
func TestXCCDFGroupIDMatchesSharedTable(t *testing.T) {
	for _, c := range loadGroupIDCases(t) {
		t.Run(c.GID, func(t *testing.T) {
			assert.Equal(t, c.ID, xccdfGroupID(c.GID), c.Why)
			assert.Equal(t, c.Passthrough, isXCCDFGroupID(c.GID), c.Why)
		})
	}
}

// Whatever the input, the result must satisfy groupIdType — the property the
// encoder exists to guarantee, asserted here against the XSD's own pattern
// rather than against the encoder's idea of it.
func TestXCCDFGroupIDAlwaysSatisfiesGroupIDType(t *testing.T) {
	pattern := regexp.MustCompile(`^xccdf_[^_]+_group_.+$`)
	ncname := regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9._-]*$`)

	gids := []string{"", " ", "_", "café", "日本", "V-1", "a:b", "xccdf__group_x"}
	for _, c := range loadGroupIDCases(t) {
		gids = append(gids, c.GID)
	}
	for _, gid := range gids {
		id := xccdfGroupID(gid)
		assert.Regexp(t, pattern, id, "gid %q encoded to %q, which fails the XSD pattern", gid, id)
		assert.Regexp(t, ncname, id, "gid %q encoded to %q, which is not an NCName", gid, id)
	}
}

// Encoding is not injective, so the question is not whether collisions can exist
// but whether they exist for the gids this repo actually produces. Two gids
// encoding to one id would merge two distinct STIG groups into one.
func TestXCCDFGroupIDNoCollisionsAcrossRealFixtureGIDs(t *testing.T) {
	seen := map[string]bool{}
	var gids []string
	require.NoError(t, shared.ForEachFixtureTags(func(tags map[string]interface{}) {
		if gid, ok := tags["gid"].(string); ok && !seen[gid] {
			seen[gid] = true
			gids = append(gids, gid)
		}
	}))
	require.Greater(t, len(gids), 1000, "the fixture scan found too few gids to be meaningful")

	byID := make(map[string]string, len(gids))
	for _, gid := range gids {
		id := xccdfGroupID(gid)
		if prior, dup := byID[id]; dup {
			t.Errorf("gids %q and %q both encode to %q", prior, gid, id)
			continue
		}
		byID[id] = gid
	}
}
