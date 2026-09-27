package hdftoxccdf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"

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

type realShape struct {
	GID    string `json:"gid"`
	Shape  string `json:"shape"`
	Source string `json:"source"`
}

func loadRealShapes(t *testing.T) []realShape {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "shared", "xccdf-group-id-cases.json"))
	require.NoError(t, err)

	var table struct {
		RealShapes []realShape `json:"realShapes"`
	}
	require.NoError(t, json.Unmarshal(raw, &table))
	require.NotEmpty(t, table.RealShapes, "an empty table would pass vacuously")
	return table.RealShapes
}

// Encoding is not injective: sanitization folds every character outside
// [A-Za-z0-9._-] to "_", so two gids that differ only in such characters
// collide, and the shared table above pins that behaviour on hostile input.
// What real content needs is narrower and provable rather than sampled: for
// every gid shape real tools emit, sanitization must be the identity, because
// then encoding is prefix-plus-gid (or passthrough) and cannot collide at all.
// One representative per shape is enough — the property is about the
// characters a shape uses, not about how many gids share it.
func TestXCCDFGroupIDLeavesRealShapesUntouched(t *testing.T) {
	for _, r := range loadRealShapes(t) {
		t.Run(r.Shape, func(t *testing.T) {
			got := xccdfGroupID(r.GID)
			if isXCCDFGroupID(r.GID) {
				assert.Equal(t, r.GID, got, "a conforming %s id must pass through unchanged", r.Source)
				return
			}
			assert.Equal(t, "xccdf_hdf_group_"+r.GID, got,
				"a %s id (%s) was rewritten by the sanitizer — that shape can now collide", r.Source, r.Shape)
		})
	}
}
