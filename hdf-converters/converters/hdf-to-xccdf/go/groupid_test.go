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

type groupIDCorpus struct {
	Count  int      `json:"count"`
	Shapes []string `json:"shapes"`
	GIDs   []string `json:"gids"`
}

// The collision corpus is a committed snapshot of every distinct real gid the
// repo's fixtures carried when it was extracted, with the fixtures it came from
// recorded in the file. It is deliberately NOT rebuilt from the fixture tree at
// test time: that coupled every converter's fixture size to this one test, so a
// clean trim of an unrelated fixture failed here with a message blaming the scan.
func loadGroupIDCorpus(t *testing.T) groupIDCorpus {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "shared", "xccdf-group-id-corpus.json"))
	require.NoError(t, err)

	var corpus groupIDCorpus
	require.NoError(t, json.Unmarshal(raw, &corpus))
	require.Len(t, corpus.GIDs, corpus.Count, "the corpus does not hold the number of gids it records — truncated or hand-edited")
	require.Positive(t, corpus.Count, "an empty corpus would pass vacuously")
	uniq := make(map[string]bool, len(corpus.GIDs))
	for _, gid := range corpus.GIDs {
		uniq[gid] = true
	}
	require.Len(t, uniq, corpus.Count, "the corpus repeats a gid — a duplicate can never collide with itself, so it pads the count without testing anything")
	return corpus
}

// Encoding is not injective, so the question is not whether collisions can exist
// but whether they exist for the gids real STIG content actually carries. Two
// gids encoding to one id would merge two distinct groups into one.
//
// Sample size is the whole corpus, not a threshold: the file records how many
// distinct gids it holds and the test requires exactly that many, so a truncated
// file fails rather than passing over fewer ids. The shape check below is a
// guard against the corpus silently losing a CLASS of real gid (the digit-free
// SSG group names, say), not a claim about sanitization coverage: real content
// is almost entirely NCName-safe, so this corpus mostly exercises the identity
// path, and the hostile inputs that do exercise the sanitizer live in the shared
// cases table (TestXCCDFGroupIDMatchesSharedTable).
func TestXCCDFGroupIDNoCollisionsAcrossRealCorpus(t *testing.T) {
	corpus := loadGroupIDCorpus(t)

	digits := regexp.MustCompile(`[0-9]+`)
	shapes := map[string]bool{}
	for _, gid := range corpus.GIDs {
		shapes[digits.ReplaceAllString(gid, "N")] = true
	}
	for _, want := range corpus.Shapes {
		assert.True(t, shapes[want], "the corpus records shape %q but no gid in it has that shape", want)
	}
	assert.Len(t, shapes, len(corpus.Shapes), "the corpus holds gid shapes its shapes list does not record: %v", shapes)

	byID := make(map[string]string, len(corpus.GIDs))
	for _, gid := range corpus.GIDs {
		id := xccdfGroupID(gid)
		if prior, dup := byID[id]; dup {
			t.Errorf("gids %q and %q both encode to %q", prior, gid, id)
			continue
		}
		byID[id] = gid
	}
}
