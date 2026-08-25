package hdftoxml

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type elementNameCase struct {
	Key       string `json:"key"`
	Name      string `json:"name"`
	Rewritten bool   `json:"rewritten"`
	Why       string `json:"why"`
}

func loadElementNameCases(t *testing.T) []elementNameCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "shared", "xml-element-name-cases.json"))
	require.NoError(t, err)

	var table struct {
		Cases []elementNameCase `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &table))
	require.NotEmpty(t, table.Cases, "an empty table would pass vacuously")
	return table.Cases
}

// The encoder is implemented twice, so the expectations live in one shared file
// both languages read rather than in two hand-kept copies.
func TestXMLElementNameMatchesSharedTable(t *testing.T) {
	for _, c := range loadElementNameCases(t) {
		t.Run(c.Key, func(t *testing.T) {
			name, rewritten := xmlElementName(c.Key)
			assert.Equal(t, c.Name, name, c.Why)
			assert.Equal(t, c.Rewritten, rewritten, c.Why)
		})
	}
}

// Encoding is not injective, so the question is not whether collisions can exist
// but whether they exist for the keys this repo actually produces. Scans every
// tag key in every converter fixture.
func TestXMLElementNameNoCollisionsAcrossRealFixtureKeys(t *testing.T) {
	keys := collectFixtureTagKeys(t)
	require.Greater(t, len(keys), 100, "the fixture scan found too few keys to be meaningful")

	seen := make(map[string]string, len(keys))
	for _, key := range keys {
		name, _ := xmlElementName(key)
		if prior, dup := seen[name]; dup {
			t.Errorf("tag keys %q and %q both encode to %q", prior, key, name)
			continue
		}
		seen[name] = key
	}
}

// Every encoded name must be one an XML parser accepts, which is the property
// the encoder exists to guarantee.
func TestXMLElementNameAlwaysParses(t *testing.T) {
	keys := append(collectFixtureTagKeys(t), "800-53", "a<b", "my tag", "", "café")
	for _, key := range keys {
		name, _ := xmlElementName(key)
		doc := []byte("<" + name + ">v</" + name + ">")
		require.NoError(t, xmlWellFormed(doc), "key %q encoded to unparseable name %q", key, name)
	}
}

// xmlWellFormed reports whether a document parses, which is a stronger property
// than schema validity: an unencoded key does not merely produce a document some
// validator rejects, it produces one no parser can read.
func xmlWellFormed(doc []byte) error {
	dec := xml.NewDecoder(bytes.NewReader(doc))
	for {
		_, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// collectFixtureTagKeys gathers every HDF tag key across every converter's
// fixtures, so the collision and parse checks run against the keys real
// converters emit rather than shapes chosen to pass.
func collectFixtureTagKeys(t *testing.T) []string {
	t.Helper()

	seen := map[string]bool{}
	require.NoError(t, shared.ForEachFixtureTags(func(tags map[string]interface{}) {
		for key := range tags {
			seen[key] = true
		}
	}))

	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
