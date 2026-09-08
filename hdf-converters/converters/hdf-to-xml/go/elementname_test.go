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
	"strconv"
	"strings"
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

type elementNameCollision struct {
	Name    string   `json:"name"`
	Keys    []string `json:"keys"`
	Between string   `json:"between"`
	Why     string   `json:"why"`
}

func loadElementNameTable(t *testing.T) (cases []elementNameCase, collisions []elementNameCollision) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "shared", "xml-element-name-cases.json"))
	require.NoError(t, err)

	var table struct {
		Cases      []elementNameCase      `json:"cases"`
		Collisions []elementNameCollision `json:"collisions"`
	}
	require.NoError(t, json.Unmarshal(raw, &table))
	require.NotEmpty(t, table.Cases, "an empty table would pass vacuously")
	require.NotEmpty(t, table.Collisions, "an empty table would pass vacuously")
	return table.Cases, table.Collisions
}

func loadElementNameCases(t *testing.T) []elementNameCase {
	t.Helper()
	cases, _ := loadElementNameTable(t)
	return cases
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

// Two keys encoding to one element name must yield two elements, each at its own
// source position — asserted as a sequence, which is what distinguishes real
// order preservation from merely emitting both.
func TestConvertHDFToXMLEmitsCollidingKeysInSourceOrder(t *testing.T) {
	_, collisions := loadElementNameTable(t)
	for _, c := range collisions {
		t.Run(c.Name+"/"+c.Between, func(t *testing.T) {
			require.Greater(t, len(c.Keys), 1, "a collision needs at least two keys")

			keys := c.Keys
			if c.Between != "" {
				keys = append([]string{c.Keys[0], c.Between}, c.Keys[1:]...)
			}
			var tags []string
			want := make([][2]string, 0, len(keys))
			for _, k := range c.Keys {
				name, _ := xmlElementName(k)
				require.Equal(t, c.Name, name,
					"the table says %q collides onto %q; if it no longer does, this row tests nothing", k, c.Name)
			}
			for i, k := range keys {
				tags = append(tags, strconv.Quote(k)+":"+strconv.Quote("v"+strconv.Itoa(i)))
				name, rewritten := xmlElementName(k)
				attr := ""
				if rewritten {
					attr = k
				}
				want = append(want, [2]string{name, attr})
			}
			input := []byte(`{"baselines":[{"name":"b","requirements":[{"id":"r","impact":0,` +
				`"tags":{` + strings.Join(tags, ",") + `},` +
				`"descriptions":[{"label":"default","data":"d"}],` +
				`"results":[{"status":"passed","codeDesc":"c","startTime":"2020-01-01T00:00:00Z"}]}]}]}`)

			out, err := ConvertHDFToXML(input)
			require.NoError(t, err)
			require.NoError(t, xmlWellFormed(out), c.Why)

			assert.Equal(t, want, tagSequence(t, out),
				"Go emits every key at its source position: %s", c.Why)
		})
	}
}

// tagSequence returns the (element name, name attribute) of each child of the
// first <tags> element, in document order.
func tagSequence(t *testing.T, doc []byte) [][2]string {
	t.Helper()
	dec := xml.NewDecoder(bytes.NewReader(doc))
	var seq [][2]string
	inTags := false
	depth := 0
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		switch el := tok.(type) {
		case xml.StartElement:
			if !inTags && el.Name.Local == "tags" {
				inTags = true
				continue
			}
			if inTags {
				depth++
				if depth == 1 {
					attr := ""
					for _, a := range el.Attr {
						if a.Name.Local == "name" {
							attr = a.Value
						}
					}
					seq = append(seq, [2]string{el.Name.Local, attr})
				}
			}
		case xml.EndElement:
			if inTags {
				if depth == 0 {
					return seq
				}
				depth--
			}
		}
	}
	return seq
}
