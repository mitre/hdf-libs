package hdftoxml

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

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

type elementNameShape struct {
	Key       string `json:"key"`
	Name      string `json:"name"`
	Rewritten bool   `json:"rewritten"`
	Source    string `json:"source"`
}

func loadElementNameShapes(t *testing.T) []elementNameShape {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "shared", "xml-element-name-cases.json"))
	require.NoError(t, err)

	var table struct {
		RealShapes []elementNameShape `json:"realShapes"`
	}
	require.NoError(t, json.Unmarshal(raw, &table))
	require.NotEmpty(t, table.RealShapes, "an empty table would pass vacuously")
	return table.RealShapes
}

// Encoding is not injective — every character outside [A-Za-z0-9._-] folds to
// "_" — and a collision is tolerable because a rewritten key is emitted with a
// name attribute carrying the original. What real content needs is that each
// key SHAPE real converters emit encodes as recorded: one representative per
// shape, from the shared table, not a scan of every fixture in the repo, which
// made every converter's fixtures load-bearing for this one.
func TestXMLElementNameRealShapesEncodeAsRecorded(t *testing.T) {
	for _, r := range loadElementNameShapes(t) {
		t.Run(r.Key, func(t *testing.T) {
			name, rewritten := xmlElementName(r.Key)
			assert.Equal(t, r.Name, name, "a %s key encoded differently from the table", r.Source)
			assert.Equal(t, r.Rewritten, rewritten, r.Source)
		})
	}
}

// Every encoded name must be one an XML parser accepts, which is the property
// the encoder exists to guarantee — over every key the shared table knows,
// real and hostile alike, plus a few that stress the start-character rule.
func TestXMLElementNameAlwaysParses(t *testing.T) {
	var keys []string
	for _, c := range loadElementNameCases(t) {
		keys = append(keys, c.Key)
	}
	for _, r := range loadElementNameShapes(t) {
		keys = append(keys, r.Key)
	}
	keys = append(keys, "800-53", "a<b", "my tag", "", "café", "1", "-", ".", "$ref", "a/b/c")
	for _, key := range keys {
		name, _ := xmlElementName(key)
		doc := []byte("<" + name + ">v</" + name + ">")
		assert.NoError(t, xmlWellFormed(doc), "key %q encoded to unparseable name %q", key, name)
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
