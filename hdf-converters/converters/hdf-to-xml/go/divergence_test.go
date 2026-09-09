package hdftoxml

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type divergenceCase struct {
	Name string     `json:"name"`
	Tags string     `json:"tags"`
	Go   [][]string `json:"go"`
	TS   [][]string `json:"ts"`
	Why  string     `json:"why"`
}

// These divergences are documented and deliberate, not latent. Pinning them
// means a change to either language is a test failure rather than a silent
// widening, and it keeps the package doc comment's claim honest.
func TestConvertHDFToXMLDocumentedDivergences(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "shared", "xml-divergence-cases.json"))
	require.NoError(t, err)

	var table struct {
		Cases []divergenceCase `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &table))
	require.NotEmpty(t, table.Cases, "an empty table would pass vacuously")

	for _, c := range table.Cases {
		t.Run(c.Name, func(t *testing.T) {
			require.NotEqual(t, c.TS, c.Go,
				"a row that no longer diverges should be deleted, not kept as a passing no-op")

			input := []byte(`{"baselines":[{"name":"b","requirements":[{"id":"r","impact":0,` +
				`"tags":` + c.Tags + `,` +
				`"descriptions":[{"label":"default","data":"d"}],` +
				`"results":[{"status":"passed","codeDesc":"c","startTime":"2020-01-01T00:00:00Z"}]}]}]}`)

			out, err := ConvertHDFToXML(input)
			require.NoError(t, err)

			want := make([][2]string, 0, len(c.Go))
			for _, pair := range c.Go {
				require.Len(t, pair, 2, "each row is an [element, text] pair")
				want = append(want, [2]string{pair[0], pair[1]})
			}
			assert.Equal(t, want, tagTextSequence(t, out), c.Why)
		})
	}
}

// tagTextSequence returns the (element name, character data) of each child of
// the first <tags> element, in document order. Distinct from tagSequence, which
// reports the name attribute rather than the text.
func tagTextSequence(t *testing.T, doc []byte) [][2]string {
	t.Helper()
	dec := xml.NewDecoder(bytes.NewReader(doc))
	var seq [][2]string
	inTags := false
	depth := 0
	var current string
	var text strings.Builder
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
					current = el.Name.Local
					text.Reset()
				}
			}
		case xml.CharData:
			if inTags && depth == 1 {
				text.Write(el)
			}
		case xml.EndElement:
			if inTags {
				if depth == 0 {
					return seq
				}
				if depth == 1 {
					seq = append(seq, [2]string{current, text.String()})
				}
				depth--
			}
		}
	}
	return seq
}
