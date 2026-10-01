package hdfutil

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type doctypeCase struct {
	Name                string `json:"name"`
	XML                 string `json:"xml"`
	LeadingCommentBytes int    `json:"leadingCommentBytes"`
	Doctype             bool   `json:"doctype"`
	Entity              bool   `json:"entity"`
	ExternalID          bool   `json:"externalId"`
	Malformed           bool   `json:"malformed"`
	Why                 string `json:"why"`
}

// document builds the case's input, expanding leadingCommentBytes into a prologue
// comment so a case can exceed any fixed scan window without embedding the filler.
func (c doctypeCase) document() string {
	if c.LeadingCommentBytes <= 0 {
		return c.XML
	}
	return "<!--" + strings.Repeat("x", c.LeadingCommentBytes) + "-->" + c.XML
}

func loadDoctypeCases(t *testing.T) []doctypeCase {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "xml-doctype-cases.json"))
	require.NoError(t, err, "the shared case table must be present; it is the Go/TS parity contract")
	var table struct {
		Cases []doctypeCase `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(data, &table))
	require.NotEmpty(t, table.Cases, "an empty table would pass vacuously")
	return table.Cases
}

// The inspector reports the three facts separately; the POLICY over them is the
// consumer's. This is the test that pins all three at once.
func TestInspectXMLPrologue_SharedTable(t *testing.T) {
	for _, c := range loadDoctypeCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			got := InspectXMLPrologue([]byte(c.document()))
			assert.Equal(t, c.Doctype, got.HasDoctype, "HasDoctype: "+c.Why)
			assert.Equal(t, c.Entity, got.HasEntityDecl, "HasEntityDecl: "+c.Why)
			assert.Equal(t, c.ExternalID, got.HasExternalID, "HasExternalID: "+c.Why)
			assert.Equal(t, c.Malformed, got.Malformed, "Malformed: "+c.Why)
		})
	}
}

func TestContainsXMLDoctype_SharedTable(t *testing.T) {
	for _, c := range loadDoctypeCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			assert.Equal(t, c.Doctype, ContainsXMLDoctype([]byte(c.document())), c.Why)
		})
	}
}

func TestContainsXMLEntityDeclarations_SharedTable(t *testing.T) {
	for _, c := range loadDoctypeCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			assert.Equal(t, c.Entity, ContainsXMLEntityDeclarations([]byte(c.document())), c.Why)
		})
	}
}

// The prologue has no length bound, so the scan must not have one either. This is
// the regression the fixed 4 KB window allowed: a DOCTYPE pushed past it was
// accepted outright.
func TestContainsXMLDoctype_NoFixedScanWindow(t *testing.T) {
	for _, pad := range []int{4000, 4096, 4097, 100_000} {
		doc := "<!--" + strings.Repeat("x", pad) + "--><!DOCTYPE note><note/>"
		assert.True(t, ContainsXMLDoctype([]byte(doc)),
			"a DOCTYPE after %d bytes of comment must still be found", pad)
		assert.True(t, ContainsXMLEntityDeclarations([]byte(
			"<!--"+strings.Repeat("x", pad)+"--><!DOCTYPE n [<!ENTITY e \"v\">]><n/>")),
			"an ENTITY after %d bytes of comment must still be found", pad)
	}
}

// A detector that scans unbounded input must still terminate on adversarial input.
func TestContainsXMLDoctype_TerminatesOnMalformedPrologue(t *testing.T) {
	for _, doc := range []string{
		"<!--", "<?", "<!", "<", "<!DOCTYPE", "<?xml", strings.Repeat("<!--a-->", 10_000),
	} {
		assert.NotPanics(t, func() { ContainsXMLDoctype([]byte(doc)) }, "input %q", doc)
		assert.NotPanics(t, func() { ContainsXMLEntityDeclarations([]byte(doc)) }, "input %q", doc)
	}
}
