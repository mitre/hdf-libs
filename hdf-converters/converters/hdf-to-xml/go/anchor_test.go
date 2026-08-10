package hdftoxml

import (
	"encoding/json"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures"
	"github.com/stretchr/testify/require"
)

// countRequirementObjects counts every OBJECT item of every "requirements"
// array anywhere in the HDF tree, walking the raw JSON (not the converter's
// parser). The generic serializer emits a <requirement> element only for the
// object-array form (the object-array wrapper + singular-child rule); scalar
// id-ref items (e.g. groups[].requirements: ["simple"]) render as unwrapped
// repeated <requirements> keys instead, so they are excluded here. This is the
// independent ground-truth for the emitted <requirement> element count.
func countRequirementObjects(v interface{}) int {
	switch t := v.(type) {
	case map[string]interface{}:
		n := 0
		for k, val := range t {
			if k == "requirements" {
				if arr, ok := val.([]interface{}); ok {
					for _, item := range arr {
						if _, isObj := item.(map[string]interface{}); isObj {
							n++
						}
					}
				}
			}
			n += countRequirementObjects(val)
		}
		return n
	case []interface{}:
		n := 0
		for _, item := range t {
			n += countRequirementObjects(item)
		}
		return n
	default:
		return 0
	}
}

// TestConvertHDFToXML_OutputCountAnchor is the export-side ground-truth anchor:
// the generic serializer emits exactly one <requirement> element per object
// item of a "requirements" array in the HDF input (at any nesting depth), so
// their counts must match a count derived independently from the JSON.
func TestConvertHDFToXML_OutputCountAnchor(t *testing.T) {
	input := fixtures.Results.InspecMultilayered

	var tree interface{}
	require.NoError(t, json.Unmarshal(input, &tree))
	want := countRequirementObjects(tree)
	require.Greater(t, want, 1, "fixture must have multiple requirements for a meaningful anchor")

	out, err := ConvertHDFToXML(input)
	require.NoError(t, err)

	got := shared.CountXMLElements(t, out, "requirement")
	require.Equal(t, want, got, "one <requirement> element per object requirements-array item")
}
