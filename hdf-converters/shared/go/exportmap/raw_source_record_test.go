package exportmap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var recordLayouts = map[string]RecordLayout{"compact": RecordCompact, "indented": RecordIndented}

// The TypeScript peer reads the same ../../testdata/json-raw-source-record-cases.json.
func TestBuildJSONRawSourceRecord_Vectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "json-raw-source-record-cases.json"))
	require.NoError(t, err)
	var file struct {
		Cases []struct {
			Name    string               `json:"name"`
			Raw     string               `json:"raw"`
			Pointer string               `json:"pointer"`
			Layout  string               `json:"layout"`
			Want    *hdf.RawSourceRecord `json:"want"`
		} `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &file))
	require.NotEmpty(t, file.Cases)
	for _, c := range file.Cases {
		t.Run(c.Name, func(t *testing.T) {
			layout, ok := recordLayouts[c.Layout]
			require.True(t, ok, "unknown layout %q", c.Layout)
			assert.Equal(t, c.Want, BuildJSONRawSourceRecord(json.RawMessage(c.Raw), c.Pointer, layout))
		})
	}
}

func TestBuildJSONRawSourceRecord_UndecodableYieldsNoRecord(t *testing.T) {
	assert.Nil(t, BuildJSONRawSourceRecord(json.RawMessage(`{"a":`), "/matches/0", RecordCompact))
}

// A typed value keeps its own field order: a struct encodes in declaration order.
func TestBuildJSONRawSourceRecordFromValue_KeepsStructOrder(t *testing.T) {
	type vuln struct {
		ID   string  `json:"id"`
		CVSS float64 `json:"cvss"`
		Desc string  `json:"description"`
	}
	got := BuildJSONRawSourceRecordFromValue(vuln{ID: "CVE-2024-0001", CVSS: 9.8, Desc: "a < b & c"}, "/results/0/vulnerabilities/0", RecordIndented)
	require.NotNil(t, got)
	assert.Equal(t, "{\n  \"id\": \"CVE-2024-0001\",\n  \"cvss\": 9.8,\n  \"description\": \"a < b & c\"\n}", got.Content)
	assert.Equal(t, hdf.UTF8, got.Encoding)
	assert.Equal(t, "application/json", got.MediaType)
	require.NotNil(t, got.Pointer)
	assert.Equal(t, "/results/0/vulnerabilities/0", *got.Pointer)
}

func TestBuildJSONRawSourceRecordFromValue_UnencodableYieldsNoRecord(t *testing.T) {
	assert.Nil(t, BuildJSONRawSourceRecordFromValue(make(chan int), "/matches/0", RecordCompact))
}
