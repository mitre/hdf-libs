package hdfutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJsonPathLineMap_BasicObject(t *testing.T) {
	data := []byte(`{
  "name": "test",
  "version": "1.0"
}`)
	lineMap := JSONPathLineMap(data)

	assert.Equal(t, 2, lineMap["name"], "name should be on line 2")
	assert.Equal(t, 3, lineMap["version"], "version should be on line 3")
}

func TestJsonPathLineMap_NestedObject(t *testing.T) {
	data := []byte(`{
  "outer": {
    "inner": "value"
  }
}`)
	lineMap := JSONPathLineMap(data)

	assert.Equal(t, 2, lineMap["outer"], "outer should be on line 2")
	assert.Equal(t, 3, lineMap["outer.inner"], "outer.inner should be on line 3")
}

func TestJsonPathLineMap_Array(t *testing.T) {
	data := []byte(`{
  "items": [
    "first",
    "second"
  ]
}`)
	lineMap := JSONPathLineMap(data)

	assert.Equal(t, 2, lineMap["items"], "items should be on line 2")
	assert.Contains(t, lineMap, "items.0")
	assert.Contains(t, lineMap, "items.1")
}

func TestJsonPathLineMap_ArrayOfObjects(t *testing.T) {
	data := []byte(`{
  "baselines": [
    {
      "name": "RHEL9-STIG",
      "requirements": [
        {
          "id": "SV-001"
        }
      ]
    }
  ]
}`)
	lineMap := JSONPathLineMap(data)

	assert.Equal(t, 2, lineMap["baselines"], "baselines on line 2")
	assert.Contains(t, lineMap, "baselines.0")
	assert.Equal(t, 4, lineMap["baselines.0.name"], "baselines.0.name on line 4")
	assert.Equal(t, 5, lineMap["baselines.0.requirements"], "baselines.0.requirements on line 5")
	assert.Contains(t, lineMap, "baselines.0.requirements.0")
	assert.Equal(t, 7, lineMap["baselines.0.requirements.0.id"], "baselines.0.requirements.0.id on line 7")
}

func TestJsonPathLineMap_InvalidJSON(t *testing.T) {
	lineMap := JSONPathLineMap([]byte("not json"))
	// Should return an empty map, not panic
	assert.NotNil(t, lineMap)
}

func TestLookupLineNumber_ExactMatch(t *testing.T) {
	lineMap := map[string]int{
		"baselines":        2,
		"baselines.0.name": 4,
	}

	assert.Equal(t, 4, LookupLineNumber(lineMap, "baselines.0.name"))
}

func TestLookupLineNumber_PrefixFallback(t *testing.T) {
	lineMap := map[string]int{
		"baselines":   2,
		"baselines.0": 3,
	}

	// "baselines.0.name" doesn't exist, falls back to "baselines.0"
	assert.Equal(t, 3, LookupLineNumber(lineMap, "baselines.0.name"))
}

func TestLookupLineNumber_RootOrEmpty(t *testing.T) {
	lineMap := map[string]int{"baselines": 2}

	assert.Equal(t, 0, LookupLineNumber(lineMap, ""))
	assert.Equal(t, 0, LookupLineNumber(lineMap, "(root)"))
	assert.Equal(t, 0, LookupLineNumber(lineMap, "(parse)"))
}

func TestOffsetToLine(t *testing.T) {
	// "abc\ndef\nghi" → line offsets [0, 4, 8]
	offsets := []int{0, 4, 8}

	assert.Equal(t, 1, offsetToLine(offsets, 0))  // 'a'
	assert.Equal(t, 1, offsetToLine(offsets, 3))  // '\n'
	assert.Equal(t, 2, offsetToLine(offsets, 4))  // 'd'
	assert.Equal(t, 3, offsetToLine(offsets, 8))  // 'g'
	assert.Equal(t, 3, offsetToLine(offsets, 10)) // 'i'
}
