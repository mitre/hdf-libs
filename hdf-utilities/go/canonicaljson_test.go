package hdfutil

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type canonicalVector struct {
	Name      string `json:"name"`
	Input     any    `json:"input"`
	Canonical string `json:"canonical"`
	Checksum  string `json:"checksum"`
}

func loadCanonicalVectors(t *testing.T) []canonicalVector {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "canonical-json-vectors.json"))
	require.NoError(t, err)
	var doc struct {
		Vectors []canonicalVector `json:"vectors"`
	}
	require.NoError(t, json.Unmarshal(data, &doc))
	require.NotEmpty(t, doc.Vectors)
	return doc.Vectors
}

// The vectors are shared with the TypeScript suite; both languages asserting
// against the same expected bytes is what makes the cross-language checksum
// contract real rather than aspirational.
func TestCanonicalJSON_Vectors(t *testing.T) {
	for _, vector := range loadCanonicalVectors(t) {
		t.Run(vector.Name, func(t *testing.T) {
			canonical, err := CanonicalJSON(vector.Input)
			require.NoError(t, err)
			assert.Equal(t, vector.Canonical, string(canonical))

			sum, err := ChecksumJSON(vector.Input)
			require.NoError(t, err)
			assert.Equal(t, vector.Checksum, sum)
		})
	}
}

func TestCanonicalJSON(t *testing.T) {
	t.Run("a struct and an equivalent map produce identical bytes", func(t *testing.T) {
		type override struct {
			Type   string  `json:"type"`
			Reason string  `json:"reason"`
			Absent *string `json:"absent,omitempty"`
		}
		fromStruct, err := CanonicalJSON(override{Type: "waiver", Reason: "accepted"})
		require.NoError(t, err)
		fromMap, err := CanonicalJSON(map[string]any{"reason": "accepted", "type": "waiver"})
		require.NoError(t, err)
		assert.Equal(t, string(fromMap), string(fromStruct))
	})

	t.Run("an explicit null hashes the same as an omitted key", func(t *testing.T) {
		withNull, err := ChecksumJSON(map[string]any{"a": 1, "b": nil})
		require.NoError(t, err)
		without, err := ChecksumJSON(map[string]any{"a": 1})
		require.NoError(t, err)
		assert.Equal(t, without, withNull)
	})

	t.Run("array order is significant", func(t *testing.T) {
		forward, err := ChecksumJSON([]any{"a", "b"})
		require.NoError(t, err)
		reversed, err := ChecksumJSON([]any{"b", "a"})
		require.NoError(t, err)
		assert.NotEqual(t, forward, reversed)
	})

	t.Run("a value that cannot be encoded returns an error", func(t *testing.T) {
		_, err := CanonicalJSON(make(chan int))
		require.Error(t, err)
		_, err = ChecksumJSON(make(chan int))
		require.Error(t, err)
	})
}
