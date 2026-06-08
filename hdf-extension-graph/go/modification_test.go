package hdfextension

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTrackedFields(t *testing.T) {
	t.Run("should list the five fields the TypeScript package tracks, in order", func(t *testing.T) {
		// Field order is part of the spec — Modifications appends in this
		// order and the cross-language equivalence dump sorts by Field, so
		// downstream tests assert ordering. It cannot change silently here.
		assert.Equal(t, []string{"impact", "title", "severity", "effectiveImpact", "disposition"}, TrackedFields)
	})
}

func TestModification_JSONShape(t *testing.T) {
	t.Run("should serialize with camelCase keys matching the TypeScript Modification interface", func(t *testing.T) {
		m := Modification{
			Field:         "impact",
			OriginalValue: 0.5,
			NewValue:      0.7,
			InBaseline:    "child",
		}
		out, err := json.Marshal(m)
		assert.NoError(t, err)
		assert.JSONEq(t, `{"field":"impact","originalValue":0.5,"newValue":0.7,"inBaseline":"child"}`, string(out))
	})

	t.Run("should preserve nil values as JSON null (no omitempty on value fields)", func(t *testing.T) {
		m := Modification{
			Field:         "title",
			OriginalValue: nil,
			NewValue:      "new title",
			InBaseline:    "child",
		}
		out, err := json.Marshal(m)
		assert.NoError(t, err)
		assert.JSONEq(t, `{"field":"title","originalValue":null,"newValue":"new title","inBaseline":"child"}`, string(out))
	})
}
