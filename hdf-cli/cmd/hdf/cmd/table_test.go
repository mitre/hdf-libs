package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewTable_Len(t *testing.T) {
	tbl := NewTable(Column{Header: "X"})
	assert.Equal(t, 0, tbl.Len())
	tbl.AddRow("a")
	tbl.AddRow("b")
	assert.Equal(t, 2, tbl.Len())
}

func TestNewTable_AddRow_MissingValues(t *testing.T) {
	tbl := NewTable(
		Column{Header: "A"},
		Column{Header: "B"},
		Column{Header: "C"},
	)
	tbl.AddRow("x")
	assert.Equal(t, 1, tbl.Len())
}

func TestNewTable_AlignConstants(t *testing.T) {
	// Verify re-exported constants are accessible
	_ = NewTable(
		Column{Header: "Left", Align: AlignLeft},
		Column{Header: "Right", Align: AlignRight},
	)
}
