package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTable_ComputeWidths(t *testing.T) {
	tbl := NewTable(
		Column{Header: "ID"},
		Column{Header: "Status"},
	)
	tbl.AddRow("AC-1", "passed")
	tbl.AddRow("SV-230001", "failed")

	widths := tbl.computeWidths()
	assert.Equal(t, 9, widths[0], "should fit 'SV-230001'")
	assert.Equal(t, 6, widths[1], "should fit 'Status' header")
}

func TestTable_ComputeWidths_HeaderWider(t *testing.T) {
	tbl := NewTable(
		Column{Header: "Requirement ID"},
		Column{Header: "S"},
	)
	tbl.AddRow("AC-1", "p")

	widths := tbl.computeWidths()
	assert.Equal(t, 14, widths[0], "header should win when wider")
	assert.Equal(t, 1, widths[1], "data should win when wider")
}

func TestTable_AddRow_MissingValues(t *testing.T) {
	tbl := NewTable(
		Column{Header: "A"},
		Column{Header: "B"},
		Column{Header: "C"},
	)
	tbl.AddRow("x")
	assert.Equal(t, 1, tbl.Len())
	assert.Equal(t, "x", tbl.rows[0][0])
	assert.Equal(t, "", tbl.rows[0][1])
	assert.Equal(t, "", tbl.rows[0][2])
}

func TestTable_Len(t *testing.T) {
	tbl := NewTable(Column{Header: "X"})
	assert.Equal(t, 0, tbl.Len())
	tbl.AddRow("a")
	tbl.AddRow("b")
	assert.Equal(t, 2, tbl.Len())
}

func TestPadRight(t *testing.T) {
	assert.Equal(t, "ab   ", padRight("ab", 5))
	assert.Equal(t, "abcde", padRight("abcde", 5))
	assert.Equal(t, "abcdef", padRight("abcdef", 5))
}

func TestPadLeft(t *testing.T) {
	assert.Equal(t, "   ab", padLeft("ab", 5))
	assert.Equal(t, "abcde", padLeft("abcde", 5))
	assert.Equal(t, "abcdef", padLeft("abcdef", 5))
}
