package cmd

import (
	"os"

	"github.com/mitre/hdf-cli/pkg/table"
)

// ColumnAlign re-exports table.ColumnAlign for use by command files.
type ColumnAlign = table.ColumnAlign

// Column re-exports table.Column for use by command files.
type Column = table.Column

// Table wraps pkg/table.Table with CLI-specific defaults (stdout, noHeaders).
type Table struct {
	inner *table.Table
}

// Re-export alignment constants.
const (
	AlignLeft  = table.AlignLeft
	AlignRight = table.AlignRight
)

// NewTable creates a table that renders to stdout using the global noHeaders flag.
func NewTable(columns ...Column) *Table {
	return &Table{inner: table.New(columns...)}
}

// AddRow appends a row to the table.
func (t *Table) AddRow(values ...string) {
	t.inner.AddRow(values...)
}

// Len returns the number of data rows.
func (t *Table) Len() int {
	return t.inner.Len()
}

// Render prints the table to stdout, respecting the global noHeaders flag.
func (t *Table) Render() {
	t.inner.Render(os.Stdout, !noHeaders)
}
