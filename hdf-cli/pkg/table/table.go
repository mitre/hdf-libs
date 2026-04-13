// Package table provides a simple column-aligned text table renderer.
// It supports left/right alignment, optional headers, and writes to any io.Writer.
package table

import (
	"fmt"
	"io"
	"strings"
)

// ColumnAlign specifies column alignment.
type ColumnAlign int

const (
	// AlignLeft left-aligns column content (default).
	AlignLeft ColumnAlign = iota
	// AlignRight right-aligns column content (for numbers).
	AlignRight
)

// Column defines a table column.
type Column struct {
	Header string
	Align  ColumnAlign
}

// Table renders columnar data with optional headers.
type Table struct {
	columns []Column
	rows    [][]string
}

// New creates a table with the given column definitions.
func New(columns ...Column) *Table {
	return &Table{columns: columns}
}

// AddRow appends a row. Values are positional — one per column.
// Extra values are ignored; missing values become empty strings.
func (t *Table) AddRow(values ...string) {
	row := make([]string, len(t.columns))
	for i := range t.columns {
		if i < len(values) {
			row[i] = values[i]
		}
	}
	t.rows = append(t.rows, row)
}

// Len returns the number of data rows.
func (t *Table) Len() int {
	return len(t.rows)
}

// Render writes the table to w. Headers are included when showHeaders is true.
func (t *Table) Render(w io.Writer, showHeaders bool) {
	if len(t.rows) == 0 && !showHeaders {
		return
	}

	widths := t.computeWidths()

	if showHeaders {
		t.renderHeader(w, widths)
	}

	for _, row := range t.rows {
		t.renderRow(w, row, widths)
	}
}

// computeWidths returns the maximum width for each column, considering
// both headers and data.
func (t *Table) computeWidths() []int {
	widths := make([]int, len(t.columns))

	for i, col := range t.columns {
		widths[i] = len(col.Header)
	}

	for _, row := range t.rows {
		for i, val := range row {
			if len(val) > widths[i] {
				widths[i] = len(val)
			}
		}
	}

	return widths
}

func (t *Table) renderHeader(w io.Writer, widths []int) {
	parts := make([]string, len(t.columns))
	for i, col := range t.columns {
		parts[i] = padRight(col.Header, widths[i])
	}
	_, _ = fmt.Fprintln(w, strings.TrimRight(strings.Join(parts, "  "), " "))

	sepParts := make([]string, len(t.columns))
	for i, width := range widths {
		sepParts[i] = strings.Repeat("-", width)
	}
	_, _ = fmt.Fprintln(w, strings.Join(sepParts, "  "))
}

func (t *Table) renderRow(w io.Writer, row []string, widths []int) {
	parts := make([]string, len(t.columns))
	for i, col := range t.columns {
		val := ""
		if i < len(row) {
			val = row[i]
		}
		if col.Align == AlignRight {
			parts[i] = padLeft(val, widths[i])
		} else {
			parts[i] = padRight(val, widths[i])
		}
	}
	_, _ = fmt.Fprintln(w, strings.TrimRight(strings.Join(parts, "  "), " "))
}

func padRight(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}

func padLeft(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return strings.Repeat(" ", width-len(s)) + s
}
