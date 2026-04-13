package table

import (
	"bytes"
	"strings"
	"testing"
)

func TestTable_BasicRender(t *testing.T) {
	tbl := New(Column{Header: "Name"}, Column{Header: "Value"})
	tbl.AddRow("foo", "bar")
	tbl.AddRow("longer", "x")

	var buf bytes.Buffer
	tbl.Render(&buf, true)

	output := buf.String()
	if !strings.Contains(output, "Name") {
		t.Error("expected header 'Name' in output")
	}
	if !strings.Contains(output, "foo") {
		t.Error("expected 'foo' in output")
	}
	if !strings.Contains(output, "longer") {
		t.Error("expected 'longer' in output")
	}
}

func TestTable_NoHeaders(t *testing.T) {
	tbl := New(Column{Header: "Name"}, Column{Header: "Value"})
	tbl.AddRow("foo", "bar")

	var buf bytes.Buffer
	tbl.Render(&buf, false)

	output := buf.String()
	if strings.Contains(output, "Name") {
		t.Error("expected no header when showHeaders=false")
	}
	if !strings.Contains(output, "foo") {
		t.Error("expected 'foo' in output")
	}
}

func TestTable_RightAlign(t *testing.T) {
	tbl := New(Column{Header: "Label"}, Column{Header: "Count", Align: AlignRight})
	tbl.AddRow("items", "42")
	tbl.AddRow("x", "1000")

	var buf bytes.Buffer
	tbl.Render(&buf, true)

	output := buf.String()
	lines := strings.Split(output, "\n")
	// Data rows should right-align the Count column
	for _, line := range lines {
		if strings.Contains(line, "42") {
			// "42" should be padded on the left relative to "1000"
			if !strings.Contains(line, "  42") {
				t.Errorf("expected right-aligned '42', got line: %q", line)
			}
		}
	}
}

func TestTable_EmptyWithNoHeaders(t *testing.T) {
	tbl := New(Column{Header: "X"})

	var buf bytes.Buffer
	tbl.Render(&buf, false)

	if buf.Len() != 0 {
		t.Errorf("expected empty output for no rows + no headers, got %q", buf.String())
	}
}

func TestTable_Len(t *testing.T) {
	tbl := New(Column{Header: "A"})
	if tbl.Len() != 0 {
		t.Errorf("expected 0 rows, got %d", tbl.Len())
	}
	tbl.AddRow("x")
	if tbl.Len() != 1 {
		t.Errorf("expected 1 row, got %d", tbl.Len())
	}
}

func TestTable_MissingValues(t *testing.T) {
	tbl := New(Column{Header: "A"}, Column{Header: "B"}, Column{Header: "C"})
	tbl.AddRow("only-one")

	var buf bytes.Buffer
	tbl.Render(&buf, false)

	output := buf.String()
	if !strings.Contains(output, "only-one") {
		t.Error("expected 'only-one' in output")
	}
}
