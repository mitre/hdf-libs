package oscal

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// The table sits beside this package because go:embed cannot reach a parent
// directory; the TypeScript peer imports the same file.
//
//go:embed oscal-vocabulary.json
var vocabularyJSON []byte

// VocabularyRow is one prop of the OSCAL vocabulary hdf-libs exporters emit or read.
type VocabularyRow struct {
	Name        string   `json:"name"`
	Ns          string   `json:"ns"`
	Objects     []string `json:"objects"`
	Meaning     string   `json:"meaning"`
	ValueFormat string   `json:"valueFormat"`
	HDFField    *string  `json:"hdfField"`
	Legacy      bool     `json:"legacy"`
}

type vocabularyTable struct {
	Namespace        string          `json:"namespace"`
	DefaultNamespace string          `json:"defaultNamespace"`
	Props            []VocabularyRow `json:"props"`
	byName           map[string]VocabularyRow
}

var vocabulary = mustLoadVocabulary(vocabularyJSON)

func mustLoadVocabulary(raw []byte) *vocabularyTable {
	var table vocabularyTable
	if err := json.Unmarshal(raw, &table); err != nil {
		panic(fmt.Sprintf("oscal: the OSCAL vocabulary table is not valid JSON: %v", err))
	}
	v, err := newVocabulary(table)
	if err != nil {
		panic(err.Error())
	}
	return v
}

// newVocabulary validates a decoded vocabulary table and indexes its rows by name.
// The TypeScript peer's validateVocabularyTable makes the same checks.
func newVocabulary(table vocabularyTable) (*vocabularyTable, error) {
	switch {
	case table.Namespace == "":
		return nil, errors.New("oscal: the OSCAL vocabulary table has no namespace")
	case table.DefaultNamespace == "":
		return nil, errors.New("oscal: the OSCAL vocabulary table has no defaultNamespace")
	case len(table.Props) == 0:
		return nil, errors.New("oscal: the OSCAL vocabulary table has no rows")
	}
	table.byName = make(map[string]VocabularyRow, len(table.Props))
	for _, row := range table.Props {
		if _, dup := table.byName[row.Name]; dup {
			return nil, fmt.Errorf("oscal: the OSCAL vocabulary table defines %q twice", row.Name)
		}
		table.byName[row.Name] = row
	}
	return &table, nil
}

// VocabularyNamespace returns the ns URI of every prop HDF defines.
func VocabularyNamespace() string { return vocabulary.Namespace }

// VocabularyDefaultNamespace returns NIST's default namespace, which a prop with no ns belongs to.
func VocabularyDefaultNamespace() string { return vocabulary.DefaultNamespace }

// VocabularyRows returns a copy of every row of the vocabulary table.
func VocabularyRows() []VocabularyRow {
	rows := make([]VocabularyRow, len(vocabulary.Props))
	for i, row := range vocabulary.Props {
		row.Objects = append([]string(nil), row.Objects...)
		if row.HDFField != nil {
			field := *row.HDFField
			row.HDFField = &field
		}
		rows[i] = row
	}
	return rows
}

func mustVocabularyRow(name string) VocabularyRow {
	row, ok := vocabulary.byName[name]
	if !ok {
		panic(fmt.Sprintf("oscal: %q is not a row of the OSCAL vocabulary", name))
	}
	return row
}

// isOSCALLineTerminator reports the characters OSCAL's single-line string pattern
// cannot hold: ECMAScript LineTerminator.
func isOSCALLineTerminator(r rune) bool {
	return r == '\n' || r == '\r' || r == '\u2028' || r == '\u2029'
}

// isECMAScriptWhitespace reports whether r matches ECMAScript \s, the whitespace
// OSCAL's StringDatatype pattern forbids at either edge. strings.TrimSpace uses a
// different set (it trims U+0085 and keeps U+FEFF).
func isECMAScriptWhitespace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', '\u00A0', '\u1680', '\u2028', '\u2029', '\u202F', '\u205F', '\u3000', '\uFEFF':
		return true
	}
	return r >= '\u2000' && r <= '\u200A'
}

// NormalizePropValue renders an HDF value as an OSCAL StringDatatype (ADR-0014
// §1.7.1): each run of line terminators becomes one space, ECMAScript whitespace
// is trimmed from both edges, and a value with nothing left becomes "_". An empty
// value stays empty; carrying it is the caller's decision (§1.7.3).
func NormalizePropValue(value string) string {
	if value == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(value))
	inRun := false
	for _, r := range value {
		if isOSCALLineTerminator(r) {
			if !inRun {
				b.WriteByte(' ')
			}
			inRun = true
			continue
		}
		inRun = false
		b.WriteRune(r)
	}
	normalized := strings.TrimFunc(b.String(), isECMAScriptWhitespace)
	if normalized == "" {
		return "_"
	}
	return normalized
}

// VocabularyProp builds the prop a vocabulary row names, in that row's namespace
// (omitted for NIST's default namespace). The value is normalized (§1.7.1), and an
// HDF prop whose value changed carries the exact value in remarks (§1.7.2). It
// returns false for an empty value, which writes no prop. An unknown name panics:
// every prop an exporter emits must be a row.
func VocabularyProp(name, value string) (Property, bool) {
	row := mustVocabularyRow(name)
	if value == "" {
		return Property{}, false
	}
	prop := Property{Name: row.Name, Value: NormalizePropValue(value)}
	if row.Ns != vocabulary.DefaultNamespace {
		prop.Ns = row.Ns
	}
	if row.Ns == vocabulary.Namespace && prop.Value != value {
		prop.Remarks = value
	}
	return prop, true
}

// AppendVocabularyProp appends VocabularyProp(name, value) to props when it writes a prop.
func AppendVocabularyProp(props []Property, name, value string) []Property {
	if prop, ok := VocabularyProp(name, value); ok {
		return append(props, prop)
	}
	return props
}

// EmptyFieldProp marks an optional HDF string field that is present but empty (§1.7.3).
func EmptyFieldProp(field string) Property {
	return mustFieldProp("empty-field", field)
}

// AbsentFieldProp marks an HDF field OSCAL required a display fallback for (§1.7.4).
func AbsentFieldProp(field string) Property {
	return mustFieldProp("absent-field", field)
}

func mustFieldProp(name, field string) Property {
	prop, ok := VocabularyProp(name, field)
	if !ok {
		panic(fmt.Sprintf("oscal: %s needs the name of an HDF field", name))
	}
	return prop
}

// PropMatch is a prop the read helpers matched to a vocabulary row.
type PropMatch struct {
	// Index is the prop's position in the slice searched.
	Index int
	// Value is the HDF value: an HDF prop's remarks when present (§1.7.2), otherwise its value.
	Value string
	// Legacy reports a match through the pre-ADR fallback: a prop with no ns whose name is a legacy row (§1.4).
	Legacy bool
}

// FindVocabularyProp returns the first prop in props that is the named row's prop.
func FindVocabularyProp(props []Property, name string) (PropMatch, bool) {
	row, ok := vocabulary.byName[name]
	if !ok {
		return PropMatch{}, false
	}
	for i := range props {
		if m, ok := matchVocabularyProp(row, i, &props[i]); ok {
			return m, true
		}
	}
	return PropMatch{}, false
}

// FindVocabularyProps returns every prop in props that is the named row's prop, in order.
func FindVocabularyProps(props []Property, name string) []PropMatch {
	row, ok := vocabulary.byName[name]
	if !ok {
		return nil
	}
	var matches []PropMatch
	for i := range props {
		if m, ok := matchVocabularyProp(row, i, &props[i]); ok {
			matches = append(matches, m)
		}
	}
	return matches
}

// matchVocabularyProp matches a prop to a row by name and namespace. An absent ns
// is NIST's default namespace, except that for a legacy row it is also accepted
// as the row's own prop.
func matchVocabularyProp(row VocabularyRow, index int, p *Property) (PropMatch, bool) {
	if p.Name != row.Name {
		return PropMatch{}, false
	}
	ns := p.Ns
	if ns == "" {
		ns = vocabulary.DefaultNamespace
	}
	legacy := false
	if ns != row.Ns {
		if p.Ns != "" || !row.Legacy {
			return PropMatch{}, false
		}
		legacy = true
	}
	value := p.Value
	if row.Ns == vocabulary.Namespace && p.Remarks != "" {
		value = p.Remarks
	}
	return PropMatch{Index: index, Value: value, Legacy: legacy}, true
}

// ConsumedVocabularyProp reports whether p is HDF's own and so must never be
// carried as a foreign prop: every prop in the HDF namespace, and a prop with no
// ns whose name is a legacy row (§1.4, §3.1).
func ConsumedVocabularyProp(p Property) bool {
	if p.Ns == vocabulary.Namespace {
		return true
	}
	row, ok := vocabulary.byName[p.Name]
	return ok && p.Ns == "" && row.Legacy
}
