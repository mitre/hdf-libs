package convert

import (
	"errors"
	"testing"
)

// mockConverter is a test double for the Converter interface.
type mockConverter struct {
	name      string
	output    []byte
	err       error
	callCount int
}

func (m *mockConverter) Convert(_ []byte) ([]byte, error) {
	m.callCount++
	if m.err != nil {
		return nil, m.err
	}
	return m.output, nil
}

func (m *mockConverter) Name() string {
	return m.name
}

func TestRegisterConverter(t *testing.T) {
	orig := converterRegistry
	defer func() { converterRegistry = orig }()
	converterRegistry = make(map[FormatPair]Converter)

	mock := &mockConverter{name: "Test Converter"}
	RegisterConverter("foo", "bar", mock)

	conv, err := GetConverter("foo", "bar")
	if err != nil {
		t.Errorf("GetConverter() error = %v, want nil", err)
	}
	if conv != mock {
		t.Errorf("GetConverter() returned wrong converter")
	}
}

func TestGetConverter_NotFound(t *testing.T) {
	orig := converterRegistry
	defer func() { converterRegistry = orig }()
	converterRegistry = make(map[FormatPair]Converter)

	_, err := GetConverter("unknown", "format")
	if err == nil {
		t.Error("GetConverter() expected error for unknown format pair, got nil")
	}
	if !errors.Is(err, ErrConverterNotFound) {
		t.Errorf("GetConverter() error = %v, want ErrConverterNotFound", err)
	}
}

func TestGetConverter_Normalization(t *testing.T) {
	orig := converterRegistry
	defer func() { converterRegistry = orig }()
	converterRegistry = make(map[FormatPair]Converter)

	mock := &mockConverter{name: "Normalized Converter"}
	RegisterConverter("legacyhdf", "hdf", mock)

	tests := []struct {
		name   string
		source string
		dest   string
	}{
		{"exact case", "legacyhdf", "hdf"},
		{"uppercase source", "LEGACYHDF", "hdf"},
		{"uppercase dest", "legacyhdf", "HDF"},
		{"mixed case", "LegacyHDF", "HDF"},
		{"with leading space", " legacyhdf", "hdf"},
		{"with trailing space", "legacyhdf ", "hdf "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conv, err := GetConverter(tt.source, tt.dest)
			if err != nil {
				t.Errorf("GetConverter(%q, %q) error = %v, want nil", tt.source, tt.dest, err)
			}
			if conv != mock {
				t.Errorf("GetConverter(%q, %q) returned wrong converter", tt.source, tt.dest)
			}
		})
	}
}

func TestListConverters(t *testing.T) {
	orig := converterRegistry
	defer func() { converterRegistry = orig }()
	converterRegistry = make(map[FormatPair]Converter)

	mock1 := &mockConverter{name: "Converter 1"}
	mock2 := &mockConverter{name: "Converter 2"}

	RegisterConverter("a", "b", mock1)
	RegisterConverter("c", "d", mock2)

	pairs := ListConverters()

	if len(pairs) != 2 {
		t.Errorf("ListConverters() returned %d pairs, want 2", len(pairs))
	}

	// Check that both pairs are present (order not guaranteed)
	foundAB := false
	foundCD := false
	for _, pair := range pairs {
		if pair.Source == "a" && pair.Dest == "b" {
			foundAB = true
		}
		if pair.Source == "c" && pair.Dest == "d" {
			foundCD = true
		}
	}

	if !foundAB {
		t.Error("ListConverters() missing a->b pair")
	}
	if !foundCD {
		t.Error("ListConverters() missing c->d pair")
	}
}

func TestListConverters_Empty(t *testing.T) {
	orig := converterRegistry
	defer func() { converterRegistry = orig }()
	converterRegistry = make(map[FormatPair]Converter)

	pairs := ListConverters()

	if len(pairs) != 0 {
		t.Errorf("ListConverters() returned %d pairs, want 0", len(pairs))
	}
}

func TestFormatPair_String(t *testing.T) {
	pair := FormatPair{Source: "legacyhdf", Dest: "hdf"}
	expected := "legacyhdf -> hdf"

	if pair.String() != expected {
		t.Errorf("FormatPair.String() = %q, want %q", pair.String(), expected)
	}
}

func TestNormalizeFormat(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hdf", "hdf"},
		{"HDF", "hdf"},
		{"LegacyHDF", "legacyhdf"},
		{" hdf ", "hdf"},
		{"  LEGACYHDF  ", "legacyhdf"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeFormat(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeFormat(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
