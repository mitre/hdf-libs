package threshold

import (
	"strings"
	"testing"
)

// The specs below are the contract both surfaces enforce. `hdf validate
// threshold` and the MCP compliance tool reach this package by different
// routes — a YAML file and a JSON-marshalled inline object — so proving the
// behavior here is what makes the two surfaces agree by construction rather
// than by two implementations that happen to match today.

func TestDecode_RejectsUnknownKeyAtEveryLevel(t *testing.T) {
	for name, tc := range map[string]struct{ spec, wants string }{
		"category":   {"faild:\n  total:\n    max: 0\n", "is not a known threshold category"},
		"severity":   {"failed:\n  totl:\n    max: 0\n", "is not a known severity field"},
		"bound":      {"failed:\n  total:\n    mx: 0\n", "is not a known bound"},
		"compliance": {"compliance:\n  mn: 80\n", "is not a known compliance field"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Decode([]byte(tc.spec))
			if err == nil {
				t.Fatal("unknown key must be rejected")
			}
			// The message must read in the spec's vocabulary, not name the Go
			// type that happened to reject the key.
			if !strings.Contains(err.Error(), tc.wants) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.wants)
			}
			if strings.Contains(err.Error(), "hdfengine.") {
				t.Errorf("error leaks a Go type name: %q", err.Error())
			}
		})
	}
}

func TestDecode_AcceptsJSONAsWellAsYAML(t *testing.T) {
	// The MCP inline route marshals its object to JSON and decodes it here.
	cfg, err := Decode([]byte(`{"failed":{"total":{"max":0}}}`))
	if err != nil {
		t.Fatalf("JSON spec must decode, got %v", err)
	}
	if AssertionCount(cfg) != 1 {
		t.Errorf("assertion count = %d, want 1", AssertionCount(cfg))
	}

	if _, err := Decode([]byte(`{"faild":{"total":{"max":0}}}`)); err == nil {
		t.Error("an unknown key must be rejected in JSON too")
	}
}

func TestDecode_AcceptsEveryKnownKey(t *testing.T) {
	spec := `
compliance:
  min: 0
  max: 100
passed:
  critical: { min: 0 }
  high: { min: 0 }
  medium: { min: 0 }
  low: { min: 0 }
  none: { min: 0 }
  total: { min: 0 }
failed:
  total: { max: 1000 }
skipped:
  total: { max: 1000 }
error:
  total: { max: 1000 }
no_impact:
  total: { max: 1000 }
`
	cfg, err := Decode([]byte(spec))
	if err != nil {
		t.Fatalf("every documented key must decode, got %v", err)
	}
	if got := AssertionCount(cfg); got != 12 {
		t.Errorf("assertion count = %d, want 12", got)
	}
}

func TestAssertionCount_ZeroForSpecsThatAssertNothing(t *testing.T) {
	for name, spec := range map[string]string{
		"empty":          "",
		"empty mapping":  "{}\n",
		"comment only":   "# nothing\n",
		"null section":   "failed:\n",
		"empty section":  "failed: {}\n",
		"empty bound":    "failed:\n  total: {}\n",
		"empty controls": "failed:\n  total:\n    controls: []\n",
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := Decode([]byte(spec))
			if err != nil {
				t.Fatalf("spec must parse (it is well-formed), got %v", err)
			}
			if got := AssertionCount(cfg); got != 0 {
				t.Errorf("assertion count = %d, want 0 — this spec asserts nothing", got)
			}
		})
	}
}

func TestAssertionCount_CountsControlsAndNilConfig(t *testing.T) {
	cfg, err := Decode([]byte("failed:\n  total:\n    controls: [\"V-1\", \"V-2\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := AssertionCount(cfg); got != 2 {
		t.Errorf("controls list = %d assertions, want 2", got)
	}
	if got := AssertionCount(nil); got != 0 {
		t.Errorf("nil config = %d, want 0", got)
	}
}
