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

// A threshold spec is one policy, but yaml.Decoder.Decode reads exactly one
// document — so bounds written after a second `---` were parsed by nobody and
// dropped without a word. KnownFields cannot catch it: strictness applies
// within a document, not across a stream.
func TestDecode_RejectsMultiDocumentSpec(t *testing.T) {
	for name, spec := range map[string]string{
		"second document is a typo":    "failed:\n  total:\n    max: 0\n---\nfaild:\n  total:\n    max: 5\n",
		"second document is valid":     "failed:\n  total:\n    max: 0\n---\npassed:\n  total:\n    min: 1\n",
		"content after a blank line":   "failed:\n  total:\n    max: 0\n---\n\npassed:\n  total:\n    min: 1\n",
		"second document is empty map": "failed:\n  total:\n    max: 0\n---\n{}\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode([]byte(spec)); err == nil {
				t.Fatal("a spec carrying a second document must be rejected, not silently truncated")
			} else if !strings.Contains(err.Error(), "single document") {
				t.Errorf("error = %q, want it to say the spec must be a single document", err.Error())
			}
		})
	}
}

// Separators that introduce no second document stay legal. A leading `---` is
// how many generated and hand-edited templates begin, so rejecting it is the
// obvious way to break every real spec while closing the hole above. Measured
// with yaml.v3: a bare trailing `---`, a repeated one, and a comment-only tail
// each decode to a null-tagged scalar carrying no value — nothing the author
// wrote is discarded, so there is nothing to report.
func TestDecode_AcceptsSeparatorsCarryingNoSecondDocument(t *testing.T) {
	for name, spec := range map[string]string{
		"leading separator":       "---\nfailed:\n  total:\n    max: 0\n",
		"trailing separator":      "failed:\n  total:\n    max: 0\n---\n",
		"two trailing separators": "failed:\n  total:\n    max: 0\n---\n---\n",
		"comment after separator": "failed:\n  total:\n    max: 0\n---\n# nothing here\n",
		"explicit end marker":     "failed:\n  total:\n    max: 0\n...\n",
		"both ends":               "---\nfailed:\n  total:\n    max: 0\n---\n",
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := Decode([]byte(spec))
			if err != nil {
				t.Fatalf("Decode() = %v, want the spec accepted", err)
			}
			if cfg.Failed == nil || cfg.Failed.Total == nil || cfg.Failed.Total.Max == nil {
				t.Fatalf("the first document must still be the one evaluated; got %+v", cfg)
			}
			if *cfg.Failed.Total.Max != 0 {
				t.Errorf("failed.total.max = %d, want 0", *cfg.Failed.Total.Max)
			}
		})
	}
}
