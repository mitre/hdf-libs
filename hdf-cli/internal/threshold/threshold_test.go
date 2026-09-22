package threshold

import (
	"strings"
	"testing"

	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
)

// The specs below are the contract both surfaces enforce. `hdf validate
// threshold` and the MCP compliance tool reach this package by different
// routes — a YAML file and a JSON-marshalled inline object — so proving the
// behavior here is what makes the two surfaces agree by construction rather
// than by two implementations that happen to match today.

// decodeOne parses a stream expected to hold exactly one policy and returns it.
// Most specs are a single document; the tests that care about several use
// DecodeAll directly.
func decodeOne(t *testing.T, spec string) (*hdfengine.ThresholdConfig, error) {
	t.Helper()
	specs, err := DecodeAll([]byte(spec), "spec.yaml")
	if err != nil {
		return nil, err
	}
	if len(specs) > 1 {
		t.Fatalf("got %d policies, want at most 1", len(specs))
	}
	if len(specs) == 0 {
		return &hdfengine.ThresholdConfig{}, nil
	}
	return specs[0].Config, nil
}

func TestDecode_RejectsUnknownKeyAtEveryLevel(t *testing.T) {
	for name, tc := range map[string]struct{ spec, wants string }{
		"category":   {"faild:\n  total:\n    max: 0\n", "is not a known threshold category"},
		"severity":   {"failed:\n  totl:\n    max: 0\n", "is not a known severity field"},
		"bound":      {"failed:\n  total:\n    mx: 0\n", "is not a known bound"},
		"compliance": {"compliance:\n  mn: 80\n", "is not a known compliance field"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := decodeOne(t, tc.spec)
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
	cfg, err := decodeOne(t, `{"failed":{"total":{"max":0}}}`)
	if err != nil {
		t.Fatalf("JSON spec must decode, got %v", err)
	}
	if AssertionCount(cfg) != 1 {
		t.Errorf("assertion count = %d, want 1", AssertionCount(cfg))
	}

	if _, err := decodeOne(t, `{"faild":{"total":{"max":0}}}`); err == nil {
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
	cfg, err := decodeOne(t, spec)
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
			cfg, err := decodeOne(t, spec)
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
	cfg, err := decodeOne(t, "failed:\n  total:\n    controls: [\"V-1\", \"V-2\"]\n")
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

// A spec stream holding several documents used to be truncated at the first and
// then, from 3.7, rejected outright. Both were stop-gaps for the same hole: the
// documents after the first had no defined meaning. They do now — a conjunction —
// so they are kept and evaluated. This test replaces the rejection it supersedes;
// what must never come back is the silent truncation both of them prevented.
func TestDecodeAll_KeepsEveryDocumentItUsedToRejectOrDrop(t *testing.T) {
	for name, tc := range map[string]struct {
		spec string
		want int
	}{
		"two policies":          {"failed:\n  total:\n    max: 0\n---\npassed:\n  total:\n    min: 1\n", 2},
		"content after blanks":  {"failed:\n  total:\n    max: 0\n---\n\npassed:\n  total:\n    min: 1\n", 2},
		"three policies":        {"failed:\n  total:\n    max: 0\n---\npassed:\n  total:\n    min: 1\n---\nskipped:\n  total:\n    max: 2\n", 3},
		"empty map is a policy": {"failed:\n  total:\n    max: 0\n---\n{}\n", 2},
	} {
		t.Run(name, func(t *testing.T) {
			specs, err := DecodeAll([]byte(tc.spec), "policy.yaml")
			if err != nil {
				t.Fatalf("DecodeAll() = %v, want %d policies", err, tc.want)
			}
			if len(specs) != tc.want {
				t.Fatalf("got %d policies, want %d", len(specs), tc.want)
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
			cfg, err := decodeOne(t, spec)
			if err != nil {
				t.Fatalf("DecodeAll() = %v, want the spec accepted", err)
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

// A spec stream may now hold several policies, evaluated as a conjunction. Each
// one is returned separately with a label, because a violation has to be able to
// name the policy it came from once a run applies more than one.
func TestDecodeAll_ReturnsOneSpecPerDocument(t *testing.T) {
	specs, err := DecodeAll([]byte("failed:\n  total:\n    max: 0\n---\npassed:\n  total:\n    min: 1\n"), "policy.yaml")
	if err != nil {
		t.Fatalf("DecodeAll() = %v, want two specs", err)
	}
	if len(specs) != 2 {
		t.Fatalf("got %d specs, want 2", len(specs))
	}
	// 1-based, because a person counting documents in a file starts at one.
	if specs[0].Label != "policy.yaml#1" || specs[1].Label != "policy.yaml#2" {
		t.Errorf("labels = %q, %q; want policy.yaml#1, policy.yaml#2", specs[0].Label, specs[1].Label)
	}
	if specs[0].Config.Failed == nil || specs[0].Config.Failed.Total == nil {
		t.Errorf("first spec lost its bounds: %+v", specs[0].Config)
	}
	if specs[1].Config.Passed == nil || specs[1].Config.Passed.Total == nil {
		t.Errorf("second spec lost its bounds: %+v", specs[1].Config)
	}
	// Documents stay separate. Merging two policies that bound the same key has
	// no defensible answer; evaluating both does.
	if specs[0].Config.Passed != nil || specs[1].Config.Failed != nil {
		t.Error("documents were merged into one another")
	}
}

// The common case must not grow an index it does not need.
func TestDecodeAll_SingleDocumentCarriesNoIndex(t *testing.T) {
	for name, spec := range map[string]string{
		"plain":              "failed:\n  total:\n    max: 0\n",
		"leading separator":  "---\nfailed:\n  total:\n    max: 0\n",
		"trailing separator": "failed:\n  total:\n    max: 0\n---\n",
		"comment tail":       "failed:\n  total:\n    max: 0\n---\n# nothing here\n",
	} {
		t.Run(name, func(t *testing.T) {
			specs, err := DecodeAll([]byte(spec), "policy.yaml")
			if err != nil {
				t.Fatalf("DecodeAll() = %v", err)
			}
			if len(specs) != 1 {
				t.Fatalf("got %d specs, want 1 — a separator carrying no document is not a policy", len(specs))
			}
			if specs[0].Label != "policy.yaml" {
				t.Errorf("label = %q, want the bare source with no index", specs[0].Label)
			}
		})
	}
}

// Strictness has to reach EVERY document. Before specs were decoded one by one,
// a key typed into the second document was unreachable: the decoder stopped at
// the first, so the typo was never seen by anything.
func TestDecodeAll_EnforcesKnownKeysInEveryDocument(t *testing.T) {
	_, err := DecodeAll([]byte("failed:\n  total:\n    max: 0\n---\nfaild:\n  total:\n    max: 5\n"), "policy.yaml")
	if err == nil {
		t.Fatal("a typo in the second document must be rejected")
	}
	if !strings.Contains(err.Error(), "is not a known threshold category") {
		t.Errorf("error = %q, want it to name the unknown category", err.Error())
	}
	// The message must say WHICH document, or a spec with many policies gives no
	// way to find the offending one.
	if !strings.Contains(err.Error(), "policy.yaml#2") {
		t.Errorf("error = %q, want it to name policy.yaml#2", err.Error())
	}
}

// An empty stream yields no specs at all; callers report "asserts nothing"
// rather than this layer inventing an empty policy that passes everything.
func TestDecodeAll_EmptyInputYieldsNoSpecs(t *testing.T) {
	for name, spec := range map[string]string{"empty": "", "separator only": "---\n", "comment only": "# nothing\n"} {
		t.Run(name, func(t *testing.T) {
			specs, err := DecodeAll([]byte(spec), "policy.yaml")
			if err != nil {
				t.Fatalf("DecodeAll() = %v", err)
			}
			if len(specs) != 0 {
				t.Errorf("got %d specs, want none", len(specs))
			}
		})
	}
}
