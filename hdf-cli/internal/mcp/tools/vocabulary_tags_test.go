package tools

import (
	"reflect"
	"strings"
	"testing"

	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
)

// The MCP advertises each closed vocabulary in a `jsonschema` STRUCT TAG, which
// is a compile-time literal and cannot be built from the engine's slice the way a
// cobra flag's help can. So it is guarded instead: every canonical value must
// appear in the tag, and a retired form must not — an agent reading the tag is
// the one consumer that cannot ask a follow-up question, so the tag must teach
// exactly what the tool accepts and advertises.
//
// The tag deliberately advertises the CANONICAL vocabulary only, not the aliases
// the CLI help teaches: an agent should be steered to one form per value, and
// every extra word here is permanent tools/list token cost (hdf-libs-5cim9). The
// tool's own refusal names the same canonical set, so tag and refusal agree — the
// property this guards. Retire it for a derived description if the SDK ever
// accepts one.
func TestToolSchemaTagsNameTheEngineVocabulary(t *testing.T) {
	for _, c := range []struct {
		tool  string
		input any
		field string
		vocab string
	}{
		{"hdf_query", queryInput{}, "Status", "status"},
		{"hdf_query", queryInput{}, "Severity", "severity"},
		{"hdf_query", queryInput{}, "Disposition", "disposition"},
		{"hdf_aggregate", aggregateInput{}, "Status", "status"},
		{"hdf_aggregate", aggregateInput{}, "Severity", "severity"},
	} {
		t.Run(c.tool+"."+c.vocab, func(t *testing.T) {
			field, ok := reflect.TypeOf(c.input).FieldByName(c.field)
			if !ok {
				t.Fatalf("%s has no field %s", c.tool, c.field)
			}
			tag := field.Tag.Get("jsonschema")
			if tag == "" {
				t.Fatalf("%s.%s carries no jsonschema tag", c.tool, c.field)
			}

			for _, value := range hdfengine.FilterValues(c.vocab) {
				if !strings.Contains(tag, value) {
					t.Errorf("%s.%s tag omits %q, which the tool accepts:\n  %s", c.tool, c.field, value, tag)
				}
			}

			for _, alias := range hdfengine.FilterAliases(c.vocab) {
				if alias.Advertise {
					continue
				}
				// A retired form resolves but must never be taught. Matched with a
				// delimiter so a substring of a canonical value (informational
				// contains no "none", but a future alias might) cannot false-positive.
				for _, delimited := range []string{"|" + alias.Form, alias.Form + "|"} {
					if strings.Contains(tag, delimited) {
						t.Errorf("%s.%s tag advertises the retired %q:\n  %s", c.tool, c.field, alias.Form, tag)
					}
				}
			}
		})
	}
}
