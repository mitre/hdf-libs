package tools

import (
	"reflect"
	"strings"
	"testing"

	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
)

// hdf_query.disposition is advertised in its `jsonschema` STRUCT TAG rather than as an
// enum, so it is guarded here: every canonical value must appear in the tag, and a retired
// form must not — an agent reading the tag cannot ask a follow-up question.
//
// The tag advertises the CANONICAL vocabulary only, not the aliases the CLI help teaches:
// one form per value, and every extra word is permanent tools/list token cost
// (hdf-libs-5cim9). The tool's own refusal names the same canonical set.
//
// Status and severity on hdf_query and hdf_aggregate used to be guarded here too. They now
// advertise real enum arrays built from the vocabulary, which this file's earlier note named
// as the condition for retiring the tag guard. TestToolsList_EveryClosedVocabularyIsAdvertised
// replaces it and asserts something stronger — the advertised enum EQUALS its source, so a
// missing value and a retired alias both fail, where a tag could only be checked for
// containment. Verified equal before the swap: the engine's filter values and the schema
// enum are the same five statuses and five severities.
func TestQueryDispositionTagNamesTheEngineVocabulary(t *testing.T) {
	const vocab = "disposition"

	field, ok := reflect.TypeOf(queryInput{}).FieldByName("Disposition")
	if !ok {
		t.Fatal("queryInput has no field Disposition")
	}
	tag := field.Tag.Get("jsonschema")
	if tag == "" {
		t.Fatal("queryInput.Disposition carries no jsonschema tag")
	}

	values := hdfengine.FilterValues(vocab)
	if len(values) == 0 {
		t.Fatalf("the %s vocabulary is empty, so this assertion could not fail", vocab)
	}
	for _, value := range values {
		if !strings.Contains(tag, value) {
			t.Errorf("hdf_query.Disposition tag omits %q, which the tool accepts:\n  %s", value, tag)
		}
	}

	for _, alias := range hdfengine.FilterAliases(vocab) {
		if alias.Advertise {
			continue
		}
		// Matched with a delimiter so a substring of a canonical value cannot
		// false-positive.
		for _, delimited := range []string{"|" + alias.Form, alias.Form + "|"} {
			if strings.Contains(tag, delimited) {
				t.Errorf("hdf_query.Disposition tag advertises the retired %q:\n  %s", alias.Form, tag)
			}
		}
	}
}
