package hdfengine

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// The decoder's REFUSAL surface had no test at all, which an AC review caught by
// deleting the vocabulary check inside not and watching the whole hdf-cli suite
// stay green. A refusal nothing guards is the same false green an unrefused
// value produces, one layer further in.
func TestValuesAcceptedForms(t *testing.T) {
	for _, tc := range []struct {
		name string
		yaml string
		want Values
	}{
		{"scalar is the one-element list", `failed`, Values{In: []string{"failed"}}},
		{"list", `[failed, error]`, Values{In: []string{"failed", "error"}}},
		{"not over a list", `{not: [passed]}`, Values{Not: []string{"passed"}}},
		{"not over a scalar", `{not: passed}`, Values{Not: []string{"passed"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got Values
			require.NoError(t, yaml.Unmarshal([]byte(tc.yaml), &got))
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestValuesRefusedForms(t *testing.T) {
	for _, tc := range []struct{ name, yaml, wantErr string }{
		{"an empty not asserts nothing", `{not: []}`, "asserts nothing"},
		{"not cannot nest", `{not: {not: [passed]}}`, "nested"},
		{"an unknown key is not a form", `{nope: [passed]}`, "not a known form"},
		{"the in key is not a policy form — only the decoder produces it", `{in: [failed]}`, "not a known form"},
		{"a number is not a value", `{a: 1}`, "not a known form"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got Values
			err := yaml.Unmarshal([]byte(tc.yaml), &got)
			require.Error(t, err, "a malformed predicate must be refused, not silently assert nothing")
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// JSON and YAML must refuse the same shapes: an inline -I spec and the MCP both
// arrive as JSON, and a form one accepts and the other refuses is a surface
// divergence a policy author would hit without warning.
func TestValuesJSONMatchesYAML(t *testing.T) {
	for _, form := range []string{`"failed"`, `["failed","error"]`, `{"not":["passed"]}`, `{"not":"passed"}`} {
		t.Run(form, func(t *testing.T) {
			var got Values
			require.NoError(t, json.Unmarshal([]byte(form), &got))
			assert.True(t, got.Active())
		})
	}
	for _, form := range []string{`{"not":[]}`, `{"not":{"not":["p"]}}`, `{"nope":["p"]}`, `{"in":["failed"]}`, `5`} {
		t.Run("refused "+form, func(t *testing.T) {
			var got Values
			assert.Error(t, json.Unmarshal([]byte(form), &got))
		})
	}
}

// All() is what makes the vocabulary check see inside a negation. Without it a
// typo there excludes nothing and the predicate matches EVERYTHING — the inverse
// of the inclusive typo, and harder to notice.
func TestValuesAllCoversBothModes(t *testing.T) {
	assert.ElementsMatch(t, []string{"a", "b"}, Values{In: []string{"a"}, Not: []string{"b"}}.All())
	assert.Empty(t, Values{}.All())
}

func TestValuesMatchCombinesModes(t *testing.T) {
	is := func(actual string) func(string) bool {
		return func(want string) bool { return actual == want }
	}
	assert.True(t, Values{In: []string{"a", "b"}}.Match(is("b")), "values within a field OR")
	assert.False(t, Values{In: []string{"a"}}.Match(is("b")))
	assert.False(t, Values{Not: []string{"a"}}.Match(is("a")))
	assert.True(t, Values{Not: []string{"a"}}.Match(is("b")))

	// ABSENCE: a field that matches no value at all satisfies a negation. This
	// is what lets a gate catch the failure nobody adjudicated.
	assert.True(t, Values{Not: []string{"waiver"}}.Match(func(string) bool { return false }))
	assert.False(t, Values{In: []string{"waiver"}}.Match(func(string) bool { return false }))

	assert.True(t, Values{}.Match(is("anything")), "an inactive field constrains nothing")
}
