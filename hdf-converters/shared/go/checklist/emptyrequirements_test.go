package checklist

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const emptyReqHDF = `{"baselines":[{"name":"b","requirements":[]}],` +
	`"generator":{"name":"x","version":"1"},"timestamp":"2020-01-01T00:00:00Z"}`

const oneReqHDF = `{"baselines":[{"name":"b","requirements":[{"id":"V-1","title":"t","impact":0.5,` +
	`"descriptions":[{"label":"default","data":"d"}],` +
	`"results":[{"status":"failed","codeDesc":"c","startTime":"2020-01-01T00:00:00Z"}]}]}],` +
	`"generator":{"name":"x","version":"1"},"timestamp":"2020-01-01T00:00:00Z"}`

// A baseline with no requirements is schema-invalid HDF (requirements has
// minItems 1), and both of this package's importers already refuse the shape it
// produces — ParseCKL rejects an <iSTIG> with no <VULN>, ParseCKLB a stig with no
// rules[]. The exporter now refuses it too, so the same document is rejected on
// the way out as on the way in rather than becoming a file this repo cannot read.
func TestHDFToChecklistRejectsBaselineWithNoRequirements(t *testing.T) {
	_, err := HDFToChecklist([]byte(emptyReqHDF))
	require.Error(t, err, "a baseline with no requirements must be rejected, not turned into an empty stig")
	assert.Contains(t, err.Error(), "requirements",
		"the error must say what is wrong, not just that something is")
}

// Round trip is the assertion that would have caught the original defect: the
// exporter's own output must re-import. Covers .ckl and .cklb together because
// they share one builder.
func TestChecklistRoundTripsThroughItsOwnImporters(t *testing.T) {
	cl, err := HDFToChecklist([]byte(oneReqHDF))
	require.NoError(t, err)

	ckl, err := SerializeCKL(cl)
	require.NoError(t, err)
	back, err := ParseCKL(ckl)
	require.NoError(t, err, "the CKL exporter produced output ParseCKL refuses")
	require.NotEmpty(t, back.Stigs)
	assert.NotEmpty(t, back.Stigs[0].Vulns, "round trip lost the rules")

	cklb, err := SerializeCKLB(cl)
	require.NoError(t, err)
	backB, err := ParseCKLB(cklb)
	require.NoError(t, err, "the CKLB exporter produced output ParseCKLB refuses")
	require.NotEmpty(t, backB.Stigs)
	assert.NotEmpty(t, backB.Stigs[0].Vulns, "round trip lost the rules")
}

// Asserted on raw bytes: unmarshalling into a struct cannot tell null from [],
// so a struct-level check would pass against a broken build.
func TestSerializeCKLBNeverMarshalsANullSlice(t *testing.T) {
	cl, err := HDFToChecklist([]byte(oneReqHDF))
	require.NoError(t, err)
	out, err := SerializeCKLB(cl)
	require.NoError(t, err)

	assert.NotContains(t, string(out), "null",
		"no field may marshal as null; a .cklb consumer expecting an array gets nothing it can iterate")

	// The specific field this card is about, checked positively rather than by
	// the absence of the word null alone.
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &doc))
	stigs, _ := doc["stigs"].([]interface{})
	require.NotEmpty(t, stigs)
	first, _ := stigs[0].(map[string]interface{})
	_, hasRules := first["rules"]
	assert.True(t, hasRules, "rules must be present")
	assert.True(t, strings.Contains(string(out), `"rules": [`) || strings.Contains(string(out), `"rules":[`),
		"rules must marshal as an array")
}

// The export guard makes a nil Rules unreachable FROM HDF, but Checklist is a
// public type that ParseCKL/ParseCKLB and callers also build, so the serializer
// must not depend on its input having come through that guard. Audit of cklb.go's
// non-omitempty slice fields: stigs and rules were unguarded, ccis was already
// guarded by OrEmpty, legacy_ids carries omitempty. These cover the two that were
// not.
func TestSerializeCKLBGuardsEveryNonOmitemptySlice(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cl    *Checklist
		field string
	}{
		{"a stig with no rules", &Checklist{Stigs: []Stig{{StigID: "s", Title: "t"}}}, "rules"},
		{"a checklist with no stigs", &Checklist{}, "stigs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := SerializeCKLB(tc.cl)
			require.NoError(t, err)
			// Raw bytes: unmarshalling cannot tell null from [].
			assert.NotContains(t, string(out), `"`+tc.field+`": null`,
				"%s must marshal as [], not null — a consumer expecting an array gets nothing it can iterate", tc.field)
			assert.Contains(t, string(out), `"`+tc.field+`": [`,
				"%s must be present as an array", tc.field)
		})
	}
}

// Severity is always emitted and CKL's vocabulary is high/medium/low, so blank
// is not a legal value. It also round-trips badly: the importer maps an unknown
// severity to impact 0.5, so an exported impact of 0 came back as 0.5. This pins
// the floor and, by using the same ladder as the override path, pins that the two
// no longer disagree.
func TestResolveSeverityIsNeverBlank(t *testing.T) {
	for _, impact := range []float64{0, 0.01, 0.39, 0.4, 0.69, 0.7, 0.95, 1.0} {
		doc := `{"baselines":[{"name":"b","requirements":[{"id":"V-1","title":"t","impact":` +
			formatImpact(impact) +
			`,"descriptions":[{"label":"default","data":"d"}],` +
			`"results":[{"status":"failed","codeDesc":"c","startTime":"2020-01-01T00:00:00Z"}]}]}],` +
			`"generator":{"name":"x","version":"1"},"timestamp":"2020-01-01T00:00:00Z"}`

		cl, err := HDFToChecklist([]byte(doc))
		require.NoError(t, err, "impact %v", impact)
		require.NotEmpty(t, cl.Stigs)
		require.NotEmpty(t, cl.Stigs[0].Vulns)
		sev := cl.Stigs[0].Vulns[0].Severity
		assert.Contains(t, []string{"high", "medium", "low"}, sev,
			"impact %v produced severity %q, outside CKL's vocabulary", impact, sev)
	}
}

func formatImpact(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// baselines: [null] is a shape a non-schema-validating producer can emit. Go
// decodes null into a zero-value struct and reaches the domain error; the
// TypeScript peer had to be taught not to dereference it first. Pinned in both
// languages so they keep agreeing on the same input.
func TestHDFToChecklistRejectsNullBaseline(t *testing.T) {
	_, err := HDFToChecklist([]byte(`{"baselines":[null],` +
		`"generator":{"name":"x","version":"1"},"timestamp":"2020-01-01T00:00:00Z"}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "baseline 1 has no requirements",
		"a null baseline must reach the domain error, not a decode failure")
}
