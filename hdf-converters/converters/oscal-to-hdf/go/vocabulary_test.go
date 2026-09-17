package oscal_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	hdftooscalpoam "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hdf-to-oscal-poam/go"
	hdftooscalsar "github.com/mitre/hdf-libs/hdf-converters/v3/converters/hdf-to-oscal-sar/go"
	oscal "github.com/mitre/hdf-libs/hdf-converters/v3/converters/oscal-to-hdf/go"
	corpus "github.com/mitre/hdf-libs/hdf-converters/v3/internal/corpus"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fedRAMPNamespace is FedRAMP's registered extension namespace (ADR-0014 §1.3).
const fedRAMPNamespace = "https://fedramp.gov/ns/oscal"

// allSARProps exercises every prop the SAR exporter can emit.
const allSARProps = `{
	"baselines": [{
		"name": "b", "version": "1.2.0",
		"requirements": [{
			"id": "SV-230221r858734_rule", "impact": 0.7, "title": "req",
			"tags": { "nist": ["AC-2"], "cci": ["CCI-000012"] },
			"descriptions": [
				{ "label": "default", "data": "default desc" },
				{ "label": "check", "data": "check text" },
				{ "label": "fix", "data": "fix text" }
			],
			"code": "control 'SV-1' do end",
			"controlType": "technical", "verificationMethod": "automated", "applicability": "required",
			"refs": [{ "ref": "Handbook 3\nsection 2" }],
			"cwe": ["CWE-79"],
			"epss": { "date": "2026-01-01", "score": 0.97532, "percentile": 0.999 },
			"kev": { "inKev": true, "dateAdded": "2025-01-01", "dueDate": "2025-02-01" },
			"cvss": [{ "version": "3.1", "baseScore": 9.8, "baseVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
			"results": [{ "status": "failed", "codeDesc": "c", "startTime": "2026-01-01T00:00:00Z" }]
		}, {
			"id": "SV-2", "impact": 0.0, "tags": {},
			"descriptions": [{ "label": "default", "data": "d" }, { "label": "fix", "data": "impact-0 fix text" }],
			"results": [{ "status": "passed", "codeDesc": "c", "startTime": "2026-01-01T00:00:00Z" }]
		}]
	}]
}`

// allPOAMProps exercises every prop the POA&M exporter emits from the vocabulary.
const allPOAMProps = `{
	"name": "a", "amendmentId": "8f2b7c1e-4d3a-4b6e-9a1f-2c3d4e5f6a7b",
	"labels": { "environment": "production" },
	"overrides": [{
		"requirementId": "AC-2", "type": "waiver", "status": "notApplicable",
		"reason": "accepted", "justification": "component_not_present",
		"impact": { "value": 0.3 },
		"baselineRef": "rhel-9-stig", "componentRef": "1b2c3d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e",
		"appliedAt": "2020-01-01T00:00:00Z", "expiresAt": "2099-12-31T00:00:00Z",
		"appliedBy": { "identifier": "analyst", "type": "username" },
		"milestones": [{
			"description": "patch", "status": "completed",
			"estimatedCompletion": "2099-12-31T00:00:00Z",
			"completedAt": "2020-02-01T00:00:00Z",
			"completedBy": { "identifier": "engineer", "type": "username" }
		}],
		"evidence": [{
			"type": "file", "data": "log", "mimeType": "text/plain",
			"capturedBy": { "identifier": "scanner", "type": "username" }
		}],
		"externalReferences": [{ "sourceName": "NVD", "externalId": "CVE-2021-44228", "href": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" }]
	}]
}`

// emittedProp is a prop as it appears in exporter output, with where it was.
type emittedProp struct {
	path  string
	name  string
	ns    string
	class string
}

// collectProps walks decoded OSCAL JSON and returns every member of every props array.
func collectProps(t *testing.T, node any, path string, out *[]emittedProp) {
	t.Helper()
	switch v := node.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if k == "props" {
				arr, ok := v[k].([]any)
				require.True(t, ok, "%s.props is not an array", path)
				for i, p := range arr {
					obj, ok := p.(map[string]any)
					require.True(t, ok, "%s.props[%d] is not an object", path, i)
					name, _ := obj["name"].(string)
					ns, _ := obj["ns"].(string)
					class, _ := obj["class"].(string)
					*out = append(*out, emittedProp{path: fmt.Sprintf("%s.props[%d]", path, i), name: name, ns: ns, class: class})
				}
				continue
			}
			collectProps(t, v[k], path+"."+k, out)
		}
	case []any:
		for i, e := range v {
			collectProps(t, e, fmt.Sprintf("%s[%d]", path, i), out)
		}
	}
}

// exporterInput is one input an exporter is run on. mayReject names why the
// exporter may refuse it; an input with none must convert.
type exporterInput struct {
	label     string
	input     []byte
	mayReject string
}

func readConverterFile(t *testing.T, parts ...string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(append([]string{shared.GetConvertersDir()}, parts...)...))
	require.NoError(t, err)
	return raw
}

func sarInputs(t *testing.T) []exporterInput {
	t.Helper()
	inputs := []exporterInput{
		{"hdf-fixtures results minimal", fixtures.Results.Minimal, ""},
		{"hdf-fixtures results inspec-multilayered", fixtures.Results.InspecMultilayered, ""},
		{"hdf-to-oscal-sar multiline", readConverterFile(t, "hdf-to-oscal-sar", "fixtures", "input", "multiline.hdf.json"), ""},
		{"every SAR prop", []byte(allSARProps), ""},
	}
	for _, c := range corpus.ResultsCorpus() {
		label := "corpus " + c.Name
		mayReject := corpusRejection(c)
		if reason, ok := sarRejections[label]; ok {
			mayReject = reason
		}
		inputs = append(inputs, exporterInput{label, c.Input, mayReject})
	}
	return inputs
}

func poamInputs(t *testing.T) []exporterInput {
	t.Helper()
	minimal, err := os.ReadFile(filepath.Join(shared.GetConvertersDir(), "..", "..", "hdf-schema", "test", "fixtures", "minimal-amendments.json"))
	require.NoError(t, err)
	inputs := []exporterInput{
		{"hdf-fixtures amendments uc-01-fixed", fixtures.Amendments.UC01Fixed, ""},
		{"hdf-fixtures amendments multi-cve", fixtures.Amendments.MultiCVE, ""},
		{"hdf-schema minimal-amendments", minimal, ""},
		{"every POA&M prop", []byte(allPOAMProps), ""},
	}
	for _, c := range corpus.AmendmentsCorpus() {
		inputs = append(inputs, exporterInput{"corpus " + c.Name, c.Input, corpusRejection(c)})
	}
	return inputs
}

// canonicalNs treats an absent ns as the NIST default namespace, as OSCAL does.
func canonicalNs(ns string) string {
	if ns == "" {
		return oscal.VocabularyDefaultNamespace()
	}
	return ns
}

// amendmentLabelClass marks the POA&M label props whose names come from HDF data.
const amendmentLabelClass = "amendment-label"

// assertEmittedPropsAreRows converts every input and asserts each emitted prop
// is a vocabulary row carrying that row's namespace. It returns the names seen
// and how many amendment label props it skipped.
func assertEmittedPropsAreRows(t *testing.T, inputs []exporterInput, convert func([]byte) ([]byte, error)) (map[string]bool, int) {
	t.Helper()
	rows := map[string]oscal.VocabularyRow{}
	for _, r := range oscal.VocabularyRows() {
		rows[r.Name] = r
	}
	seen := map[string]bool{}
	labels := 0
	converted := 0
	for _, in := range inputs {
		out, err := convert(in.input)
		if err != nil {
			if problem := conversionErrorProblem(in, err); problem != "" {
				t.Error(problem)
			}
			continue
		}
		converted++
		var doc any
		require.NoError(t, json.Unmarshal(out, &doc), in.label)
		var props []emittedProp
		collectProps(t, doc, "$", &props)
		for _, p := range props {
			// ADR-0014 §1.5 excludes data-named label props; §4.6 replaces them.
			if p.class == amendmentLabelClass {
				labels++
				continue
			}
			row, ok := rows[p.name]
			if !assert.True(t, ok, "%s: %s emits prop %q, which is not a vocabulary row", in.label, p.path, p.name) {
				continue
			}
			assert.Equal(t, canonicalNs(row.Ns), canonicalNs(p.ns), "%s: %s prop %q carries the wrong namespace", in.label, p.path, p.name)
			if row.Ns == oscal.VocabularyDefaultNamespace() {
				assert.Empty(t, p.ns, "%s: %s NIST prop %q must keep the default namespace by omitting ns", in.label, p.path, p.name)
			}
			seen[p.name] = true
		}
	}
	require.NotZero(t, converted, "no input converted — the run would prove nothing")
	return seen, labels
}

// TestVocabulary_InlineInputsAreValidHDF guards the inline inputs: an exporter
// fed input its own schema rejects proves nothing about real documents.
func TestVocabulary_InlineInputsAreValidHDF(t *testing.T) {
	schemas := filepath.Join(shared.GetConvertersDir(), "..", "..", "hdf-validators", "go", "schemas")
	require.NoError(t, shared.NewSchemaValidator(t, filepath.Join(schemas, "hdf-results.schema.json")).Validate([]byte(allSARProps)))
	require.NoError(t, shared.NewSchemaValidator(t, filepath.Join(schemas, "hdf-amendments.schema.json")).Validate([]byte(allPOAMProps)))
}

func TestVocabulary_EmittedPropsAreRows(t *testing.T) {
	t.Run("hdf-to-oscal-sar", func(t *testing.T) {
		seen, _ := assertEmittedPropsAreRows(t, sarInputs(t), func(in []byte) ([]byte, error) {
			return hdftooscalsar.ConvertHDFToOSCALSAR(in, "1.0.0")
		})
		for _, name := range []string{
			"hdf-requirement-id", "baseline-version", "nist", "cci", "control-type", "verification-method",
			"applicability", "cwe", "epss-score", "epss-percentile", "kev", "kev-due-date", "cvss-base-score",
			"cvss-base-vector", "reference", "description-label", "type",
		} {
			assert.True(t, seen[name], "no input exercised the SAR prop %q, so the guard does not cover it", name)
		}
	})
	t.Run("hdf-to-oscal-poam", func(t *testing.T) {
		seen, labels := assertEmittedPropsAreRows(t, poamInputs(t), func(in []byte) ([]byte, error) {
			return hdftooscalpoam.ConvertHDFToOSCALPOAM(in, "1.0.0")
		})
		assert.Positive(t, labels, "no input emitted an amendment label prop, so the label exclusion is not exercised")
		for _, name := range []string{
			"amendment-id", "override-type", "impact-override", "justification", "baseline-ref", "component-ref",
			"milestone-status", "completed-at", "completed-by", "mime-type", "captured-by", "source-name",
			"external-id", "impacted-control-id",
		} {
			assert.True(t, seen[name], "no input exercised the POA&M prop %q, so the guard does not cover it", name)
		}
	})
}

// adrContextInventory is the ADR-0014 Context inventory: the 18 SAR and 13 POA&M
// names exporters emitted without ns before the ADR, plus FedRAMP's impacted-control-id.
var adrContextInventory = []string{
	"applicability", "baseline-version", "cci", "check", "control-type", "cvss-base-score",
	"cvss-base-vector", "cwe", "epss-percentile", "epss-score", "fix", "hdf-requirement-id", "kev",
	"kev-due-date", "nist", "rationale", "reference", "verification-method",
	"amendment-id", "baseline-ref", "captured-by", "completed-at", "completed-by", "component-ref",
	"external-id", "impact-override", "justification", "milestone-status", "mime-type",
	"override-type", "source-name",
	"impacted-control-id",
}

func TestVocabulary_TableShape(t *testing.T) {
	require.Equal(t, "https://mitre.github.io/hdf-libs/ns/oscal", oscal.VocabularyNamespace())
	require.Equal(t, "http://csrc.nist.gov/ns/oscal", oscal.VocabularyDefaultNamespace())
	rows := oscal.VocabularyRows()
	require.NotEmpty(t, rows)

	legacy := map[string]bool{}
	names := map[string]bool{}
	for _, r := range rows {
		assert.False(t, names[r.Name], "duplicate row %q", r.Name)
		names[r.Name] = true
		assert.NotEmpty(t, r.Name)
		assert.Equal(t, oscal.OSCALToken(r.Name), r.Name, "row name %q is not an OSCAL token", r.Name)
		assert.Contains(t, []string{oscal.VocabularyNamespace(), oscal.VocabularyDefaultNamespace(), fedRAMPNamespace}, r.Ns, "row %q", r.Name)
		assert.NotEmpty(t, r.Objects, "row %q names no OSCAL object", r.Name)
		assert.NotEmpty(t, r.Meaning, "row %q", r.Name)
		assert.NotEmpty(t, r.ValueFormat, "row %q", r.Name)
		if r.HDFField != nil {
			assert.NotEmpty(t, *r.HDFField, "row %q", r.Name)
		}
		if r.Legacy {
			legacy[r.Name] = true
		}
	}
	want := map[string]bool{}
	for _, n := range adrContextInventory {
		want[n] = true
	}
	require.Len(t, adrContextInventory, 32)
	assert.Equal(t, want, legacy, "legacy must be true for exactly the ADR-0014 Context inventory")

	byName := map[string]oscal.VocabularyRow{}
	for _, r := range rows {
		byName[r.Name] = r
	}
	assert.Equal(t, fedRAMPNamespace, byName["impacted-control-id"].Ns)
	for _, n := range []string{"type", "label", "sort-id", "version"} {
		assert.Equal(t, oscal.VocabularyDefaultNamespace(), byName[n].Ns, n)
		assert.False(t, byName[n].Legacy, n)
	}
	for _, n := range []string{"POAM-ID", "CORE", "assessment-type"} {
		assert.Equal(t, fedRAMPNamespace, byName[n].Ns, n)
		assert.False(t, byName[n].Legacy, n)
	}
	for _, n := range []string{"description-label", "empty-field", "absent-field"} {
		assert.Equal(t, oscal.VocabularyNamespace(), byName[n].Ns, n)
		assert.False(t, byName[n].Legacy, n)
	}
}

func TestVocabulary_RowsReturnsACopy(t *testing.T) {
	rows := oscal.VocabularyRows()
	rows[0].Name = "mutated"
	rows[0].Objects[0] = "mutated"
	assert.NotEqual(t, "mutated", oscal.VocabularyRows()[0].Name)
	assert.NotEqual(t, "mutated", oscal.VocabularyRows()[0].Objects[0])
}

// stringCases is the shared §1.7 case table.
type stringCases struct {
	Whitespace []string `json:"ecmascriptWhitespace"`
	Cases      []struct {
		Name    string  `json:"name"`
		In      string  `json:"in"`
		Value   *string `json:"value"`
		Remarks *string `json:"remarks"`
	} `json:"cases"`
}

func loadStringCases(t *testing.T) stringCases {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "shared", "oscal-string-cases.json"))
	require.NoError(t, err)
	var table stringCases
	require.NoError(t, json.Unmarshal(raw, &table))
	require.NotEmpty(t, table.Cases, "shared table is empty — the run would pass vacuously")
	return table
}

func TestVocabulary_EmitMatchesSharedStringCases(t *testing.T) {
	for _, tc := range loadStringCases(t).Cases {
		t.Run(tc.Name, func(t *testing.T) {
			prop, ok := oscal.VocabularyProp("reference", tc.In)
			if tc.Value == nil {
				assert.False(t, ok, "an empty value writes no prop")
				assert.Empty(t, oscal.AppendVocabularyProp(nil, "reference", tc.In))
				return
			}
			require.True(t, ok)
			assert.Equal(t, *tc.Value, prop.Value)
			assert.Equal(t, *tc.Value, oscal.NormalizePropValue(tc.In))
			if tc.Remarks == nil {
				assert.Empty(t, prop.Remarks)
			} else {
				assert.Equal(t, *tc.Remarks, prop.Remarks)
			}
			assert.Equal(t, oscal.VocabularyNamespace(), prop.Ns)
			assert.Equal(t, []oscal.Property{prop}, oscal.AppendVocabularyProp(nil, "reference", tc.In))

			assert.True(t, isStringDatatype(t, prop.Value), "%q is not an OSCAL StringDatatype", prop.Value)
			assert.Equal(t, tc.In == *tc.Value, isStringDatatype(t, tc.In), "the StringDatatype check must accept exactly the inputs normalization leaves unchanged")

			match, found := oscal.FindVocabularyProp([]oscal.Property{prop}, "reference")
			require.True(t, found)
			assert.Equal(t, tc.In, match.Value, "the read helper must return the exact HDF value")
		})
	}
}

// TestVocabulary_TrimSetIsECMAScriptWhitespace checks every code point: a
// character is trimmed from the edges exactly when the shared table lists it.
func TestVocabulary_TrimSetIsECMAScriptWhitespace(t *testing.T) {
	listed := map[rune]bool{}
	for _, cp := range loadStringCases(t).Whitespace {
		n, err := strconv.ParseUint(strings.TrimPrefix(cp, "U+"), 16, 32)
		require.NoError(t, err, cp)
		listed[rune(n)] = true
	}
	require.Len(t, listed, 25)
	for r := rune(0); r <= utf8.MaxRune; r++ {
		if !utf8.ValidRune(r) {
			continue
		}
		trimmed := oscal.NormalizePropValue(string(r)+"x") == "x"
		if trimmed != listed[r] {
			t.Errorf("U+%04X: trimmed=%v, listed as ECMAScript whitespace=%v", r, trimmed, listed[r])
		}
	}
}

func TestVocabulary_EmitHelpers(t *testing.T) {
	t.Run("an unknown name is a programming error", func(t *testing.T) {
		assert.PanicsWithValue(t, `oscal: "not-a-row" is not a row of the OSCAL vocabulary`, func() {
			oscal.VocabularyProp("not-a-row", "x")
		})
	})
	t.Run("a NIST row omits ns", func(t *testing.T) {
		p, ok := oscal.VocabularyProp("type", "evidence")
		require.True(t, ok)
		assert.Equal(t, oscal.Property{Name: "type", Value: "evidence"}, p)
	})
	t.Run("a FedRAMP row carries FedRAMP's namespace", func(t *testing.T) {
		p, ok := oscal.VocabularyProp("impacted-control-id", "ac-2")
		require.True(t, ok)
		assert.Equal(t, oscal.Property{Name: "impacted-control-id", Ns: fedRAMPNamespace, Value: "ac-2"}, p)
	})
	t.Run("a third-party prop never records remarks", func(t *testing.T) {
		p, ok := oscal.VocabularyProp("impacted-control-id", " ac-2\n")
		require.True(t, ok)
		assert.Equal(t, "ac-2", p.Value)
		assert.Empty(t, p.Remarks, "a third-party prop's remarks belong to its owner")
	})
	t.Run("append keeps existing props", func(t *testing.T) {
		props := oscal.AppendVocabularyProp([]oscal.Property{{Name: "x", Value: "y"}}, "kev", "true")
		assert.Equal(t, []oscal.Property{{Name: "x", Value: "y"}, {Name: "kev", Ns: oscal.VocabularyNamespace(), Value: "true"}}, props)
	})
	t.Run("empty-field names the HDF field", func(t *testing.T) {
		assert.Equal(t, oscal.Property{Name: "empty-field", Ns: oscal.VocabularyNamespace(), Value: "baselineRef"}, oscal.EmptyFieldProp("baselineRef"))
	})
	t.Run("a field prop needs a field name", func(t *testing.T) {
		assert.PanicsWithValue(t, "oscal: empty-field needs the name of an HDF field", func() { oscal.EmptyFieldProp("") })
	})
	t.Run("normalizing an empty value leaves it empty", func(t *testing.T) {
		assert.Empty(t, oscal.NormalizePropValue(""))
	})
	t.Run("absent-field names the HDF field", func(t *testing.T) {
		assert.Equal(t, oscal.Property{Name: "absent-field", Ns: oscal.VocabularyNamespace(), Value: "systemRef"}, oscal.AbsentFieldProp("systemRef"))
	})
}

func TestVocabulary_ReadHelpers(t *testing.T) {
	hdfNs := oscal.VocabularyNamespace()
	t.Run("matches name and namespace", func(t *testing.T) {
		props := []oscal.Property{
			{Name: "nist", Ns: "https://example.org/ns/oscal", Value: "foreign"},
			{Name: "cci", Ns: hdfNs, Value: "CCI-1"},
			{Name: "nist", Ns: hdfNs, Value: "AC-2"},
		}
		m, ok := oscal.FindVocabularyProp(props, "nist")
		require.True(t, ok)
		assert.Equal(t, oscal.PropMatch{Index: 2, Value: "AC-2"}, m)
	})
	t.Run("a legacy row accepts a prop with no ns and reports it", func(t *testing.T) {
		m, ok := oscal.FindVocabularyProp([]oscal.Property{{Name: "hdf-requirement-id", Value: "SV-1"}}, "hdf-requirement-id")
		require.True(t, ok)
		assert.Equal(t, oscal.PropMatch{Index: 0, Value: "SV-1", Legacy: true}, m)
	})
	t.Run("a non-legacy row rejects a prop with no ns", func(t *testing.T) {
		_, ok := oscal.FindVocabularyProp([]oscal.Property{{Name: "description-label", Value: "check"}}, "description-label")
		assert.False(t, ok)
	})
	t.Run("a legacy row rejects a prop in another namespace", func(t *testing.T) {
		_, ok := oscal.FindVocabularyProp([]oscal.Property{{Name: "nist", Ns: "https://example.org/ns/oscal", Value: "AC-2"}}, "nist")
		assert.False(t, ok)
	})
	t.Run("the FedRAMP row matches FedRAMP's namespace byte for byte", func(t *testing.T) {
		props := []oscal.Property{
			{Name: "impacted-control-id", Ns: "http://fedramp.gov/ns/oscal", Value: "ac-1"},
			{Name: "impacted-control-id", Ns: fedRAMPNamespace, Value: "ac-2"},
		}
		m, ok := oscal.FindVocabularyProp(props, "impacted-control-id")
		require.True(t, ok)
		assert.Equal(t, oscal.PropMatch{Index: 1, Value: "ac-2"}, m)
	})
	t.Run("the legacy FedRAMP row accepts no ns", func(t *testing.T) {
		m, ok := oscal.FindVocabularyProp([]oscal.Property{{Name: "impacted-control-id", Value: "ac-2"}}, "impacted-control-id")
		require.True(t, ok)
		assert.Equal(t, oscal.PropMatch{Index: 0, Value: "ac-2", Legacy: true}, m)
	})
	t.Run("an HDF prop prefers remarks", func(t *testing.T) {
		m, ok := oscal.FindVocabularyProp([]oscal.Property{{Name: "reference", Ns: hdfNs, Value: "a b", Remarks: "a\nb"}}, "reference")
		require.True(t, ok)
		assert.Equal(t, "a\nb", m.Value)
	})
	t.Run("a legacy-matched HDF prop prefers remarks", func(t *testing.T) {
		m, ok := oscal.FindVocabularyProp([]oscal.Property{{Name: "check", Value: "preview", Remarks: "full\ntext"}}, "check")
		require.True(t, ok)
		assert.Equal(t, "full\ntext", m.Value)
	})
	t.Run("a third-party prop ignores remarks", func(t *testing.T) {
		m, ok := oscal.FindVocabularyProp([]oscal.Property{{Name: "impacted-control-id", Ns: fedRAMPNamespace, Value: "ac-2", Remarks: "owner's note"}}, "impacted-control-id")
		require.True(t, ok)
		assert.Equal(t, "ac-2", m.Value)
	})
	t.Run("the NIST row matches an absent or explicit default namespace", func(t *testing.T) {
		props := []oscal.Property{
			{Name: "type", Ns: hdfNs, Value: "ours"},
			{Name: "type", Value: "evidence"},
			{Name: "type", Ns: oscal.VocabularyDefaultNamespace(), Value: "plan"},
		}
		assert.Equal(t, []oscal.PropMatch{{Index: 1, Value: "evidence"}, {Index: 2, Value: "plan"}}, oscal.FindVocabularyProps(props, "type"))
	})
	t.Run("an unknown name matches nothing", func(t *testing.T) {
		_, ok := oscal.FindVocabularyProp([]oscal.Property{{Name: "not-a-row", Ns: hdfNs, Value: "x"}}, "not-a-row")
		assert.False(t, ok)
		assert.Empty(t, oscal.FindVocabularyProps([]oscal.Property{{Name: "not-a-row", Value: "x"}}, "not-a-row"))
	})
	t.Run("finds every match in order", func(t *testing.T) {
		props := []oscal.Property{
			{Name: "cci", Ns: hdfNs, Value: "CCI-1"},
			{Name: "cci", Value: "CCI-2"},
			{Name: "cci", Ns: "https://example.org/ns/oscal", Value: "CCI-3"},
		}
		assert.Equal(t, []oscal.PropMatch{{Index: 0, Value: "CCI-1"}, {Index: 1, Value: "CCI-2", Legacy: true}}, oscal.FindVocabularyProps(props, "cci"))
	})
}

func TestVocabulary_ConsumedProps(t *testing.T) {
	hdfNs := oscal.VocabularyNamespace()
	for _, tc := range []struct {
		name string
		prop oscal.Property
		want bool
	}{
		{"an HDF-namespaced row", oscal.Property{Name: "nist", Ns: hdfNs, Value: "AC-2"}, true},
		{"an HDF-namespaced name that is not a row", oscal.Property{Name: "future-prop", Ns: hdfNs, Value: "x"}, true},
		{"a legacy row with no ns", oscal.Property{Name: "check", Value: "x"}, true},
		{"the legacy FedRAMP row with no ns", oscal.Property{Name: "impacted-control-id", Value: "ac-2"}, true},
		{"a non-legacy row with no ns", oscal.Property{Name: "description-label", Value: "check"}, false},
		{"a legacy name in a foreign namespace", oscal.Property{Name: "nist", Ns: "https://example.org/ns/oscal", Value: "AC-2"}, false},
		{"a FedRAMP prop in FedRAMP's namespace", oscal.Property{Name: "impacted-control-id", Ns: fedRAMPNamespace, Value: "ac-2"}, false},
		{"a NIST prop", oscal.Property{Name: "type", Value: "evidence"}, false},
		{"an unknown name with no ns", oscal.Property{Name: "priority", Value: "high"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, oscal.ConsumedVocabularyProp(tc.prop))
		})
	}
}

// corpusRejection is why the exporter may refuse a corpus case: the corpus marks
// MustReject cases as refused and lets MustNotCorrupt cases be refused.
func corpusRejection(c corpus.CorpusCase) string {
	if c.Contract == corpus.MustConvert {
		return ""
	}
	return "the adversarial corpus contract " + c.Contract.String() + " allows rejection"
}

// sarRejections mirrors the documented exemption in the SAR exporter's corpus
// test: OSCAL cannot represent an assessment with no evaluated baselines.
var sarRejections = map[string]string{
	"corpus zero-baselines": "OSCAL Assessment Results requires at least one result, so the SAR exporter rejects an assessment with no evaluated baselines",
}

// conversionErrorProblem returns why a conversion error fails the guard, or ""
// when the input may be rejected.
func conversionErrorProblem(in exporterInput, err error) string {
	if in.mayReject != "" {
		return ""
	}
	return fmt.Sprintf("%s: expected to convert, but the exporter failed: %v", in.label, err)
}

func TestVocabulary_ConversionErrorProblem(t *testing.T) {
	failure := fmt.Errorf("boom")
	assert.Equal(t, "fixture: expected to convert, but the exporter failed: boom", conversionErrorProblem(exporterInput{label: "fixture"}, failure))
	assert.Empty(t, conversionErrorProblem(exporterInput{label: "corpus x", mayReject: "allowed"}, failure))
	for _, c := range corpus.AmendmentsCorpus() {
		assert.Equal(t, c.Contract == corpus.MustConvert, corpusRejection(c) == "", c.Name)
	}
}

// stringDatatypePattern is OSCAL's StringDatatype pattern as vendored.
func stringDatatypePattern(t *testing.T) string {
	t.Helper()
	raw := readConverterFile(t, "hdf-to-oscal-sar", "schemas", "oscal_assessment-results_schema-v1.2.3.json")
	var schema struct {
		Definitions struct {
			StringDatatype struct {
				Pattern string `json:"pattern"`
			} `json:"StringDatatype"`
		} `json:"definitions"`
	}
	require.NoError(t, json.Unmarshal(raw, &schema))
	return schema.Definitions.StringDatatype.Pattern
}

// isStringDatatype applies the vendored StringDatatype pattern with the
// ECMAScript semantics JSON Schema gives it. Go's regexp reads \S and . with
// different character sets, so the pattern is evaluated from the shared case
// table's ECMAScript whitespace list instead, and the vendored pattern is pinned
// so a change to it fails here rather than going unchecked.
func isStringDatatype(t *testing.T, value string) bool {
	t.Helper()
	require.Equal(t, `^\S(.*\S)?$`, stringDatatypePattern(t), "the vendored StringDatatype pattern changed; revisit isStringDatatype")
	whitespace := map[rune]bool{}
	for _, cp := range loadStringCases(t).Whitespace {
		n, err := strconv.ParseUint(strings.TrimPrefix(cp, "U+"), 16, 32)
		require.NoError(t, err, cp)
		whitespace[rune(n)] = true
	}
	runes := []rune(value)
	if len(runes) == 0 || whitespace[runes[0]] || whitespace[runes[len(runes)-1]] {
		return false
	}
	for _, r := range runes {
		if r == '\n' || r == '\r' || r == '\u2028' || r == '\u2029' {
			return false
		}
	}
	return true
}

// propRead is a prop name the importer reads, as the static sweep found it.
type propRead struct {
	line    int
	name    string
	literal bool
	lookup  bool
}

var (
	propLookupRe        = regexp.MustCompile(`(\bfunc\s+)?\b(?:ExtractPropValue|ExtractAllPropValues|FindVocabularyProps?)\(\s*[^,()]+,\s*([^,)]+)`)
	nameComparisonRe    = regexp.MustCompile(`\.Name\s*(?:==|!=)\s*"([^"]*)"`)
	nonPropComparisonOK = map[string]string{
		"impact":     "a risk characterization facet name, not a prop",
		"risk":       "a risk characterization facet name, not a prop",
		"likelihood": "a risk characterization facet name, not a prop",
	}
)

// scanPropReads finds, in Go source, every prop-name argument of a prop lookup
// and every string literal a Name is compared with, across line breaks.
func scanPropReads(src string) []propRead {
	lineOf := func(offset int) int { return strings.Count(src[:offset], "\n") + 1 }
	var reads []propRead
	for _, m := range propLookupRe.FindAllStringSubmatchIndex(src, -1) {
		if m[2] >= 0 {
			continue // the helper's own definition
		}
		arg := strings.TrimSpace(src[m[4]:m[5]])
		name, err := strconv.Unquote(arg)
		if err != nil {
			reads = append(reads, propRead{line: lineOf(m[4]), name: arg, lookup: true})
			continue
		}
		reads = append(reads, propRead{line: lineOf(m[4]), name: name, literal: true, lookup: true})
	}
	for _, m := range nameComparisonRe.FindAllStringSubmatchIndex(src, -1) {
		name := src[m[2]:m[3]]
		if _, ok := nonPropComparisonOK[name]; ok {
			continue
		}
		reads = append(reads, propRead{line: lineOf(m[2]), name: name, literal: true})
	}
	return reads
}

func TestVocabulary_ScanPropReads(t *testing.T) {
	src := "package x\n\nfunc ExtractPropValue(props []Property, name, ns string) (string, bool) {\n" +
		"\tv, _ := ExtractPropValue(\n\t\tctrl.Props,\n\t\t\"CORE\",\n\t\t\"\",\n\t)\n" +
		"\tw := ExtractAllPropValues(p.Props, name, \"\")\n" +
		"\tif p.Name ==\n\t\t\"sort-id\" || f.Name != \"impact\" {\n\t}\n}\n"
	assert.Equal(t, []propRead{
		{line: 6, name: "CORE", literal: true, lookup: true},
		{line: 9, name: "name", lookup: true},
		{line: 11, name: "sort-id", literal: true},
	}, scanPropReads(src))
}

// TestVocabulary_ImporterPropReadsAreRows sweeps the importer's Go sources: a prop
// name the importer reads must be a vocabulary row (ADR-0014 §1.5).
func TestVocabulary_ImporterPropReadsAreRows(t *testing.T) {
	rows := map[string]bool{}
	for _, r := range oscal.VocabularyRows() {
		rows[r.Name] = true
	}
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	read := map[string]bool{}
	for _, f := range files {
		// vocabulary.go is the helpers themselves, which forward a caller's name.
		if strings.HasSuffix(f, "_test.go") || f == "vocabulary.go" {
			continue
		}
		raw, err := os.ReadFile(f)
		require.NoError(t, err)
		for _, r := range scanPropReads(string(raw)) {
			switch {
			case !r.literal:
				t.Errorf("%s:%d reads a prop whose name is not a string literal (%s), so the sweep cannot check it", f, r.line, r.name)
			case !rows[r.name] && r.lookup:
				t.Errorf("%s:%d reads prop %q, which is not a vocabulary row", f, r.line, r.name)
			case !rows[r.name]:
				t.Errorf("%s:%d compares a name with %q, which is not a vocabulary row", f, r.line, r.name)
			}
			read[r.name] = true
		}
	}
	for _, name := range []string{"CORE", "label", "sort-id", "version", "assessment-type", "POAM-ID", "impacted-control-id", "description-label"} {
		assert.True(t, read[name], "the sweep no longer finds the importer's read of %q; it may have stopped matching", name)
	}
}
