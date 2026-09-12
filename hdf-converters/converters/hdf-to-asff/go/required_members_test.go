package hdftoasff

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	corpus "github.com/mitre/hdf-libs/hdf-converters/v3/internal/corpus"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AWS publishes no JSON Schema for ASFF, so the required-member lists come from
// its official service model instead of a hand-kept list in this file. See
// ../schemas/provenance.json for the source and how to re-derive them.
func requiredMembers(t *testing.T) map[string][]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "schemas", "asff-required-members.json"))
	require.NoError(t, err)
	var table struct {
		Required map[string][]string `json:"required"`
	}
	require.NoError(t, json.Unmarshal(raw, &table))
	require.NotEmpty(t, table.Required, "an empty table would pass vacuously")
	return table.Required
}

// A required member that is present but empty is not satisfied: AWS rejects an
// empty GeneratorId, and the hand-rolled key-list check this replaces could not
// see the difference between "absent" and "".
func TestConvertHDFToASFFRequiredMembersArePresentAndNonEmpty(t *testing.T) {
	req := requiredMembers(t)
	for _, fixture := range []string{"compliance.json", "cve.json"} {
		for i, f := range convert(t, fixture) {
			for _, k := range req["AwsSecurityFinding"] {
				v, ok := f[k]
				if !assert.True(t, ok, "%s finding %d: required member %q absent", fixture, i, k) {
					continue
				}
				if s, isStr := v.(string); isStr {
					assert.NotEmpty(t, s, "%s finding %d: required member %q is an empty string", fixture, i, k)
				}
			}
		}
	}
}

// Every emitted Vulnerability carries its required Id. A vulnerability object
// without one is not a lesser finding, it is an invalid one.
func TestConvertHDFToASFFEveryVulnerabilityHasRequiredID(t *testing.T) {
	req := requiredMembers(t)
	require.Contains(t, req["Vulnerability"], "Id", "the table must say Id is required or this asserts nothing")

	// A CVSS entry with no source: the field Id was being derived from.
	input := []byte(`{"baselines":[{"name":"b","requirements":[{"id":"SV-1","title":"t","impact":0.5,` +
		`"descriptions":[{"label":"default","data":"d"}],` +
		`"cvss":[{"score":7.5}],` +
		`"results":[{"status":"failed","codeDesc":"c","startTime":"2020-01-01T00:00:00Z"}]}]}],` +
		`"generator":{"name":"x","version":"1"},"timestamp":"2020-01-01T00:00:00Z"}`)

	out, err := ConvertHDFToASFF(input, converterVersion)
	require.NoError(t, err)
	var doc struct {
		Findings []map[string]interface{} `json:"Findings"`
	}
	require.NoError(t, json.Unmarshal(out, &doc))
	require.NotEmpty(t, doc.Findings)

	for i, f := range doc.Findings {
		vulns, ok := f["Vulnerabilities"].([]interface{})
		if !ok {
			continue
		}
		for j, v := range vulns {
			entry, isMap := v.(map[string]interface{})
			require.True(t, isMap)
			id, present := entry["Id"]
			assert.True(t, present, "finding %d vulnerability %d: required Id absent", i, j)
			if present {
				assert.NotEmpty(t, id, "finding %d vulnerability %d: required Id is empty", i, j)
			}
		}
	}
}

// GeneratorId falls back rather than emitting "" when a requirement has no id.
func TestConvertHDFToASFFGeneratorIDNeverEmpty(t *testing.T) {
	input := []byte(`{"baselines":[{"name":"b","requirements":[{"id":"","title":"t","impact":0.5,` +
		`"descriptions":[{"label":"default","data":"d"}],` +
		`"results":[{"status":"failed","codeDesc":"c","startTime":"2020-01-01T00:00:00Z"}]}]}],` +
		`"generator":{"name":"x","version":"1"},"timestamp":"2020-01-01T00:00:00Z"}`)

	out, err := ConvertHDFToASFF(input, converterVersion)
	require.NoError(t, err)
	var doc struct {
		Findings []map[string]interface{} `json:"Findings"`
	}
	require.NoError(t, json.Unmarshal(out, &doc))
	require.NotEmpty(t, doc.Findings)
	assert.NotEmpty(t, doc.Findings[0]["GeneratorId"], "GeneratorId must never be an empty string")
}

// asffRequiredMembersValidator is this converter's stand-in for a target schema:
// AWS publishes no JSON Schema for ASFF (see ../schemas/provenance.txt), but its
// service model states which members are required, so output missing one is
// malformed in the way a schema would catch. A no-op validator would make every
// MustConvert contract pass vacuously.
type asffRequiredMembersValidator struct {
	required map[string][]string
}

func (v asffRequiredMembersValidator) Validate(doc []byte) error {
	if len(doc) == 0 {
		return nil
	}
	var parsed struct {
		Findings []map[string]interface{} `json:"Findings"`
	}
	if err := json.Unmarshal(doc, &parsed); err != nil {
		return fmt.Errorf("output is not a JSON object: %w", err)
	}
	for i, f := range parsed.Findings {
		for _, k := range v.required["AwsSecurityFinding"] {
			val, ok := f[k]
			if !ok {
				return fmt.Errorf("finding %d: required member %q absent", i, k)
			}
			if s, isStr := val.(string); isStr && s == "" {
				return fmt.Errorf("finding %d: required member %q is an empty string", i, k)
			}
		}
		resources, _ := f["Resources"].([]interface{})
		for j, raw := range resources {
			entry, _ := raw.(map[string]interface{})
			for _, k := range v.required["Resource"] {
				val, ok := entry[k]
				if !ok {
					return fmt.Errorf("finding %d resource %d: required member %q absent", i, j, k)
				}
				if str, isStr := val.(string); isStr && str == "" {
					return fmt.Errorf("finding %d resource %d: required member %q is empty", i, j, k)
				}
			}
		}
		vulns, _ := f["Vulnerabilities"].([]interface{})
		for j, raw := range vulns {
			entry, _ := raw.(map[string]interface{})
			if id, ok := entry["Id"].(string); !ok || id == "" {
				return fmt.Errorf("finding %d vulnerability %d: required Id absent or empty", i, j)
			}
		}
	}
	return nil
}

// TestConvertHDFToASFF_AdversarialCorpus holds this converter to the shared
// corpus contracts, with AWS's own required-member lists standing in for the
// schema it does not publish.
func TestConvertHDFToASFF_AdversarialCorpus(t *testing.T) {
	v := asffRequiredMembersValidator{required: requiredMembers(t)}
	corpus.RunSchemaCorpus(t, v, corpus.ResultsCorpus(),
		func(in []byte) ([]byte, error) { return ConvertHDFToASFF(in, converterVersion) })
}

// corpusRejected marks a corpus case the converter refuses; the two languages
// must agree on rejection as well as on output.
const corpusRejected = "REJECTED"

// TestConvertHDFToASFF_CorpusOutputGolden pins what this converter emits for
// every corpus input so the two languages are compared against one another
// rather than each against its own expectations. Go owns regeneration
// (go test ./converters/hdf-to-asff/go/ -update); TypeScript only verifies.
//
// This is what makes the byte-identical-output claim an assertion rather than a
// manual observation. It covers the id-less REQUIREMENT shape, which the full
// fixtures do not reach; no corpus case carries a cvss[] entry, so the id-less
// CVSS shape is covered by TestConvertHDFToASFFTypesReflectsEmittedVulnerabilities
// instead, not here.
func TestConvertHDFToASFF_CorpusOutputGolden(t *testing.T) {
	outputs := make(map[string]string, len(corpus.ResultsCorpus()))
	for _, c := range corpus.ResultsCorpus() {
		out, err := corpus.ConvertNoPanic(
			func(in []byte) ([]byte, error) { return ConvertHDFToASFF(in, converterVersion) }, c.Input)
		if err != nil {
			outputs[c.Name] = corpusRejected
			continue
		}
		outputs[c.Name] = string(out)
	}

	actual, err := json.MarshalIndent(outputs, "", "  ")
	require.NoError(t, err)
	actual = append(actual, '\n')

	path := filepath.Join("..", "fixtures", "expected", "corpus-outputs.json")
	if shared.UpdateSnapshots() {
		require.NoError(t, os.WriteFile(path, actual, 0o600))
		t.Logf("updated %s", path)
		return
	}
	expected, err := os.ReadFile(path) // #nosec G304 -- repo-relative golden
	require.NoError(t, err, "missing corpus output golden; regenerate with -update")
	require.JSONEq(t, string(expected), string(actual),
		"corpus output changed; if intentional regenerate with: go test ./converters/hdf-to-asff/go/ -update")
}

// Types describes what the finding carries, not what the input had. A CVSS entry
// with no CVE id is dropped, so a requirement whose only CVSS entry is dropped
// must NOT claim the CVE taxonomy — otherwise the document says "vulnerability
// finding" while carrying no vulnerability. Pinned in both languages because the
// fixtures all have CVSS sources and so reach neither branch.
func TestConvertHDFToASFFTypesReflectsEmittedVulnerabilities(t *testing.T) {
	for _, tc := range []struct {
		name, cvss, wantType string
		wantVulns            bool
	}{
		{"cvss with a source keeps the CVE taxonomy", `[{"score":7.5,"source":"CVE-2024-1"}]`,
			"Software and Configuration Checks/Vulnerabilities/CVE", true},
		{"cvss without a source drops to the compliance taxonomy", `[{"score":7.5}]`,
			"Software and Configuration Checks", false},
		{"no cvss at all is a compliance finding", `[]`,
			"Software and Configuration Checks", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := []byte(`{"baselines":[{"name":"b","requirements":[{"id":"SV-1","title":"t","impact":0.5,` +
				`"descriptions":[{"label":"default","data":"d"}],"cvss":` + tc.cvss + `,` +
				`"results":[{"status":"failed","codeDesc":"c","startTime":"2020-01-01T00:00:00Z"}]}]}],` +
				`"generator":{"name":"x","version":"1"},"timestamp":"2020-01-01T00:00:00Z"}`)

			out, err := ConvertHDFToASFF(input, converterVersion)
			require.NoError(t, err)
			var doc struct {
				Findings []map[string]interface{} `json:"Findings"`
			}
			require.NoError(t, json.Unmarshal(out, &doc))
			require.NotEmpty(t, doc.Findings)

			types, _ := doc.Findings[0]["Types"].([]interface{})
			require.Len(t, types, 1)
			assert.Equal(t, tc.wantType, types[0])

			_, hasVulns := doc.Findings[0]["Vulnerabilities"]
			assert.Equal(t, tc.wantVulns, hasVulns,
				"Types and Vulnerabilities must agree about whether this is a vulnerability finding")
		})
	}
}
