package hdftooscalsar

import (
	"encoding/json"
	"testing"

	oscal "github.com/mitre/hdf-libs/hdf-converters/v3/converters/oscal-to-hdf/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// identityTitlesInput builds a one-baseline, one-requirement, one-component HDF
// Results document whose component name, baseline title and requirement title
// carry the given values. Each is an identity/prose value the importer reads
// back from the OSCAL single-line title sink it lands in.
func identityTitlesInput(compName, baselineTitle, reqTitle string) []byte {
	return []byte(`{
		"baselines": [{
			"name": "b",
			"title": ` + jsonString(baselineTitle) + `,
			"requirements": [{
				"id": "AC-1", "impact": 0.5, "title": ` + jsonString(reqTitle) + `,
				"tags": { "nist": ["AC-1"] },
				"descriptions": [{ "label": "default", "data": "d" }],
				"results": [{ "status": "passed", "codeDesc": "c", "startTime": "2026-01-01T00:00:00Z" }]
			}]
		}],
		"components": [{ "type": "host", "name": ` + jsonString(compName) + `,
			"componentId": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d" }]
	}`)
}

// roundTripIdentityTitles converts the input to SAR and back, returning the
// recovered component name, baseline title and requirement title.
func roundTripIdentityTitles(t *testing.T, input []byte) (compName, baselineTitle, reqTitle string) {
	t.Helper()
	sar, err := ConvertHDFToOSCALSAR(input, "1.0.0")
	require.NoError(t, err)
	back, err := oscal.ConvertAssessmentResultsToHDF(sar, "1.0.0")
	require.NoError(t, err)
	require.Len(t, back.Components, 1, "the component must reconstitute")
	require.Len(t, back.Baselines, 1)
	require.Len(t, back.Baselines[0].Requirements, 1)
	require.NotNil(t, back.Baselines[0].Title, "baseline title must be present")
	require.NotNil(t, back.Baselines[0].Requirements[0].Title, "requirement title must be present")
	return back.Components[0].Name, *back.Baselines[0].Title, *back.Baselines[0].Requirements[0].Title
}

// TestSARIdentityTitles_NewlineRoundTripsAndValidates is the card's first-failing
// test: a component name, a baseline title and a requirement title that each
// carry a line terminator must convert to a SAR valid on OSCAL AR 1.1.2 AND
// 1.2.3, and HDF -> SAR -> HDF must return each value byte-exact. On main the
// values landed in single-line title sinks with no prop home, so 1.2.3 rejected
// the document (or normalizing the title silently lost the value).
func TestSARIdentityTitles_NewlineRoundTripsAndValidates(t *testing.T) {
	const compName = "web\n01"
	const baselineTitle = "RHEL 9 STIG\nHost A"
	const reqTitle = "Session lock\nmust be enabled"
	input := identityTitlesInput(compName, baselineTitle, reqTitle)

	for _, file := range arSchemaFiles {
		requireValidAR(t, arSchemaFor(t, file), file, input)
	}

	gotComp, gotBaseline, gotReq := roundTripIdentityTitles(t, input)
	assert.Equal(t, compName, gotComp, "component name must round-trip byte-exact")
	assert.Equal(t, baselineTitle, gotBaseline, "baseline title must round-trip byte-exact")
	assert.Equal(t, reqTitle, gotReq, "requirement title must round-trip byte-exact")
}

// TestSARIdentityTitles_EdgeCasesRoundTrip covers the other §1.7 shapes: CR,
// U+2028, U+2029, and edge whitespace — each applied to all three sinks at once
// — plus an already-valid single-line value that must survive unchanged. Every
// case must validate on both vendored schemas and round-trip byte-exact.
func TestSARIdentityTitles_EdgeCasesRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
	}{
		{"carriage return", "a\rb"},
		{"CRLF", "a\r\nb"},
		{"line separator U+2028", "a b"},
		{"paragraph separator U+2029", "a b"},
		{"leading and trailing whitespace", "  padded  "},
		{"interior run of terminators", "a\n\n\nb"},
		{"already valid unchanged", "Access Control 2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := identityTitlesInput(tc.value, tc.value, tc.value)
			for _, file := range arSchemaFiles {
				requireValidAR(t, arSchemaFor(t, file), file, input)
			}
			gotComp, gotBaseline, gotReq := roundTripIdentityTitles(t, input)
			assert.Equal(t, tc.value, gotComp, "component name")
			assert.Equal(t, tc.value, gotBaseline, "baseline title")
			assert.Equal(t, tc.value, gotReq, "requirement title")
		})
	}
}

// TestSARIdentityTitles_DisplaySinksNormalizedExactInProps asserts the two-part
// treatment (§1.7.1 display + §1.7.2 exact home): the display title sinks
// (assessment-subject title, result title, finding title) are normalized so no
// line terminator reaches them, while the exact value is preserved in the
// HDF-namespaced prop's remarks.
func TestSARIdentityTitles_DisplaySinksNormalizedExactInProps(t *testing.T) {
	const compName = "web\n01"
	const baselineTitle = "RHEL 9 STIG\nHost A"
	const reqTitle = "Session lock\nmust be enabled"
	input := identityTitlesInput(compName, baselineTitle, reqTitle)

	sar := sarDoc(t, input)
	require.Len(t, sar.Results, 1)
	result := sar.Results[0]

	// Result title: normalized display, exact value in the baseline-title prop.
	assert.Equal(t, "RHEL 9 STIG Host A", result.Title, "result title is normalized display text")
	baselineTitleProps := propsNamed(result.Props, "baseline-title")
	require.Len(t, baselineTitleProps, 1)
	assert.Equal(t, "RHEL 9 STIG Host A", baselineTitleProps[0].Value, "value is normalized (§1.7.1)")
	assert.Equal(t, baselineTitle, baselineTitleProps[0].Remarks, "remarks carries the exact title (§1.7.2)")
	assert.Equal(t, oscal.VocabularyNamespace(), baselineTitleProps[0].Ns)

	// Finding title: normalized display, exact value in the requirement-title prop.
	require.Len(t, result.Findings, 1)
	finding := result.Findings[0]
	assert.Equal(t, "Session lock must be enabled", finding.Title, "finding title is normalized display text")
	reqTitleProps := propsNamed(finding.Props, "requirement-title")
	require.Len(t, reqTitleProps, 1)
	assert.Equal(t, reqTitle, reqTitleProps[0].Remarks, "remarks carries the exact requirement title (§1.7.2)")
	assert.Equal(t, oscal.VocabularyNamespace(), reqTitleProps[0].Ns)

	// Subject title: normalized display, exact value in the component-name prop.
	require.Len(t, result.Observations, 1)
	require.Len(t, result.Observations[0].Subjects, 1)
	subj := result.Observations[0].Subjects[0]
	assert.Equal(t, "web 01", subj.Title, "subject title is normalized display text")
	compNameProps := propsNamed(subj.Props, "component-name")
	require.Len(t, compNameProps, 1)
	assert.Equal(t, compName, compNameProps[0].Remarks, "remarks carries the exact component name (§1.7.2)")
	assert.Equal(t, oscal.VocabularyNamespace(), compNameProps[0].Ns)
}

// TestSARIdentityTitles_AlreadyValueEmitsNoRemarks pins that an already-valid
// single-line value carries no remarks — only the value — so no golden churn
// beyond the added props.
func TestSARIdentityTitles_AlreadyValueEmitsNoRemarks(t *testing.T) {
	input := identityTitlesInput("web01", "RHEL 9 STIG", "Session lock")
	sar := sarDoc(t, input)

	bt := propsNamed(sar.Results[0].Props, "baseline-title")
	require.Len(t, bt, 1)
	assert.Equal(t, "RHEL 9 STIG", bt[0].Value)
	assert.Empty(t, bt[0].Remarks)

	rt := propsNamed(sar.Results[0].Findings[0].Props, "requirement-title")
	require.Len(t, rt, 1)
	assert.Equal(t, "Session lock", rt[0].Value)
	assert.Empty(t, rt[0].Remarks)

	cn := propsNamed(sar.Results[0].Observations[0].Subjects[0].Props, "component-name")
	require.Len(t, cn, 1)
	assert.Equal(t, "web01", cn[0].Value)
	assert.Empty(t, cn[0].Remarks)
}

// TestSARIdentityTitles_ForeignFallback pins no regression for foreign SARs: a
// document with no HDF-namespaced identity prop still imports the component name
// from the subject title, the baseline title from the result title, and the
// requirement title from the finding title, exactly as before this card.
func TestSARIdentityTitles_ForeignFallback(t *testing.T) {
	foreign := []byte(`{
		"assessment-results": {
			"uuid": "11111111-1111-4111-8111-111111111111",
			"metadata": { "title": "t", "last-modified": "2026-01-01T00:00:00Z", "version": "1", "oscal-version": "1.1.2" },
			"import-ap": { "href": "#" },
			"results": [{
				"uuid": "22222222-2222-4222-8222-222222222222",
				"title": "Foreign Baseline",
				"description": "d",
				"start": "2026-01-01T00:00:00Z",
				"reviewed-controls": { "control-selections": [{ "include-all": {} }] },
				"findings": [{
					"uuid": "33333333-3333-4333-8333-333333333333",
					"title": "Foreign Requirement",
					"description": "d",
					"target": { "type": "objective-id", "target-id": "ac-1", "status": { "state": "satisfied" } },
					"related-observations": [{ "observation-uuid": "44444444-4444-4444-8444-444444444444" }]
				}],
				"observations": [{
					"uuid": "44444444-4444-4444-8444-444444444444",
					"description": "d",
					"methods": ["TEST"],
					"collected": "2026-01-01T00:00:00Z",
					"subjects": [{ "subject-uuid": "55555555-5555-4555-8555-555555555555", "type": "host", "title": "web01" }]
				}]
			}]
		}
	}`)

	back, err := oscal.ConvertAssessmentResultsToHDF(foreign, "1.0.0")
	require.NoError(t, err)
	require.Len(t, back.Components, 1)
	assert.Equal(t, "web01", back.Components[0].Name, "foreign component name comes from the subject title")
	require.Len(t, back.Baselines, 1)
	require.NotNil(t, back.Baselines[0].Title)
	assert.Equal(t, "Foreign Baseline", *back.Baselines[0].Title, "foreign baseline title comes from the result title")
	require.Len(t, back.Baselines[0].Requirements, 1)
	require.NotNil(t, back.Baselines[0].Requirements[0].Title)
	assert.Equal(t, "Foreign Requirement", *back.Baselines[0].Requirements[0].Title, "foreign requirement title comes from the finding title")

	// A foreign document carries none of the HDF identity props.
	var doc struct {
		AR oscal.AssessmentResults `json:"assessment-results"`
	}
	require.NoError(t, json.Unmarshal(foreign, &doc))
	assert.Empty(t, propsNamed(doc.AR.Results[0].Props, "baseline-title"))
}
