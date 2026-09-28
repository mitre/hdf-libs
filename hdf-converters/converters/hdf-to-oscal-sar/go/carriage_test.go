package hdftooscalsar

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	oscal "github.com/mitre/hdf-libs/hdf-converters/v3/converters/oscal-to-hdf/go"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hdfWithOscalProps builds an HDF Results document with one requirement whose
// tags carry the given oscal-props entries. impact and results are controllable
// so the emission of the observation and risk objects can be exercised.
func hdfWithOscalProps(t *testing.T, impact float64, withResults bool, entries string) []byte {
	t.Helper()
	results := ""
	if withResults {
		results = `"results": [{"status": "failed", "codeDesc": "c", "startTime": "2026-01-01T00:00:00Z"}],`
	}
	doc := `{
      "baselines": [{
        "name": "b",
        "requirements": [{
          "id": "AC-1",
          "impact": ` + jsonFloat(impact) + `,
          "title": "req",
          "tags": {"nist": ["AC-1"], "oscal-props": ` + entries + `},
          "descriptions": [{"label": "default", "data": "d"}],
          ` + results + `
          "impact_dummy": 0
        }]
      }]
    }`
	// impact_dummy keeps a trailing comma harmless when results is empty; strip it.
	doc = strings.Replace(doc, `,
          "impact_dummy": 0`, ``, 1)
	return []byte(doc)
}

func jsonFloat(f float64) string {
	b, _ := json.Marshal(f)
	return string(b)
}

func exportRequirement(t *testing.T, in []byte) oscal.AssessmentResults {
	t.Helper()
	out, err := ConvertHDFToOSCALSAR(in, "1.0.0")
	require.NoError(t, err)
	var doc oscalSARDocument
	require.NoError(t, json.Unmarshal(out, &doc))
	return doc.AssessmentResults
}

// AC: re-emitting carried props on finding, observation and risk keeps the
// output valid against both vendored OSCAL AR schemas (1.1.2 and 1.2.3).
func TestReemittedCarriageValidatesAgainstSchemas(t *testing.T) {
	in := hdfWithOscalProps(t, 0.5, true, `[
      {"on": "finding", "name": "marking", "value": "CUI", "ns": "https://fedramp.gov/ns/oscal"},
      {"on": "observation", "name": "scan-percentage", "value": "100", "ns": "https://fedramp.gov/ns/oscal", "class": "c", "group": "g", "remarks": "r"},
      {"on": "risk", "name": "priority", "value": "high", "ns": "https://fedramp.gov/ns/oscal"}
    ]`)
	for _, file := range arSchemaFiles {
		requireValidAR(t, arSchemaFor(t, file), file, in)
	}
}

// AC §3.4: on:finding entries go on the finding, after its own props.
func TestReemitFindingPropsAfterOwnProps(t *testing.T) {
	in := hdfWithOscalProps(t, 0.5, true, `[{"on": "finding", "name": "marking", "value": "CUI", "ns": "https://fedramp.gov/ns/oscal"}]`)
	sar := exportRequirement(t, in)
	require.Len(t, sar.Results, 1)
	require.Len(t, sar.Results[0].Findings, 1)
	props := sar.Results[0].Findings[0].Props

	// Own props (hdf-requirement-id, nist) come first; the carried prop is last.
	require.NotEmpty(t, props)
	assert.Equal(t, "hdf-requirement-id", props[0].Name, "own props emitted first")
	last := props[len(props)-1]
	assert.Equal(t, "marking", last.Name)
	assert.Equal(t, "CUI", last.Value)
	assert.Equal(t, "https://fedramp.gov/ns/oscal", last.Ns)
}

// AC §3.4: on:observation entries go on the requirement's observation.
func TestReemitObservationProps(t *testing.T) {
	in := hdfWithOscalProps(t, 0.5, true, `[{"on": "observation", "name": "scan-percentage", "value": "100", "ns": "https://fedramp.gov/ns/oscal"}]`)
	sar := exportRequirement(t, in)
	require.Len(t, sar.Results[0].Observations, 1)
	props := sar.Results[0].Observations[0].Props
	require.Len(t, props, 1)
	assert.Equal(t, "scan-percentage", props[0].Name)
	assert.Equal(t, "https://fedramp.gov/ns/oscal", props[0].Ns)
}

// AC §3.4: on:risk entries go on the one risk the exporter emits.
func TestReemitRiskProps(t *testing.T) {
	in := hdfWithOscalProps(t, 0.5, true, `[{"on": "risk", "name": "priority", "value": "high", "ns": "https://fedramp.gov/ns/oscal"}]`)
	sar := exportRequirement(t, in)
	require.Len(t, sar.Results[0].Risks, 1)
	props := sar.Results[0].Risks[0].Props
	require.Len(t, props, 1)
	assert.Equal(t, "priority", props[0].Name)
}

// AC §3.4: an entry whose object the exporter does not emit (no observation,
// because the requirement has no results) is not re-emitted anywhere.
func TestObservationEntriesNotReemittedWithoutObservation(t *testing.T) {
	in := hdfWithOscalProps(t, 0.5, false, `[{"on": "observation", "name": "scan-percentage", "value": "100", "ns": "https://fedramp.gov/ns/oscal"}]`)
	out, err := ConvertHDFToOSCALSAR(in, "1.0.0")
	require.NoError(t, err)
	sar := exportRequirement(t, in)
	assert.Empty(t, sar.Results[0].Observations, "no results, so no observation")
	assert.NotContains(t, string(out), "scan-percentage", "the observation entry is not re-emitted")
}

// AC §3.4: an on:risk entry is not re-emitted when the requirement's impact is 0,
// so no risk is emitted.
func TestRiskEntriesNotReemittedWithoutRisk(t *testing.T) {
	in := hdfWithOscalProps(t, 0, true, `[{"on": "risk", "name": "priority", "value": "high", "ns": "https://fedramp.gov/ns/oscal"}]`)
	out, err := ConvertHDFToOSCALSAR(in, "1.0.0")
	require.NoError(t, err)
	sar := exportRequirement(t, in)
	assert.Empty(t, sar.Results[0].Risks, "impact 0, so no risk")
	assert.NotContains(t, string(out), `"priority"`, "the risk entry is not re-emitted")
}

// AC §3.4: two carried entries with the same (ns, name, value) are emitted once.
func TestReemitDedupesIdenticalEntries(t *testing.T) {
	in := hdfWithOscalProps(t, 0.5, true, `[
      {"on": "risk", "name": "priority", "value": "high", "ns": "https://fedramp.gov/ns/oscal"},
      {"on": "risk", "name": "priority", "value": "high", "ns": "https://fedramp.gov/ns/oscal"}
    ]`)
	sar := exportRequirement(t, in)
	assert.Len(t, sar.Results[0].Risks[0].Props, 1, "identical carried entries dedupe")
}

// AC §3.4: an absent ns compares equal to NIST's default namespace when deduping.
func TestReemitDedupTreatsAbsentNsAsNistDefault(t *testing.T) {
	nist := oscal.VocabularyDefaultNamespace()
	in := hdfWithOscalProps(t, 0.5, true, `[
      {"on": "risk", "name": "foo", "value": "bar", "ns": "`+nist+`"},
      {"on": "risk", "name": "foo", "value": "bar"}
    ]`)
	sar := exportRequirement(t, in)
	assert.Len(t, sar.Results[0].Risks[0].Props, 1, "absent ns == NIST default, so deduped")
}

// AC §3.5: convergence from the RAW third-party SAR. OSCAL → HDF → OSCAL → HDF →
// OSCAL is stable: the first HDF-produced export equals the second after masking
// volatile uuids and timestamps. observation.description idempotency closed the
// last gap that once forced this to start from the first HDF-produced export.
func TestConvergenceCarriesForeignProps(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(shared.GetConvertersDir(), "oscal-to-hdf", "fixtures", "input", "sar-fedramp.json"))
	require.NoError(t, err)

	roundTrip := func(oscalDoc []byte) []byte {
		hdfDoc, err := oscal.ConvertAssessmentResultsToHDF(oscalDoc, "test")
		require.NoError(t, err)
		hdfBytes, err := json.Marshal(hdfDoc)
		require.NoError(t, err)
		out, err := ConvertHDFToOSCALSAR(hdfBytes, "test")
		require.NoError(t, err)
		return out
	}

	export1 := roundTrip(raw) // first HDF-produced OSCAL SAR
	export2 := roundTrip(export1)

	// Foreign FedRAMP props survive round-tripping.
	assert.Contains(t, string(export1), "https://fedramp.gov/ns/oscal", "foreign namespace survives")
	assert.Contains(t, string(export1), `"priority"`, "a carried FedRAMP prop is re-emitted")

	vk := []string{"last-modified"}
	m1, err := shared.MaskVolatileJSON(export1, vk)
	require.NoError(t, err)
	m2, err := shared.MaskVolatileJSON(export2, vk)
	require.NoError(t, err)
	assert.Equal(t, m1, m2, "OSCAL→HDF→OSCAL→HDF→OSCAL converges")
}
