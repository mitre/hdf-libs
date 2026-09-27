package oscal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xeipuuv/gojsonschema"
)

// sarWithProps is a minimal, schema-shaped assessment-results document carrying
// one finding (with its related observation and risk) whose props exercise
// carriage: a foreign-namespace prop, an HDF-namespaced prop the importer
// consumes, and a bare foreign prop with no ns.
const sarWithProps = `{
  "assessment-results": {
    "uuid": "11111111-1111-1111-1111-111111111111",
    "metadata": {"title": "t", "last-modified": "2023-05-10T00:00:00Z", "version": "1", "oscal-version": "1.1.2"},
    "import-ap": {"href": "#"},
    "results": [{
      "uuid": "22222222-2222-2222-2222-222222222222",
      "title": "r",
      "description": "d",
      "start": "2023-05-10T00:00:00Z",
      "reviewed-controls": {"control-selections": [{"include-all": {}}]},
      "findings": [{
        "uuid": "33333333-3333-3333-3333-333333333333",
        "title": "f",
        "description": "fd",
        "target": {"type": "objective-id", "target-id": "ac-1_obj", "status": {"state": "not-satisfied"}},
        "props": [
          {"name": "marking", "value": "CUI", "ns": "https://fedramp.gov/ns/oscal"},
          {"name": "hdf-requirement-id", "value": "V-1234", "ns": "https://mitre.github.io/hdf-libs/ns/oscal"},
          {"name": "bare", "value": "b1"}
        ],
        "related-observations": [{"observation-uuid": "44444444-4444-4444-4444-444444444444"}],
        "related-risks": [{"risk-uuid": "55555555-5555-5555-5555-555555555555"}]
      }],
      "observations": [{
        "uuid": "44444444-4444-4444-4444-444444444444",
        "description": "od",
        "methods": ["EXAMINE"],
        "collected": "2023-05-10T00:00:00Z",
        "props": [{"name": "obs-marking", "value": "internal", "ns": "https://fedramp.gov/ns/oscal", "class": "c1", "group": "g1", "uuid": "66666666-6666-6666-6666-666666666666", "remarks": "rk"}]
      }],
      "risks": [{
        "uuid": "55555555-5555-5555-5555-555555555555",
        "title": "rt",
        "description": "rd",
        "statement": "rs",
        "status": "open",
        "props": [{"name": "priority", "value": "high", "ns": "https://example.org/ns/oscal"}]
      }]
    }]
  }
}`

// requireCarriage returns the sole requirement's oscal-props entries from the
// import of sarWithProps.
func importCarriage(t *testing.T) []CarriedProp {
	t.Helper()
	results, err := ConvertAssessmentResultsToHDF([]byte(sarWithProps), "test")
	require.NoError(t, err)
	require.Len(t, results.Baselines, 1)
	require.Len(t, results.Baselines[0].Requirements, 1)
	entries := ReadCarriedProps(results.Baselines[0].Requirements[0].Tags)
	return entries
}

// AC: foreign-namespace and unconsumed props on a SAR finding survive import in
// oscal-props with on/name/value/ns intact, and the HDF-namespaced prop the
// importer consumes never appears.
func TestImportCarriesForeignFindingProp(t *testing.T) {
	entries := importCarriage(t)

	var finding []CarriedProp
	for _, e := range entries {
		if e.On == "finding" {
			finding = append(finding, e)
		}
	}
	require.Len(t, finding, 2, "finding carries the foreign and bare props, not the HDF prop")
	assert.Equal(t, CarriedProp{On: "finding", Name: "marking", Value: "CUI", Ns: "https://fedramp.gov/ns/oscal"}, finding[0])
	assert.Equal(t, CarriedProp{On: "finding", Name: "bare", Value: "b1"}, finding[1])

	for _, e := range entries {
		assert.NotEqual(t, "hdf-requirement-id", e.Name, "an HDF-namespaced prop must never be carried")
	}
}

// AC: props on the finding's related observation and risk are carried with the
// correct `on`, and every optional member (ns/class/group/uuid/remarks) is
// preserved exactly when the source prop has it.
func TestImportCarriesObservationAndRiskProps(t *testing.T) {
	entries := importCarriage(t)

	var obs, risk *CarriedProp
	for i := range entries {
		switch entries[i].On {
		case "observation":
			obs = &entries[i]
		case "risk":
			risk = &entries[i]
		}
	}
	require.NotNil(t, obs, "observation prop carried")
	require.NotNil(t, risk, "risk prop carried")

	assert.Equal(t, CarriedProp{
		On: "observation", Name: "obs-marking", Value: "internal",
		Ns: "https://fedramp.gov/ns/oscal", Class: "c1", Group: "g1",
		UUID: "66666666-6666-6666-6666-666666666666", Remarks: "rk",
	}, *obs)
	assert.Equal(t, CarriedProp{On: "risk", Name: "priority", Value: "high", Ns: "https://example.org/ns/oscal"}, *risk)
}

// AC: source order is preserved (finding entries first, then observation, then risk).
func TestImportCarriageSourceOrder(t *testing.T) {
	entries := importCarriage(t)
	require.Len(t, entries, 4)
	assert.Equal(t, []string{"finding", "finding", "observation", "risk"}, []string{entries[0].On, entries[1].On, entries[2].On, entries[3].On})
}

// AC: every oscal-props tag the importer produces validates against the shared JSON Schema.
func TestImportedCarriageValidatesAgainstSchema(t *testing.T) {
	results, err := ConvertAssessmentResultsToHDF([]byte(sarWithProps), "test")
	require.NoError(t, err)
	schema := loadOscalPropsSchema(t)
	for _, b := range results.Baselines {
		for _, req := range b.Requirements {
			raw, ok := req.Tags[OscalPropsTag]
			if !ok {
				continue
			}
			data, err := json.Marshal(raw)
			require.NoError(t, err)
			res, err := schema.Validate(gojsonschema.NewBytesLoader(data))
			require.NoError(t, err)
			assert.True(t, res.Valid(), "oscal-props for %s: %v", req.ID, res.Errors())
		}
	}
}

// AC: the real FedRAMP SAR fixture's foreign props are carried. The fixture
// carries FedRAMP-namespaced props on observations and risks; every carried
// entry keeps that namespace and its `on`, and every emitted tag is schema-valid.
func TestImportRealFedRAMPFixtureCarriesProps(t *testing.T) {
	input, err := os.ReadFile(filepath.Join("..", "fixtures", "input", "sar-fedramp.json"))
	require.NoError(t, err)
	results, err := ConvertAssessmentResultsToHDF(input, "test")
	require.NoError(t, err)

	schema := loadOscalPropsSchema(t)
	var total int
	for _, b := range results.Baselines {
		for _, req := range b.Requirements {
			entries := ReadCarriedProps(req.Tags)
			total += len(entries)
			for _, e := range entries {
				assert.NotEmpty(t, e.On, "on is required")
				assert.NotEmpty(t, e.Value, "value is required and verbatim")
				assert.NotEqual(t, VocabularyNamespace(), e.Ns, "HDF-namespaced props are never carried")
			}
			if raw, ok := req.Tags[OscalPropsTag]; ok {
				data, err := json.Marshal(raw)
				require.NoError(t, err)
				res, err := schema.Validate(gojsonschema.NewBytesLoader(data))
				require.NoError(t, err)
				assert.True(t, res.Valid(), "oscal-props for %s: %v", req.ID, res.Errors())
			}
		}
	}
	// The fixture carries FedRAMP-namespaced observation and risk props.
	assert.Positive(t, total, "the FedRAMP SAR fixture carries foreign props")
}

// AC (ADR-0014 §3.1): a recognised third-party vocabulary row carried under its
// owner's namespace is carried (consumed AND carried), so re-export reproduces
// it; the same name with no namespace is a legacy match — consumed, never
// carried. impacted-control-id is a legacy FedRAMP row, so it exercises both.
func TestCarryRecognisedThirdPartyProp(t *testing.T) {
	const fedrampNs = "https://fedramp.gov/ns/oscal"
	thirdParty := Property{Name: "impacted-control-id", Value: "ac-2", Ns: fedrampNs}
	legacy := Property{Name: "impacted-control-id", Value: "ac-2"}

	assert.False(t, ConsumedVocabularyProp(thirdParty), "a FedRAMP-namespaced impacted-control-id is a recognised third-party prop — carried, not consumed-only")
	assert.True(t, ConsumedVocabularyProp(legacy), "a no-namespace impacted-control-id is a legacy match — consumed and never carried")

	entries := CarryForeignProps(nil, "risk", []Property{thirdParty, legacy})
	require.Len(t, entries, 1, "the recognised third-party prop is carried; the legacy match is not")
	assert.Equal(t, CarriedProp{On: "risk", Name: "impacted-control-id", Value: "ac-2", Ns: fedrampNs}, entries[0])
}

func loadOscalPropsSchema(t *testing.T) *gojsonschema.Schema {
	t.Helper()
	path := filepath.Join("..", "..", "..", "shared", "oscal-props.schema.json")
	raw, err := os.ReadFile(path)
	require.NoError(t, err, "read oscal-props schema")
	schema, err := gojsonschema.NewSchema(gojsonschema.NewBytesLoader(raw))
	require.NoError(t, err, "load oscal-props schema")
	return schema
}
