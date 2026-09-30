package oscal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
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
	return ReadCarriedProps(results.Baselines[0].Requirements[0].Tags, results.Baselines[0].Requirements[0].ID)
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
			entries := ReadCarriedProps(req.Tags, req.ID)
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

// tagsFromJSON decodes an HDF requirement's tags the way the reader leaves them.
func tagsFromJSON(t *testing.T, raw string) map[string]interface{} {
	t.Helper()
	var tags map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(raw), &tags))
	return tags
}

// readCarriageWithLog reads the tag and returns the entries plus everything logged.
func readCarriageWithLog(t *testing.T, tags map[string]interface{}, requirementID string) ([]CarriedProp, string) {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)
	return ReadCarriedProps(tags, requirementID), buf.String()
}

// AC (ADR-0014 §3.3): carriage is per-entry tolerant — one malformed entry must
// not erase the rest of the requirement's carried props, and the drop is reported
// once for the requirement rather than silently.
func TestReadCarriedPropsKeepsValidEntriesWhenOneIsMalformed(t *testing.T) {
	tags := tagsFromJSON(t, `{"oscal-props":[
		{"on":"finding","name":"a","value":"1"},
		{"on":"finding","name":"b","value":"2","ns":42}]}`)

	entries, logged := readCarriageWithLog(t, tags, "V-1234")
	require.Len(t, entries, 1, "the valid entry survives a malformed sibling")
	assert.Equal(t, CarriedProp{On: "finding", Name: "a", Value: "1"}, entries[0])
	assert.Contains(t, logged, `WARNING: Dropping 1 malformed oscal-props entry on requirement "V-1234"`)
	assert.Equal(t, 1, strings.Count(logged, "WARNING:"), "one warning per requirement, not one per entry")
}

// AC: several malformed entries still produce exactly one warning, naming the count.
func TestReadCarriedPropsWarnsOncePerRequirementWithTheDroppedCount(t *testing.T) {
	tags := tagsFromJSON(t, `{"oscal-props":[
		{"on":"task","name":"a","value":"1"},
		{"on":"finding","name":"b","value":"2","remarks":true},
		{"on":"risk","name":"ok","value":"3"}]}`)

	entries, logged := readCarriageWithLog(t, tags, "AC-1")
	require.Len(t, entries, 1)
	assert.Equal(t, CarriedProp{On: "risk", Name: "ok", Value: "3"}, entries[0])
	assert.Contains(t, logged, `WARNING: Dropping 2 malformed oscal-props entries on requirement "AC-1"`)
	assert.Equal(t, 1, strings.Count(logged, "WARNING:"))
}

// AC: a well-formed tag is read without a warning.
func TestReadCarriedPropsIsSilentForAWellFormedTag(t *testing.T) {
	tags := tagsFromJSON(t, `{"oscal-props":[{"on":"finding","name":"a","value":"1"}]}`)
	entries, logged := readCarriageWithLog(t, tags, "AC-1")
	require.Len(t, entries, 1)
	assert.Empty(t, logged)
}

// AC: an absent tag is not a drop, so it warns nothing.
func TestReadCarriedPropsIsSilentWhenTheTagIsAbsent(t *testing.T) {
	entries, logged := readCarriageWithLog(t, tagsFromJSON(t, `{"nist":["AC-1"]}`), "AC-1")
	assert.Empty(t, entries)
	assert.Empty(t, logged)
}

// AC: a tag that is not an array carries nothing, and says so.
func TestReadCarriedPropsWarnsWhenTheTagIsNotAnArray(t *testing.T) {
	for _, raw := range []string{`{"oscal-props":{"on":"finding"}}`, `{"oscal-props":"finding"}`, `{"oscal-props":null}`} {
		entries, logged := readCarriageWithLog(t, tagsFromJSON(t, raw), "AC-1")
		assert.Empty(t, entries, raw)
		assert.Contains(t, logged, `WARNING: Dropping the oscal-props tag on requirement "AC-1": it is not an array`, raw)
	}
}

type carriageCase struct {
	Label string      `json:"label"`
	Entry interface{} `json:"entry"`
	Valid bool        `json:"valid"`
	Why   string      `json:"why"`
}

func loadCarriageCases(t *testing.T) []carriageCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "shared", "oscal-carriage-cases.json"))
	require.NoError(t, err)
	var table struct {
		Cases []carriageCase `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &table))
	require.NotEmpty(t, table.Cases, "an empty table would pass vacuously")
	return table.Cases
}

// AC: the predicate that decides whether an entry is carried agrees with
// shared/oscal-props.schema.json for every case in the shared table, so the two
// languages' read paths cannot drift from the shape the schema pins.
func TestCarriagePredicateAgreesWithTheOscalPropsSchema(t *testing.T) {
	schema := loadOscalPropsSchema(t)
	for _, c := range loadCarriageCases(t) {
		t.Run(c.Label, func(t *testing.T) {
			data, err := json.Marshal([]interface{}{c.Entry})
			require.NoError(t, err)
			res, err := schema.Validate(gojsonschema.NewBytesLoader(data))
			require.NoError(t, err)
			assert.Equal(t, c.Valid, res.Valid(), "the shared table's verdict must be the schema's: %s", c.Why)
			assert.Equal(t, c.Valid, ValidCarriedProp(c.Entry), "the predicate must match the schema: %s", c.Why)
		})
	}
}

// AC: the read path keeps exactly the entries the predicate accepts.
func TestReadCarriedPropsKeepsExactlyTheSharedTablesValidEntries(t *testing.T) {
	cases := loadCarriageCases(t)
	list := make([]interface{}, 0, len(cases))
	want := 0
	for _, c := range cases {
		list = append(list, c.Entry)
		if c.Valid {
			want++
		}
	}
	data, err := json.Marshal(map[string]interface{}{OscalPropsTag: list})
	require.NoError(t, err)

	entries, logged := readCarriageWithLog(t, tagsFromJSON(t, string(data)), "AC-1")
	assert.Len(t, entries, want)
	assert.Contains(t, logged, fmt.Sprintf(`WARNING: Dropping %d malformed oscal-props entries on requirement "AC-1"`, len(cases)-want))
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

// An empty optional is absent: neither the tag entry nor the re-emitted prop
// carries an ns/class/group/uuid/remarks member for "", matching the TS peer.
func TestCarriageTreatsAnEmptyOptionalAsAbsent(t *testing.T) {
	entries := CarryForeignProps(nil, "finding", []Property{{Name: "a", Value: "1", Ns: "", Remarks: ""}})
	require.Len(t, entries, 1)
	tagJSON, err := json.Marshal(entries)
	require.NoError(t, err)
	assert.NotContains(t, string(tagJSON), `"ns"`)
	assert.NotContains(t, string(tagJSON), `"remarks"`)

	tags := map[string]interface{}{OscalPropsTag: []interface{}{
		map[string]interface{}{"on": "finding", "name": "a", "value": "1", "ns": "", "remarks": ""},
	}}
	read := ReadCarriedProps(tags, "V-1")
	require.Len(t, read, 1)
	props := AppendCarriedProps(nil, CarriedFor(read, "finding"))
	propJSON, err := json.Marshal(props)
	require.NoError(t, err)
	assert.NotContains(t, string(propJSON), `"ns"`)
	assert.NotContains(t, string(propJSON), `"remarks"`)
}
