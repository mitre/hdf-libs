package shared

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCountXMLElements(t *testing.T) {
	xml := []byte(`<Benchmark><Group><Rule id="1"></Rule><Rule id="2"/></Group><Rule id="3"/><RuleResult/></Benchmark>`)
	assert.Equal(t, 3, CountXMLElements(t, xml, "Rule"), "counts open <Rule> tags, not </Rule> or <RuleResult>")
	assert.Equal(t, 0, CountXMLElements(t, xml, "rule-result"))

	rr := []byte(`<a><rule-result/><rule-result/></a>`)
	assert.Equal(t, 2, CountXMLElements(t, rr, "rule-result"), "hyphenated element names")
}

// A non-UTF-8 encoding declaration (e.g. veracode.xml is ISO-8859-1) must not
// error the decoder — the CharsetReader passes bytes through since we only count
// ASCII element names.
func TestCountXMLElements_NonUTF8Encoding(t *testing.T) {
	in := []byte(`<?xml version="1.0" encoding="ISO-8859-1"?><a><Rule/><Rule/></a>`)
	assert.Equal(t, 2, CountXMLElements(t, in, "Rule"))
}

func TestCountJSONItemsUnderKey(t *testing.T) {
	j := []byte(`{"groups":[{"controls":[{"id":"a","controls":[{"id":"a.1"}]},{"id":"b"}]}]}`)
	assert.Equal(t, 3, CountJSONItemsUnderKey(t, j, "controls"), "counts nested controls at any depth: a, b, a.1")
	assert.Equal(t, 0, CountJSONItemsUnderKey(t, j, "missing"))
}

func TestTotalRequirementsBothShapes(t *testing.T) {
	results := map[string]interface{}{
		"baselines": []interface{}{
			map[string]interface{}{"requirements": []interface{}{struct{}{}, struct{}{}}},
		},
	}
	assert.Equal(t, 2, TotalRequirements(t, results), "HDFResults: baselines[].requirements")

	baseline := map[string]interface{}{"requirements": []interface{}{struct{}{}, struct{}{}, struct{}{}}}
	assert.Equal(t, 3, TotalRequirements(t, baseline), "HDFBaseline: top-level requirements")
}

func TestAssertRequirementCount(t *testing.T) {
	baseline := map[string]interface{}{"requirements": []interface{}{struct{}{}, struct{}{}}}
	AssertRequirementCount(t, baseline, 2, "happy path")
}

func TestTotalResultsBothShapes(t *testing.T) {
	results := map[string]interface{}{
		"baselines": []interface{}{
			map[string]interface{}{"requirements": []interface{}{
				map[string]interface{}{"results": []interface{}{struct{}{}, struct{}{}}},
				map[string]interface{}{"results": []interface{}{struct{}{}}},
			}},
		},
	}
	assert.Equal(t, 3, TotalResults(t, results), "HDFResults: baselines[].requirements[].results")

	baseline := map[string]interface{}{"requirements": []interface{}{
		map[string]interface{}{"results": []interface{}{struct{}{}}},
		map[string]interface{}{},
	}}
	assert.Equal(t, 1, TotalResults(t, baseline), "top-level requirements[].results; a requirement with none counts zero")
}

// The result anchor must count from the emitted document generically, never
// through a converter's typed structs (the independence rule at the head of
// anchor.go): a raw JSON document it has never seen a type for counts the same.
func TestTotalResultsCountsRawJSONIndependentOfConverterTypes(t *testing.T) {
	raw := json.RawMessage(`{
	  "baselines": [
	    {"requirements": [
	      {"id": "Grype/CVE-2022-48174", "results": [{"codeDesc": "busybox"}, {"codeDesc": "ssl_client"}]},
	      {"id": "Grype/CVE-2022-28391", "results": [{"codeDesc": "busybox"}]}
	    ]},
	    {"requirements": [{"id": "Grype/CVE-2022-48174", "results": [{"codeDesc": "other host"}]}]}
	  ]
	}`)
	assert.Equal(t, 4, TotalResults(t, raw), "four findings over three requirements in two baselines")
	AssertResultCount(t, raw, 4, "raw findings in the source")
}

func TestAssertResultCount(t *testing.T) {
	doc := map[string]interface{}{"requirements": []interface{}{
		map[string]interface{}{"results": []interface{}{struct{}{}, struct{}{}}},
	}}
	AssertResultCount(t, doc, 2, "happy path")
}

func TestAssertOverrideCount(t *testing.T) {
	amendments := map[string]interface{}{"overrides": []interface{}{struct{}{}, struct{}{}, struct{}{}}}
	assert.Equal(t, 3, TotalOverrides(t, amendments))
	AssertOverrideCount(t, amendments, 3, "override count")
}
