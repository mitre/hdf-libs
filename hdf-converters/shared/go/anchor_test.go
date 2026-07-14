package shared

import (
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
