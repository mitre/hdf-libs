package oscal_test

import (
	"fmt"
	"strings"
	"testing"

	oscal "github.com/mitre/hdf-libs/hdf-converters/v3/converters/oscal-to-hdf/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// componentRoundTripValues are the set→get values a field cannot take from the
// generic "value-<prop>" pattern because its HDF field is not a string.
var componentRoundTripValues = map[string]string{"component-port": "8443"}

func componentPropValue(prop string) string {
	if v, ok := componentRoundTripValues[prop]; ok {
		return v
	}
	return "value-" + prop
}

// componentVocabularyFields returns the HDF field every components[] vocabulary
// row carries, in table order (ADR-0014 §1.5).
func componentVocabularyFields(t *testing.T) ([]string, map[string]string) {
	t.Helper()
	var order []string
	fields := map[string]string{}
	for _, r := range oscal.VocabularyRows() {
		if r.HDFField == nil || !strings.HasPrefix(*r.HDFField, "components[].") {
			continue
		}
		order = append(order, r.Name)
		fields[r.Name] = *r.HDFField
	}
	require.NotEmpty(t, order)
	return order, fields
}

func TestComponentPropTableMatchesVocabulary(t *testing.T) {
	want, fields := componentVocabularyFields(t)

	var got []string
	for _, e := range oscal.ComponentPropTable() {
		got = append(got, e.Prop)
		assert.Equal(t, "components[]."+e.Field, fields[e.Prop],
			"table entry %q must name the HDF field its vocabulary row carries", e.Prop)
	}
	for _, g := range oscal.ComponentGroupPropTable() {
		got = append(got, g.KeyProp(), g.ValueProp())
		assert.Equal(t, fmt.Sprintf("components[].%s (key)", g.Field), fields[g.KeyProp()],
			"group entry %q must name the HDF field its vocabulary row carries", g.KeyProp())
		assert.Equal(t, fmt.Sprintf("components[].%s (value)", g.Field), fields[g.ValueProp()],
			"group entry %q must name the HDF field its vocabulary row carries", g.ValueProp())
	}

	assert.Equal(t, want, got,
		"the component prop table must cover every components[] vocabulary row, exactly once, in the vocabulary's order")
}

func TestComponentPropTable_EveryEntryRoundTripsAValue(t *testing.T) {
	var c hdf.Component
	table := oscal.ComponentPropTable()
	require.NotEmpty(t, table)
	for _, e := range table {
		e.Set(&c, componentPropValue(e.Prop))
	}
	for _, e := range table {
		v := e.Get(&c)
		require.NotNil(t, v, "%s: the getter reads nothing back after the setter wrote a value", e.Prop)
		assert.Equal(t, componentPropValue(e.Prop), *v, "%s: set→get is not the identity", e.Prop)
	}

	for _, g := range oscal.ComponentGroupPropTable() {
		var gc hdf.Component
		m := map[string]string{"k1": "v1", "k2": "v2"}
		g.Set(&gc, m)
		assert.Equal(t, m, g.Get(&gc), "%s: set→get is not the identity", g.Prefix)
	}
}

func TestComponentPropTable_TablesAreCopies(t *testing.T) {
	table := oscal.ComponentPropTable()
	table[0].Prop = "mutated"
	assert.NotEqual(t, "mutated", oscal.ComponentPropTable()[0].Prop)

	groups := oscal.ComponentGroupPropTable()
	groups[0].Prefix = "mutated"
	assert.NotEqual(t, "mutated", oscal.ComponentGroupPropTable()[0].Prefix)
}

func TestComponentSubjectProps_RoundTripsEveryField(t *testing.T) {
	var c hdf.Component
	for _, e := range oscal.ComponentPropTable() {
		e.Set(&c, componentPropValue(e.Prop))
	}
	for _, g := range oscal.ComponentGroupPropTable() {
		g.Set(&c, map[string]string{"k2": "v2", "k1": "v1"})
	}

	var back hdf.Component
	oscal.ReadComponentSubjectProps(&back, oscal.ComponentSubjectProps(&c))
	assert.Equal(t, c, back)
}

func TestComponentSubjectProps_CarriesAnEmptyOptionalFieldAsAMarker(t *testing.T) {
	c := hdf.Component{Name: "web01"}
	empty := ""
	c.Hostname = &empty

	props := oscal.ComponentSubjectProps(&c)
	assert.True(t, oscal.HasFieldMarker(props, "empty-field", "hostname", ""))

	var back hdf.Component
	oscal.ReadComponentSubjectProps(&back, props)
	require.NotNil(t, back.Hostname)
	assert.Equal(t, "", *back.Hostname)
	assert.Nil(t, back.FQDN, "an absent field stays absent")
}

func TestComponentSubjectProps_OmitsAnEmptyRequiredField(t *testing.T) {
	props := oscal.ComponentSubjectProps(&hdf.Component{})
	assert.Empty(t, props, "an empty required field is carried by omitting its prop, not by a marker")

	var back hdf.Component
	oscal.ReadComponentSubjectProps(&back, props)
	assert.Equal(t, "", back.Name)
}

func TestComponentSubjectProps_GroupsMapEntriesInSortedKeyOrder(t *testing.T) {
	c := hdf.Component{Name: "web01", Labels: map[string]string{"zone": "b", "environment": ""}}

	props := oscal.ComponentSubjectProps(&c)
	var groups []string
	for _, p := range props {
		if p.Group != "" {
			groups = append(groups, p.Group+"/"+p.Name+"="+p.Value)
		}
	}
	assert.Equal(t, []string{
		"component-label-1/component-label-key=environment",
		"component-label-1/empty-field=value",
		"component-label-2/component-label-key=zone",
		"component-label-2/component-label-value=b",
	}, groups)

	var back hdf.Component
	oscal.ReadComponentSubjectProps(&back, props)
	assert.Equal(t, c.Labels, back.Labels)
}
