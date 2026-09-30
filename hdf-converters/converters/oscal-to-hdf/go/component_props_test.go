package oscal_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	oscal "github.com/mitre/hdf-libs/hdf-converters/v3/converters/oscal-to-hdf/go"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// componentRoundTripValues are the set→get values a field cannot take from the
// generic "value-<prop>" pattern because its HDF field is not a string, or is a
// closed enum the accessor validates against.
var componentRoundTripValues = map[string]string{"component-port": "8443", "component-provider": "aws"}

func componentPropEntry(t *testing.T, prop string) oscal.ComponentProp {
	t.Helper()
	for _, e := range oscal.ComponentPropTable() {
		if e.Prop == prop {
			return e
		}
	}
	require.FailNow(t, "no component prop table entry named "+prop)
	return oscal.ComponentProp{}
}

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
		require.True(t, e.Set(&c, componentPropValue(e.Prop)), "%s: the setter rejected the value the table round-trips", e.Prop)
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

// AC: component-port carries an HDF integer, so the accessor takes exactly the
// decimal-integer grammar within the schema's 1..65535 and rejects everything
// else — a foreign SAR must not hand HDF a port its own schema refuses.
func TestComponentPropTable_PortAcceptsOnlyDecimalIntegersInRange(t *testing.T) {
	entry := componentPropEntry(t, "component-port")

	for _, v := range []string{"1", "80", "443", "8443", "65535", "0080"} {
		var c hdf.Component
		require.True(t, entry.Set(&c, v), "%q is a port the HDF schema admits", v)
		require.NotNil(t, c.Port)
	}
	for _, v := range []string{"", "0", "65536", "80abc", "1e3", " 80", "80 ", "-1", "+80", "8.0", "0x50", "99999999999999999999"} {
		var c hdf.Component
		assert.False(t, entry.Set(&c, v), "%q is not a port the HDF schema admits", v)
		assert.Nil(t, c.Port, "a rejected value leaves the field absent")
	}
}

// AC: component-provider carries a closed HDF enum, so the accessor takes
// exactly its values, read from the generated schema types.
func TestComponentPropTable_ProviderAcceptsOnlyTheCloudProviderEnum(t *testing.T) {
	entry := componentPropEntry(t, "component-provider")

	values := oscal.CloudProviderValues()
	require.NotEmpty(t, values)
	for _, v := range values {
		var c hdf.Component
		require.True(t, entry.Set(&c, v), "%q is a Cloud_Provider value", v)
		require.NotNil(t, c.Provider)
		assert.Equal(t, hdf.CloudProvider(v), *c.Provider)
	}
	for _, v := range []string{"", "digitalocean", "AWS", "aws ", "amazon"} {
		var c hdf.Component
		assert.False(t, entry.Set(&c, v), "%q is not a Cloud_Provider value", v)
		assert.Nil(t, c.Provider, "a rejected value leaves the field absent")
	}
}

// AC: the accepted provider list is the schema's, not a hand-kept copy — the
// generated constants the accessor reads must still be the bundled enum.
func TestCloudProviderValuesMatchTheBundledSchemaEnum(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "hdf-schema", "dist", "schemas", "hdf-results.schema.json")
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var doc interface{}
	require.NoError(t, json.Unmarshal(raw, &doc))

	want := schemaEnumValues(doc, "Cloud_Provider")
	require.NotEmpty(t, want, "the bundled schema must define Cloud_Provider")
	assert.Equal(t, want, oscal.CloudProviderValues())
}

// schemaEnumValues returns the sorted non-null enum values of the definition
// named def, wherever the bundled schema nests it.
func schemaEnumValues(v interface{}, def string) []string {
	m, ok := v.(map[string]interface{})
	if !ok {
		if list, ok := v.([]interface{}); ok {
			for _, item := range list {
				if found := schemaEnumValues(item, def); found != nil {
					return found
				}
			}
		}
		return nil
	}
	if sub, ok := m[def].(map[string]interface{}); ok {
		if raw, ok := sub["enum"].([]interface{}); ok {
			var out []string
			for _, e := range raw {
				if s, ok := e.(string); ok {
					out = append(out, s)
				}
			}
			sort.Strings(out)
			return out
		}
	}
	for _, sub := range m {
		if found := schemaEnumValues(sub, def); found != nil {
			return found
		}
	}
	return nil
}

type groupKeyCase struct {
	Label   string            `json:"label"`
	Entries map[string]string `json:"entries"`
	Order   []string          `json:"order"`
	Why     string            `json:"why"`
}

func loadGroupKeyCases(t *testing.T) []groupKeyCase {
	t.Helper()
	var table struct {
		Cases []groupKeyCase `json:"cases"`
	}
	shared.LoadJSON(t, filepath.Join("..", "..", "..", "shared", "oscal-component-group-key-cases.json"), &table)
	require.NotEmpty(t, table.Cases, "an empty table would pass vacuously")
	return table.Cases
}

// groupedMapKeys returns the key each of g's prop groups carries, group 1 first.
func groupedMapKeys(props []oscal.Property, g oscal.ComponentGroupProp) []string {
	var keys []string
	for n := 1; ; n++ {
		group := fmt.Sprintf("%s-%d", g.Prefix, n)
		found := false
		for _, p := range props {
			if p.Group == group && p.Name == g.KeyProp() {
				keys = append(keys, p.Value)
				found = true
				break
			}
		}
		if !found {
			return keys
		}
	}
}

// AC: group numbering follows Unicode code-point order in both languages. The
// expectations live in one shared table both suites read, because Go's map-key
// sort and JavaScript's default sort disagree over supplementary-plane keys.
func TestComponentSubjectProps_NumbersMapGroupsInCodePointOrder(t *testing.T) {
	for _, c := range loadGroupKeyCases(t) {
		for _, g := range oscal.ComponentGroupPropTable() {
			t.Run(c.Label+"/"+g.Prefix, func(t *testing.T) {
				comp := hdf.Component{Name: "web01"}
				entries := make(map[string]string, len(c.Entries))
				for k, v := range c.Entries {
					entries[k] = v
				}
				g.Set(&comp, entries)

				props := oscal.ComponentSubjectProps(&comp)
				assert.Equal(t, c.Order, groupedMapKeys(props, g), c.Why)
			})
		}
	}
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

// A setter that can reject must say what it accepts, or its warning ends in a
// dangling "not ".
func TestComponentPropTableRejectingSettersNameWhatTheyAccept(t *testing.T) {
	for _, e := range oscal.ComponentPropTable() {
		for _, probe := range []string{"", "-1", "not-a-value"} {
			var c hdf.Component
			if !e.Set(&c, probe) {
				assert.NotEmpty(t, e.Accepts, "%s rejects %q but names nothing it accepts", e.Prop, probe)
			}
		}
	}
}
