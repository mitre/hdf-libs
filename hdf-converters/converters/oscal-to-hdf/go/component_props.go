package oscal

import (
	"fmt"
	"log"
	"regexp"
	"sort"
	"strconv"
	"strings"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// ComponentProp maps one HDF component identity field to the HDF-namespaced prop
// that carries it on an OSCAL assessment subject (ADR-0014 §4.5). Get renders the
// field in the prop's string form and Set parses it back, so a field HDF does not
// type as a string keeps its conversion in its own accessors.
type ComponentProp struct {
	// Prop is the vocabulary prop name (ADR-0014 §1.5).
	Prop string
	// Field is the HDF field name a marker prop reports (§1.7.5).
	Field string
	// Required marks a field HDF always defines, which therefore never carries an
	// empty-field marker: an empty value omits the prop instead (§1.7.3).
	Required bool
	// Accepts names the domain of a field HDF does not type as a free string, for
	// the warning a rejected value earns; it is empty for a plain string field.
	Accepts string
	Get     func(*hdf.Component) *string
	// Set reports false when the prop's value is outside the HDF field's domain,
	// which a foreign or hand-edited subject can put there.
	Set func(*hdf.Component, string) bool
}

// ComponentGroupProp maps one HDF component string map to the grouped key/value
// props that carry it, one group per entry.
type ComponentGroupProp struct {
	// Field is the HDF map field name (labels, externalIds).
	Field string
	// Prefix names the prop group; the key and value props extend it.
	Prefix string
	Get    func(*hdf.Component) map[string]string
	Set    func(*hdf.Component, map[string]string)
}

// KeyProp is the vocabulary prop carrying a map entry's key.
func (g ComponentGroupProp) KeyProp() string { return g.Prefix + "-key" }

// ValueProp is the vocabulary prop carrying a map entry's value.
func (g ComponentGroupProp) ValueProp() string { return g.Prefix + "-value" }

// stringField builds the entry for an optional HDF string field, reached through
// the pointer field that holds it.
func stringField(prop, field string, at func(*hdf.Component) **string) ComponentProp {
	return ComponentProp{
		Prop:  prop,
		Field: field,
		Get:   func(c *hdf.Component) *string { return *at(c) },
		Set: func(c *hdf.Component, v string) bool {
			*at(c) = &v
			return true
		},
	}
}

// stringMapField builds the entry for an HDF component string map.
func stringMapField(field, prefix string, at func(*hdf.Component) *map[string]string) ComponentGroupProp {
	return ComponentGroupProp{
		Field:  field,
		Prefix: prefix,
		Get:    func(c *hdf.Component) map[string]string { return *at(c) },
		Set:    func(c *hdf.Component, m map[string]string) { *at(c) = m },
	}
}

// componentProps is the one mapping the SAR exporter and importer both drive. Its
// order is the order the exporter emits props in, and the test pins it to the
// components[] rows of the vocabulary table.
var componentProps = []ComponentProp{
	{
		Prop: "component-name", Field: "name", Required: true,
		Get: func(c *hdf.Component) *string { return &c.Name },
		Set: func(c *hdf.Component, v string) bool { c.Name = v; return true },
	},
	stringField("component-description", "description", func(c *hdf.Component) **string { return &c.Description }),
	stringField("component-hostname", "hostname", func(c *hdf.Component) **string { return &c.Hostname }),
	stringField("component-fqdn", "fqdn", func(c *hdf.Component) **string { return &c.FQDN }),
	stringField("component-domain", "domain", func(c *hdf.Component) **string { return &c.Domain }),
	stringField("component-ip-address", "ipAddress", func(c *hdf.Component) **string { return &c.IPAddress }),
	stringField("component-mac-address", "macAddress", func(c *hdf.Component) **string { return &c.MACAddress }),
	stringField("component-os-name", "osName", func(c *hdf.Component) **string { return &c.OSName }),
	stringField("component-os-version", "osVersion", func(c *hdf.Component) **string { return &c.OSVersion }),
	stringField("component-image-id", "imageId", func(c *hdf.Component) **string { return &c.ImageID }),
	stringField("component-registry", "registry", func(c *hdf.Component) **string { return &c.Registry }),
	stringField("component-repository", "repository", func(c *hdf.Component) **string { return &c.Repository }),
	stringField("component-tag", "tag", func(c *hdf.Component) **string { return &c.Tag }),
	stringField("component-container-id", "containerId", func(c *hdf.Component) **string { return &c.ContainerID }),
	stringField("component-image", "image", func(c *hdf.Component) **string { return &c.Image }),
	stringField("component-runtime", "runtime", func(c *hdf.Component) **string { return &c.Runtime }),
	stringField("component-platform-type", "platformType", func(c *hdf.Component) **string { return &c.PlatformType }),
	stringField("component-cluster-name", "clusterName", func(c *hdf.Component) **string { return &c.ClusterName }),
	stringField("component-namespace", "namespace", func(c *hdf.Component) **string { return &c.Namespace }),
	stringField("component-version", "version", func(c *hdf.Component) **string { return &c.Version }),
	{
		Prop: "component-provider", Field: "provider",
		Accepts: "one of " + strings.Join(CloudProviderValues(), ", "),
		Get:     func(c *hdf.Component) *string { return (*string)(c.Provider) },
		Set: func(c *hdf.Component, v string) bool {
			if !validCloudProvider(v) {
				return false
			}
			p := hdf.CloudProvider(v)
			c.Provider = &p
			return true
		},
	},
	stringField("component-account-id", "accountId", func(c *hdf.Component) **string { return &c.AccountID }),
	stringField("component-region", "region", func(c *hdf.Component) **string { return &c.Region }),
	stringField("component-resource-type", "resourceType", func(c *hdf.Component) **string { return &c.ResourceType }),
	stringField("component-resource-id", "resourceId", func(c *hdf.Component) **string { return &c.ResourceID }),
	stringField("component-arn", "arn", func(c *hdf.Component) **string { return &c.Arn }),
	stringField("component-url", "url", func(c *hdf.Component) **string { return &c.URL }),
	stringField("component-branch", "branch", func(c *hdf.Component) **string { return &c.Branch }),
	stringField("component-commit", "commit", func(c *hdf.Component) **string { return &c.Commit }),
	stringField("component-environment", "environment", func(c *hdf.Component) **string { return &c.Environment }),
	stringField("component-package-manager", "packageManager", func(c *hdf.Component) **string { return &c.PackageManager }),
	stringField("component-package-name", "packageName", func(c *hdf.Component) **string { return &c.PackageName }),
	stringField("component-cidr", "cidr", func(c *hdf.Component) **string { return &c.CIDR }),
	stringField("component-gateway", "gateway", func(c *hdf.Component) **string { return &c.Gateway }),
	stringField("component-engine", "engine", func(c *hdf.Component) **string { return &c.Engine }),
	stringField("component-host", "host", func(c *hdf.Component) **string { return &c.Host }),
	{
		Prop: "component-port", Field: "port",
		Accepts: fmt.Sprintf("a decimal integer in %d..%d", minComponentPort, maxComponentPort),
		Get: func(c *hdf.Component) *string {
			if c.Port == nil {
				return nil
			}
			s := strconv.FormatInt(*c.Port, 10)
			return &s
		},
		Set: func(c *hdf.Component, v string) bool {
			n, ok := componentPort(v)
			if !ok {
				return false
			}
			c.Port = &n
			return true
		},
	},
	stringField("component-model-id", "modelId", func(c *hdf.Component) **string { return &c.ModelID }),
	stringField("component-dataset-id", "datasetId", func(c *hdf.Component) **string { return &c.DatasetID }),
}

// The hdf-results bounds on Component.port; a value outside them is a document
// the HDF validator rejects, so the importer must not build one.
const (
	minComponentPort = 1
	maxComponentPort = 65535
)

// decimalDigits is the whole grammar a port prop may use. Go and JavaScript
// disagree over what a lenient numeric parse accepts ("80abc", "1e3"), so the
// grammar is spelled out rather than left to either language's parser.
var decimalDigits = regexp.MustCompile(`^[0-9]+$`)

// componentPort parses a port prop, reporting false for anything outside the
// decimal-integer grammar or the schema's range.
func componentPort(v string) (int64, bool) {
	if !decimalDigits.MatchString(v) {
		return 0, false
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < minComponentPort || n > maxComponentPort {
		return 0, false
	}
	return n, true
}

// cloudProviders are the Cloud_Provider values HDF admits, named through the
// generated schema types; a test pins them to the bundled schema's own enum.
var cloudProviders = []hdf.CloudProvider{hdf.Aws, hdf.Azure, hdf.Gcp, hdf.Oci, hdf.CloudProviderOther}

// CloudProviderValues returns the Cloud_Provider enum in sorted order, which is
// also the order the TypeScript peer reports so the two warnings read alike.
func CloudProviderValues() []string {
	out := make([]string, 0, len(cloudProviders))
	for _, p := range cloudProviders {
		out = append(out, string(p))
	}
	sort.Strings(out)
	return out
}

func validCloudProvider(v string) bool {
	for _, p := range cloudProviders {
		if string(p) == v {
			return true
		}
	}
	return false
}

var componentGroupProps = []ComponentGroupProp{
	stringMapField("labels", "component-label", func(c *hdf.Component) *map[string]string { return &c.Labels }),
	stringMapField("externalIds", "component-external-id", func(c *hdf.Component) *map[string]string { return &c.ExternalIDS }),
}

// ComponentPropTable returns a copy of the component identity prop table.
func ComponentPropTable() []ComponentProp {
	return append([]ComponentProp(nil), componentProps...)
}

// ComponentGroupPropTable returns a copy of the component map prop table.
func ComponentGroupPropTable() []ComponentGroupProp {
	return append([]ComponentGroupProp(nil), componentGroupProps...)
}

// ComponentSubjectProps carries a component's identity fields as HDF-namespaced
// props, in table order. A present-but-empty optional string is carried by an
// empty-field marker (§1.7.3); an absent field emits nothing.
func ComponentSubjectProps(c *hdf.Component) []Property {
	var props []Property
	for _, e := range componentProps {
		v := e.Get(c)
		switch {
		case v == nil:
		case *v == "":
			if !e.Required {
				props = append(props, EmptyFieldProp(e.Field))
			}
		default:
			props = AppendVocabularyProp(props, e.Prop, *v)
		}
	}
	for _, g := range componentGroupProps {
		props = appendComponentMap(props, g, g.Get(c))
	}
	return props
}

// ReadComponentSubjectProps fills a component's identity fields from the
// HDF-namespaced props on its subject, leaving a field the props do not carry as
// the caller set it. A value outside its HDF field's domain — which a foreign or
// hand-edited SAR can carry — is dropped with a warning rather than written into
// a document the HDF validator would reject.
func ReadComponentSubjectProps(c *hdf.Component, props []Property) {
	for _, e := range componentProps {
		if v := e.read(props); v != nil {
			if !e.Set(c, *v) {
				log.Printf("WARNING: Dropping %s %q on component %q: not %s", e.Prop, *v, c.Name, e.Accepts)
			}
		}
	}
	for _, g := range componentGroupProps {
		if m := readComponentMap(props, g); m != nil {
			g.Set(c, m)
		}
	}
}

// read returns the HDF value props carry for e, or nil when they do not carry the
// field. A required field has no empty-field marker to consult, so its prop is
// read wherever it sits rather than through the optional-string helper.
func (e ComponentProp) read(props []Property) *string {
	if e.Required {
		if m, ok := FindVocabularyProp(props, e.Prop); ok {
			return &m.Value
		}
		return nil
	}
	return VocabularyString(props, e.Prop, e.Field, "")
}

// appendComponentMap carries a component string map as grouped key/value props in
// sorted key order, one group per entry, so the importer can rebuild the map. An
// empty key or value is carried by an empty-field marker in the same group (§1.7.3).
func appendComponentMap(props []Property, g ComponentGroupProp, m map[string]string) []Property {
	if len(m) == 0 {
		return props
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		group := fmt.Sprintf("%s-%d", g.Prefix, i+1)
		props = append(props, groupedComponentProp(g.KeyProp(), "key", group, k))
		props = append(props, groupedComponentProp(g.ValueProp(), "value", group, m[k]))
	}
	return props
}

// groupedComponentProp builds one grouped map prop, degrading to an empty-field
// marker (§1.7.3) when the value is empty.
func groupedComponentProp(name, field, group, value string) Property {
	if value == "" {
		p := EmptyFieldProp(field)
		p.Group = group
		return p
	}
	p, _ := VocabularyProp(name, value)
	p.Group = group
	return p
}

// readComponentMap rebuilds a component string map from grouped key/value props.
// Groups are numbered from 1 in the order the exporter emitted them (sorted key
// order), so reading stops at the first group with neither a key nor a value.
func readComponentMap(props []Property, g ComponentGroupProp) map[string]string {
	m := map[string]string{}
	for n := 1; ; n++ {
		group := fmt.Sprintf("%s-%d", g.Prefix, n)
		key := VocabularyString(props, g.KeyProp(), "key", group)
		value := VocabularyString(props, g.ValueProp(), "value", group)
		if key == nil && value == nil {
			break
		}
		m[hdfutil.Deref(key)] = hdfutil.Deref(value)
	}
	if len(m) == 0 {
		return nil
	}
	return m
}
