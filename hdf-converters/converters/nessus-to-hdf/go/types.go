package nessus

import (
	"encoding/xml"
	"errors"
	"io"
	"strings"
)

// NessusXML represents the root structure of a Nessus XML scan file
type NessusXML struct {
	Policy Policy     `xml:"Policy"`
	Report ReportData `xml:"Report"`
}

// Policy contains the scan policy configuration
type Policy struct {
	PolicyName  string      `xml:"policyName"`
	Preferences Preferences `xml:"Preferences"`
}

// Preferences contains server preferences
type Preferences struct {
	ServerPreferences ServerPreferences `xml:"ServerPreferences"`
}

// ServerPreferences contains individual preference settings
type ServerPreferences struct {
	Preference []Preference `xml:"preference"`
}

// Preference represents a single server preference
type Preference struct {
	Name  string `xml:"name"`
	Value string `xml:"value"`
}

// ReportData contains the scan report information
type ReportData struct {
	Name        string       `xml:"name,attr"`
	ReportHosts []ReportHost `xml:"ReportHost"`
}

// ReportHost represents a single scanned host
type ReportHost struct {
	Name           string         `xml:"name,attr"`
	HostProperties HostProperties `xml:"HostProperties"`
	ReportItems    []ReportItem   `xml:"ReportItem"`
}

// HostProperties contains host-specific metadata
type HostProperties struct {
	Tags []HostPropertyTag `xml:"tag"`
}

// HostPropertyTag represents a single host property
type HostPropertyTag struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

// ReportItem represents a single vulnerability or compliance finding
type ReportItem struct {
	Port       string `xml:"port,attr"`
	SvcName    string `xml:"svc_name,attr"`
	Protocol   string `xml:"protocol,attr"`
	Severity   string `xml:"severity,attr"`
	PluginID   string `xml:"pluginID,attr"`
	PluginName string `xml:"pluginName,attr"`

	// Nessus emits pluginFamily as a ReportItem attribute, not a child element.
	PluginFamily string `xml:"pluginFamily,attr"`

	// Basic metadata
	Description            string `xml:"description"`
	FName                  string `xml:"fname"`
	PluginModificationDate string `xml:"plugin_modification_date"`
	PluginPublicationDate  string `xml:"plugin_publication_date"`
	PluginType             string `xml:"plugin_type"`
	RiskFactor             string `xml:"risk_factor"`
	ScriptVersion          string `xml:"script_version"`
	SeeAlso                string `xml:"see_also"`
	Solution               string `xml:"solution"`
	Synopsis               string `xml:"synopsis"`
	PluginOutput           string `xml:"plugin_output"`
	CVSSBaseScore          string `xml:"cvss_base_score"`
	CVSS3BaseScore         string `xml:"cvss3_base_score"`
	CVE                    string `xml:"cve"`

	// Structured CVSS data (Wave 2: CVE-ecosystem)
	CVSSVector          string `xml:"cvss_vector"`
	CVSS3Vector         string `xml:"cvss3_vector"`
	CVSSTemporalVector  string `xml:"cvss_temporal_vector"`
	CVSS3TemporalVector string `xml:"cvss3_temporal_vector"`
	CVSSTemporalScore   string `xml:"cvss_temporal_score"`
	CVSS3TemporalScore  string `xml:"cvss3_temporal_score"`
	CVSSScoreSource     string `xml:"cvss_score_source"`

	// EPSS (newer Tenable plugins emit these inline)
	EPSSScore      string `xml:"epss_score"`
	EPSSPercentile string `xml:"epss_percentile"`

	// CWE references (Nessus may emit multiple <cwe> elements)
	CWE []string `xml:"cwe"`

	// Compliance-specific fields (with cm: namespace)
	ComplianceReference   string `xml:"http://www.nessus.org/cm compliance-reference"`
	ComplianceCheckName   string `xml:"http://www.nessus.org/cm compliance-check-name"`
	ComplianceInfo        string `xml:"http://www.nessus.org/cm compliance-info"`
	ComplianceSolution    string `xml:"http://www.nessus.org/cm compliance-solution"`
	ComplianceResult      string `xml:"http://www.nessus.org/cm compliance-result"`
	ComplianceActualValue string `xml:"http://www.nessus.org/cm compliance-actual-value"`

	// Verbatim source finding, in document order, used to build the requirement's
	// `code` blob. The typed fields above cover only the subset the converter
	// reasons about; the raw capture keeps every element Nessus emitted.
	rawFields []rawField
}

// rawField is one key of the source ReportItem. Values are strings; repeated
// elements (cve, cwe, xref, ...) collapse into a single multi-value field.
type rawField struct {
	name   string
	values []string
	// repeated marks a field the converter always renders as a JSON array,
	// even with a single value, so single- and multi-hit findings share a shape.
	repeated bool
}

// alwaysArrayElements mirror the TypeScript parser's alwaysArray list: these
// elements render as JSON arrays in `code` even when the finding has only one.
var alwaysArrayElements = map[string]bool{"cve": true, "cwe": true}

// UnmarshalXML decodes the typed fields and, in the same pass, records the raw
// element/attribute sequence the code blob is built from. Attributes follow the
// child elements, matching the TypeScript XML parser's key ordering.
func (r *ReportItem) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type reportItem ReportItem // sheds UnmarshalXML, so DecodeElement won't recurse
	aux := struct {
		*reportItem
		InnerXML string `xml:",innerxml"`
	}{reportItem: (*reportItem)(r)}

	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}

	trimStrings(r)

	children, err := parseRawChildren(aux.InnerXML)
	if err != nil {
		return err
	}
	for _, attr := range start.Attr {
		children = appendRawField(children, attr.Name.Local, attr.Value)
	}
	r.rawFields = children

	return nil
}

// parseRawChildren walks a ReportItem's inner XML and returns its child
// elements in document order, with entity references resolved.
func parseRawChildren(innerXML string) ([]rawField, error) {
	var fields []rawField
	dec := xml.NewDecoder(strings.NewReader(innerXML))
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return fields, nil
		}
		if err != nil {
			return nil, err
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		var text string
		if err := dec.DecodeElement(&text, &se); err != nil {
			return nil, err
		}
		fields = appendRawField(fields, se.Name.Local, strings.TrimSpace(text))
	}
}

func appendRawField(fields []rawField, name, value string) []rawField {
	for i := range fields {
		if fields[i].name == name {
			fields[i].values = append(fields[i].values, value)
			fields[i].repeated = true
			return fields
		}
	}
	return append(fields, rawField{
		name:     name,
		values:   []string{value},
		repeated: alwaysArrayElements[name],
	})
}

// trimStrings trims the element-derived fields. The XML decoder keeps the
// surrounding whitespace Nessus pads multi-line text with; the TypeScript
// parser drops it, and the untrimmed text leaks into descriptions and messages.
func trimStrings(r *ReportItem) {
	for _, p := range []*string{
		&r.Description, &r.FName, &r.PluginModificationDate, &r.PluginPublicationDate,
		&r.PluginType, &r.RiskFactor, &r.ScriptVersion, &r.SeeAlso, &r.Solution,
		&r.Synopsis, &r.PluginOutput, &r.CVSSBaseScore, &r.CVSS3BaseScore, &r.CVE,
		&r.CVSSVector, &r.CVSS3Vector, &r.CVSSTemporalVector, &r.CVSS3TemporalVector,
		&r.CVSSTemporalScore, &r.CVSS3TemporalScore, &r.CVSSScoreSource,
		&r.EPSSScore, &r.EPSSPercentile,
		&r.ComplianceReference, &r.ComplianceCheckName, &r.ComplianceInfo,
		&r.ComplianceSolution, &r.ComplianceResult, &r.ComplianceActualValue,
	} {
		*p = strings.TrimSpace(*p)
	}
	for i := range r.CWE {
		r.CWE[i] = strings.TrimSpace(r.CWE[i])
	}
}
