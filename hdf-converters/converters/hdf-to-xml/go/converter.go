package hdftoxml

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"sort"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// ConvertHDFToXML converts HDF JSON to XML format
func ConvertHDFToXML(input []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("hdf-to-xml: empty input")
	}
	if err := shared.ValidateJSONSize(input, "hdf-to-xml", 0); err != nil {
		return nil, fmt.Errorf("hdf-to-xml: %w", err)
	}

	// Parse HDF JSON
	var hdfData hdf.HDFResults
	if err := json.Unmarshal(input, &hdfData); err != nil {
		return nil, fmt.Errorf("invalid HDF JSON: %w", err)
	}

	// Validate structure
	if hdfData.Baselines == nil {
		return nil, fmt.Errorf("invalid HDF structure: missing baselines field")
	}

	// Transform to XML structure
	xmlData := transformToXMLStructure(&hdfData)

	// Marshal to XML with indentation
	output, err := xml.MarshalIndent(xmlData, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal XML: %w", err)
	}

	// Add XML header
	xmlWithHeader := append([]byte(xml.Header), output...)
	return xmlWithHeader, nil
}

// XMLHDFResults is the XML representation of HDF results
type XMLHDFResults struct {
	XMLName    xml.Name       `xml:"HdfResults"`
	Baselines  XMLBaselines   `xml:"baselines"`
	Targets    *XMLTargets    `xml:"components,omitempty"`
	Statistics *XMLStatistics `xml:"statistics,omitempty"`
	Timestamp  string         `xml:"timestamp,omitempty"`
	Generator  *XMLGenerator  `xml:"generator,omitempty"`
}

// XMLGenerator mirrors the HDF generator
type XMLGenerator struct {
	Name    string `xml:"name"`
	Version string `xml:"version,omitempty"`
}

// XMLBaselines wraps baseline array
type XMLBaselines struct {
	Baseline []XMLBaseline `xml:"baseline"`
}

// XMLBaseline represents a baseline in XML
type XMLBaseline struct {
	Name             string           `xml:"name"`
	Version          *string          `xml:"version,omitempty"`
	Title            *string          `xml:"title,omitempty"`
	Summary          *string          `xml:"summary,omitempty"`
	Status           *string          `xml:"status,omitempty"`
	ResultsChecksum  *XMLChecksum     `xml:"resultsChecksum,omitempty"`
	OriginalChecksum *XMLChecksum     `xml:"originalChecksum,omitempty"`
	Integrity        XMLIntegrity     `xml:"integrity"`
	Requirements     *XMLRequirements `xml:"requirements,omitempty"`
}

// XMLChecksum mirrors an HDF Checksum ({algorithm, value})
type XMLChecksum struct {
	Algorithm string `xml:"algorithm"`
	Value     string `xml:"value"`
}

// XMLIntegrity represents an integrity block
type XMLIntegrity struct {
	Algorithm string `xml:"algorithm"`
	Checksum  string `xml:"checksum"`
}

// XMLRequirements wraps requirement array
type XMLRequirements struct {
	Requirement []XMLRequirement `xml:"requirement"`
}

// XMLRequirement represents a requirement in XML
type XMLRequirement struct {
	ID                 string             `xml:"id"`
	Title              *string            `xml:"title,omitempty"`
	Descriptions       *XMLDescriptions   `xml:"descriptions,omitempty"`
	Code               *string            `xml:"code,omitempty"`
	SourceLocation     *XMLSourceLocation `xml:"sourceLocation,omitempty"`
	ControlType        *string            `xml:"controlType,omitempty"`
	VerificationMethod *string            `xml:"verificationMethod,omitempty"`
	Applicability      *string            `xml:"applicability,omitempty"`
	Refs               *XMLRefs           `xml:"refs,omitempty"`
	Impact             float64            `xml:"impact"`
	Tags               *xmlTags           `xml:"tags,omitempty"`
	Results            *XMLResults        `xml:"results,omitempty"`
}

// XMLSourceLocation mirrors HDF sourceLocation
type XMLSourceLocation struct {
	Ref  *string  `xml:"ref,omitempty"`
	Line *float64 `xml:"line,omitempty"`
}

// XMLRefs wraps the refs array
type XMLRefs struct {
	Ref []XMLRef `xml:"ref"`
}

// XMLRef is one polymorphic Reference ({url} | {uri} | {ref: string})
type XMLRef struct {
	URL *string `xml:"url,omitempty"`
	URI *string `xml:"uri,omitempty"`
	Ref *string `xml:"ref,omitempty"`
}

// XMLDescriptions wraps description array
type XMLDescriptions struct {
	Description []XMLDescription `xml:"description"`
}

// XMLDescription represents a labeled description
type XMLDescription struct {
	Label string `xml:"label"`
	Data  string `xml:"data"`
}

// xmlTags serializes an HDF tag map as <key>value</key> elements, sorted by key.
// Sorting makes output deterministic and matches the TS converter (Go's source
// tag map is unordered, so without sorting the two languages would diverge).
// A custom marshaler is required because encoding/xml cannot marshal a map's
// dynamic keys as element names.
type xmlTags map[string]interface{}

func (t xmlTags) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	if len(t) == 0 {
		return nil
	}
	if err := e.EncodeToken(start); err != nil {
		return err
	}
	keys := make([]string, 0, len(t))
	for k := range t {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		el := xml.StartElement{Name: xml.Name{Local: k}}
		if arr, ok := t[k].([]interface{}); ok {
			for _, item := range arr {
				if err := e.EncodeElement(fmt.Sprint(item), el); err != nil {
					return err
				}
			}
			continue
		}
		if err := e.EncodeElement(fmt.Sprint(t[k]), el); err != nil {
			return err
		}
	}
	return e.EncodeToken(start.End())
}

// XMLResults wraps result array
type XMLResults struct {
	Result []XMLResult `xml:"result"`
}

// XMLResult represents a test result
type XMLResult struct {
	Status    string   `xml:"status"`
	CodeDesc  string   `xml:"codeDesc"`
	StartTime string   `xml:"startTime"`
	Message   *string  `xml:"message,omitempty"`
	RunTime   *float64 `xml:"runTime,omitempty"`
}

// XMLTargets wraps target array
type XMLTargets struct {
	Target []XMLTarget `xml:"target"`
}

// XMLTarget represents a target
type XMLTarget struct {
	ComponentID *string `xml:"componentId,omitempty"`
	Name        string  `xml:"name"`
	Type        string  `xml:"type"`
	Hostname    *string `xml:"hostname,omitempty"`
	FQDN        *string `xml:"fqdn,omitempty"`
	Domain      *string `xml:"domain,omitempty"`
	IPAddress   *string `xml:"ipAddress,omitempty"`
}

// XMLStatistics represents statistics
type XMLStatistics struct {
	Duration *float64 `xml:"duration,omitempty"`
}

// transformToXMLStructure converts HDF data to XML structure
func transformToXMLStructure(hdf *hdf.HDFResults) *XMLHDFResults {
	result := &XMLHDFResults{}

	// Transform baselines
	if len(hdf.Baselines) > 0 {
		result.Baselines.Baseline = make([]XMLBaseline, len(hdf.Baselines))
		for i, baseline := range hdf.Baselines {
			xmlBaseline := XMLBaseline{
				Name:    baseline.Name,
				Version: baseline.Version,
				Title:   baseline.Title,
				Summary: baseline.Summary,
				Status:  baseline.Status,
			}
			if baseline.ResultsChecksum != nil {
				xmlBaseline.ResultsChecksum = &XMLChecksum{
					Algorithm: string(baseline.ResultsChecksum.Algorithm),
					Value:     baseline.ResultsChecksum.Value,
				}
			}
			if baseline.OriginalChecksum != nil {
				xmlBaseline.OriginalChecksum = &XMLChecksum{
					Algorithm: string(baseline.OriginalChecksum.Algorithm),
					Value:     baseline.OriginalChecksum.Value,
				}
			}
			if baseline.Integrity != nil {
				if baseline.Integrity.Algorithm != nil {
					xmlBaseline.Integrity.Algorithm = string(*baseline.Integrity.Algorithm)
				}
				if baseline.Integrity.Checksum != nil {
					xmlBaseline.Integrity.Checksum = *baseline.Integrity.Checksum
				}
			}
			result.Baselines.Baseline[i] = xmlBaseline

			// Transform requirements
			if len(baseline.Requirements) > 0 {
				result.Baselines.Baseline[i].Requirements = &XMLRequirements{
					Requirement: make([]XMLRequirement, len(baseline.Requirements)),
				}
				for j, req := range baseline.Requirements {
					result.Baselines.Baseline[i].Requirements.Requirement[j] = transformRequirement(req)
				}
			}
		}
	}

	// Transform components
	if len(hdf.Components) > 0 {
		result.Targets = &XMLTargets{
			Target: make([]XMLTarget, len(hdf.Components)),
		}
		for i, target := range hdf.Components {
			result.Targets.Target[i] = XMLTarget{
				ComponentID: target.ComponentID,
				Name:        target.Name,
				Type:        string(target.Type),
				Hostname:    target.Hostname,
				FQDN:        target.FQDN,
				Domain:      target.Domain,
				IPAddress:   target.IPAddress,
			}
		}
	}

	// Transform statistics
	if hdf.Statistics != nil && hdf.Statistics.Duration != nil {
		result.Statistics = &XMLStatistics{
			Duration: hdf.Statistics.Duration,
		}
	}

	// Add timestamp
	if hdf.Timestamp != nil {
		result.Timestamp = hdf.Timestamp.Format("2006-01-02T15:04:05Z07:00")
	}

	// Add generator
	if hdf.Generator != nil {
		result.Generator = &XMLGenerator{
			Name:    hdf.Generator.Name,
			Version: hdf.Generator.Version,
		}
	}

	return result
}

// transformRequirement converts a requirement to XML structure
func transformRequirement(req hdf.EvaluatedRequirement) XMLRequirement {
	xmlReq := XMLRequirement{
		ID:     req.ID,
		Title:  req.Title,
		Impact: req.Impact,
	}

	// Transform descriptions
	if len(req.Descriptions) > 0 {
		xmlReq.Descriptions = &XMLDescriptions{
			Description: make([]XMLDescription, len(req.Descriptions)),
		}
		for i, desc := range req.Descriptions {
			xmlReq.Descriptions.Description[i] = XMLDescription{
				Label: desc.Label,
				Data:  desc.Data,
			}
		}
	}

	// code
	xmlReq.Code = req.Code

	// sourceLocation
	if req.SourceLocation != nil {
		xmlReq.SourceLocation = &XMLSourceLocation{
			Ref:  req.SourceLocation.Ref,
			Line: req.SourceLocation.Line,
		}
	}

	// v3.2 classification fields (enum -> *string)
	if req.ControlType != nil {
		s := string(*req.ControlType)
		xmlReq.ControlType = &s
	}
	if req.VerificationMethod != nil {
		s := string(*req.VerificationMethod)
		xmlReq.VerificationMethod = &s
	}
	if req.Applicability != nil {
		s := string(*req.Applicability)
		xmlReq.Applicability = &s
	}

	// refs (polymorphic Reference: url | uri | string ref; array-form ref skipped)
	if len(req.Refs) > 0 {
		refs := &XMLRefs{Ref: make([]XMLRef, 0, len(req.Refs))}
		for _, r := range req.Refs {
			switch {
			case r.URL != nil:
				refs.Ref = append(refs.Ref, XMLRef{URL: r.URL})
			case r.URI != nil:
				refs.Ref = append(refs.Ref, XMLRef{URI: r.URI})
			case r.Ref != nil && r.Ref.String != nil:
				refs.Ref = append(refs.Ref, XMLRef{Ref: r.Ref.String})
			}
		}
		if len(refs.Ref) > 0 {
			xmlReq.Refs = refs
		}
	}

	// tags — generic, sorted-key serialization (see xmlTags)
	if len(req.Tags) > 0 {
		t := xmlTags(req.Tags)
		xmlReq.Tags = &t
	}

	// Transform results
	if len(req.Results) > 0 {
		xmlReq.Results = &XMLResults{
			Result: make([]XMLResult, len(req.Results)),
		}
		for i, res := range req.Results {
			xmlReq.Results.Result[i] = XMLResult{
				Status:    string(res.Status),
				CodeDesc:  res.CodeDesc,
				StartTime: res.StartTime.Format("2006-01-02T15:04:05Z07:00"),
				Message:   res.Message,
				RunTime:   res.RunTime,
			}
		}
	}

	return xmlReq
}
